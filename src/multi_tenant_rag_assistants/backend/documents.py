"""Tenant-scoped document storage, approval, ingestion, and retrieval."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import zipfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Literal
from uuid import uuid4
from xml.etree import ElementTree

import chromadb
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    HTTPException,
    UploadFile,
    status,
)
from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field
from pypdf import PdfReader

from .database import PROJECT_ROOT, connect


STORAGE_ROOT = Path(
    os.getenv("DOCUMENT_STORAGE_ROOT", PROJECT_ROOT / "storage")
).resolve()
CHROMA_ROOT = Path(os.getenv("CHROMA_PERSIST_DIRECTORY", PROJECT_ROOT / "chroma_data")).resolve()
COLLECTION_NAME = "organization_knowledge"
MAX_FILE_BYTES = int(os.getenv("DOCUMENT_MAX_BYTES", str(20 * 1024 * 1024)))
CHUNK_SIZE = int(os.getenv("DOCUMENT_CHUNK_SIZE", "1000"))
CHUNK_OVERLAP = int(os.getenv("DOCUMENT_CHUNK_OVERLAP", "150"))
EMBEDDING_MODEL = os.getenv("DOCUMENT_EMBEDDING_MODEL", "text-embedding-3-small")
ALLOWED_EXTENSIONS = {".pdf": "application/pdf", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".txt": "text/plain"}
EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class DocumentValidationError(ValueError):
    """An uploaded file failed trusted backend validation."""


class DocumentDecisionRequest(BaseModel):
    reason: str = Field(default="", max_length=500)


def tenant_key(tenant: dict) -> str:
    database_id = tenant["tenant_id"] if "tenant_id" in tenant else tenant["id"]
    return f"tenant_{tenant['slug']}_{database_id:03d}"


def document_payload(row: dict) -> dict:
    return {
        "id": row["id"],
        "tenant_id": row["tenant_id"],
        "original_filename": row["original_filename"],
        "current_version": row["current_version"],
        "status": row["status"],
        "access_scope": row["access_scope"],
        "uploaded_by": row["uploaded_by"],
        "created_at": row["created_at"],
        "version": {
            "id": row["version_id"],
            "version_number": row["version_number"],
            "checksum": row["checksum"],
            "mime_type": row["mime_type"],
            "size_bytes": row["size_bytes"],
            "approval_status": row["approval_status"],
            "ingestion_status": row["ingestion_status"],
            "chunk_count": row["chunk_count"],
            "failure_reason": row["failure_reason"],
            "created_at": row["version_created_at"],
        },
    }


def audit(
    connection,
    *,
    tenant_id: int,
    actor_id: int | None,
    action: str,
    outcome: str,
    document_id: str | None = None,
    version_id: str | None = None,
    details: dict | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO rag_document_audit
            (tenant_id, document_id, version_id, actor_id, action, outcome, details)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (
            tenant_id,
            document_id,
            version_id,
            actor_id,
            action,
            outcome,
            Jsonb(details or {}),
        ),
    )


def checked_storage_path(storage_key: str) -> Path:
    path = (STORAGE_ROOT / storage_key).resolve()
    if not path.is_relative_to(STORAGE_ROOT):
        raise RuntimeError("Unsafe document storage path.")
    return path


async def write_quarantine_file(upload: UploadFile, destination: Path) -> tuple[int, str]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    try:
        with destination.open("xb") as output:
            while chunk := await upload.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_FILE_BYTES:
                    raise DocumentValidationError(
                        f"File exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MB limit."
                    )
                digest.update(chunk)
                output.write(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        await upload.close()
    if size == 0:
        destination.unlink(missing_ok=True)
        raise DocumentValidationError("Empty files cannot be uploaded.")
    return size, digest.hexdigest()


def validate_docx_archive(path: Path) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            names = {entry.filename for entry in entries}
            if "[Content_Types].xml" not in names or "word/document.xml" not in names:
                raise DocumentValidationError("The file is not a valid DOCX document.")
            if len(entries) > 2000:
                raise DocumentValidationError("The DOCX archive contains too many entries.")
            expanded_size = 0
            for entry in entries:
                member = PurePosixPath(entry.filename)
                if member.is_absolute() or ".." in member.parts:
                    raise DocumentValidationError("The DOCX archive contains an unsafe path.")
                expanded_size += entry.file_size
                if expanded_size > MAX_FILE_BYTES * 10:
                    raise DocumentValidationError("The DOCX archive expands beyond the safety limit.")
                if entry.filename.lower().endswith("vbaproject.bin"):
                    raise DocumentValidationError("Macro-enabled Office documents are not allowed.")
    except zipfile.BadZipFile as exc:
        raise DocumentValidationError("The file is not a valid DOCX document.") from exc


def validate_file_content(path: Path, extension: str) -> None:
    with path.open("rb") as source:
        header = source.read(8)
        source.seek(0)
        if EICAR_SIGNATURE in source.read():
            raise DocumentValidationError("The file failed the malware signature check.")
    if extension == ".pdf" and not header.startswith(b"%PDF-"):
        raise DocumentValidationError("The file content does not match the PDF extension.")
    if extension == ".docx":
        if not header.startswith(b"PK"):
            raise DocumentValidationError("The file content does not match the DOCX extension.")
        validate_docx_archive(path)
    if extension == ".txt":
        try:
            path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError as exc:
            raise DocumentValidationError("TXT documents must use UTF-8 encoding.") from exc


def scan_for_malware(path: Path) -> None:
    mode = os.getenv("DOCUMENT_SCANNER_MODE", "basic").strip().lower()
    if mode == "basic":
        return
    if mode != "clamav":
        raise DocumentValidationError("DOCUMENT_SCANNER_MODE must be basic or clamav.")
    command = os.getenv("CLAMAV_COMMAND", "clamscan")
    try:
        result = subprocess.run(
            [command, "--no-summary", str(path)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise DocumentValidationError("The configured malware scanner is unavailable.") from exc
    if result.returncode == 1:
        raise DocumentValidationError("The file failed the malware scan.")
    if result.returncode != 0:
        raise DocumentValidationError("The malware scanner could not validate the file.")


def extract_text(path: Path, mime_type: str) -> str:
    if mime_type == "text/plain":
        return path.read_text(encoding="utf-8-sig")
    if mime_type == "application/pdf":
        reader = PdfReader(path)
        return "\n\n".join(page.extract_text() or "" for page in reader.pages)
    if mime_type.endswith("wordprocessingml.document"):
        with zipfile.ZipFile(path) as archive:
            xml = archive.read("word/document.xml")
        root = ElementTree.fromstring(xml)
        paragraphs = []
        for paragraph in root.iter():
            if paragraph.tag.endswith("}p"):
                text = "".join(
                    node.text or "" for node in paragraph.iter() if node.tag.endswith("}t")
                )
                if text.strip():
                    paragraphs.append(text)
        return "\n\n".join(paragraphs)
    raise RuntimeError("Unsupported document MIME type.")


def embed_texts(texts: list[str]) -> list[list[float]]:
    return OpenAIEmbeddings(model=EMBEDDING_MODEL).embed_documents(texts)


def chroma_collection():
    CHROMA_ROOT.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(CHROMA_ROOT))
    return client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )


def vector_filter(tenant_storage_key: str, document_id: str, version_id: str | None = None) -> dict:
    conditions = [
        {"tenant_id": tenant_storage_key},
        {"document_id": document_id},
    ]
    if version_id:
        conditions.append({"version_id": version_id})
    return {"$and": conditions}


def delete_vectors(tenant_storage_key: str, document_id: str, version_id: str | None = None) -> None:
    try:
        chroma_collection().delete(
            where=vector_filter(tenant_storage_key, document_id, version_id)
        )
    except Exception:
        # PostgreSQL revocation remains authoritative even if physical cleanup is retried later.
        return


def process_document_version(version_id: str) -> None:
    """Parse, chunk, embed, index, verify, and atomically activate one version."""
    with connect() as connection:
        row = connection.execute(
            """
            SELECT v.id AS version_id, v.document_id, v.version_number, v.storage_key,
                   v.mime_type, v.approval_status, v.ingestion_status,
                   d.tenant_id, d.access_scope, t.slug
            FROM rag_document_versions v
            JOIN rag_documents d ON d.id = v.document_id
            JOIN rag_tenants t ON t.id = d.tenant_id
            WHERE v.id = %s AND d.status <> 'deleted'
            FOR UPDATE
            """,
            (version_id,),
        ).fetchone()
        if (
            row is None
            or row["approval_status"] != "approved"
            or row["ingestion_status"] not in {"queued", "failed"}
        ):
            return
        connection.execute(
            "UPDATE rag_document_versions SET ingestion_status = 'processing', failure_reason = NULL WHERE id = %s",
            (version_id,),
        )
        connection.execute(
            """
            UPDATE rag_documents
            SET status = 'processing', updated_at = CURRENT_TIMESTAMP
            WHERE id = %s AND NOT EXISTS (
                SELECT 1 FROM rag_document_versions
                WHERE document_id = %s AND ingestion_status = 'active'
            )
            """,
            (row["document_id"], row["document_id"]),
        )

    ids: list[str] = []
    tenant_storage_key = tenant_key({"id": row["tenant_id"], "slug": row["slug"]})
    try:
        text = extract_text(checked_storage_path(row["storage_key"]), row["mime_type"])
        if not text.strip():
            raise RuntimeError("No searchable text could be extracted from the document.")
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=CHUNK_SIZE,
            chunk_overlap=CHUNK_OVERLAP,
        )
        chunks = [chunk for chunk in splitter.split_text(text) if chunk.strip()]
        if not chunks:
            raise RuntimeError("The document did not produce any searchable chunks.")
        embeddings = embed_texts(chunks)
        ids = [f"{version_id}_chunk_{index:06d}" for index in range(1, len(chunks) + 1)]
        metadata = [
            {
                "tenant_id": tenant_storage_key,
                "tenant_db_id": row["tenant_id"],
                "document_id": row["document_id"],
                "version_id": version_id,
                "chunk_id": chunk_id,
                "access_scope": row["access_scope"],
                "status": "active",
            }
            for chunk_id in ids
        ]
        collection = chroma_collection()
        collection.upsert(ids=ids, embeddings=embeddings, documents=chunks, metadatas=metadata)
        indexed = collection.get(ids=ids)
        if len(indexed["ids"]) != len(ids):
            raise RuntimeError("ChromaDB indexing verification failed.")

        with connect() as connection:
            active_versions = connection.execute(
                """
                SELECT id FROM rag_document_versions
                WHERE document_id = %s AND ingestion_status = 'active' AND id <> %s
                """,
                (row["document_id"], version_id),
            ).fetchall()
            connection.execute(
                """
                UPDATE rag_document_versions
                SET ingestion_status = 'superseded'
                WHERE document_id = %s AND ingestion_status = 'active' AND id <> %s
                """,
                (row["document_id"], version_id),
            )
            connection.execute(
                """
                UPDATE rag_document_versions
                SET ingestion_status = 'active', chunk_count = %s, failure_reason = NULL
                WHERE id = %s
                """,
                (len(ids), version_id),
            )
            connection.execute(
                """
                UPDATE rag_documents
                SET current_version = %s, storage_key = %s, status = 'active',
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
                """,
                (row["version_number"], row["storage_key"], row["document_id"]),
            )
            audit(
                connection,
                tenant_id=row["tenant_id"],
                actor_id=None,
                document_id=row["document_id"],
                version_id=version_id,
                action="document_indexed",
                outcome="success",
                details={"chunk_count": len(ids), "collection": COLLECTION_NAME},
            )
        for old_version in active_versions:
            delete_vectors(tenant_storage_key, row["document_id"], old_version["id"])
    except Exception as exc:
        if ids:
            delete_vectors(tenant_storage_key, row["document_id"], version_id)
        message = str(exc)[:1000] or exc.__class__.__name__
        with connect() as connection:
            connection.execute(
                """
                UPDATE rag_document_versions
                SET ingestion_status = 'failed', failure_reason = %s
                WHERE id = %s
                """,
                (message, version_id),
            )
            has_active = connection.execute(
                "SELECT 1 FROM rag_document_versions WHERE document_id = %s AND ingestion_status = 'active'",
                (row["document_id"],),
            ).fetchone()
            if has_active is None:
                connection.execute(
                    "UPDATE rag_documents SET status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                    (row["document_id"],),
                )
            audit(
                connection,
                tenant_id=row["tenant_id"],
                actor_id=None,
                document_id=row["document_id"],
                version_id=version_id,
                action="document_indexing",
                outcome="failed",
                details={"reason": message},
            )


async def register_upload(
    *,
    tenant_id: int,
    actor: dict,
    upload: UploadFile,
    approved: bool,
    document_id: str | None = None,
) -> dict:
    original_filename = Path(upload.filename or "").name
    extension = Path(original_filename).suffix.lower()
    if not original_filename or extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Only PDF, DOCX, and TXT files are supported.")

    with connect() as connection:
        tenant = connection.execute(
            "SELECT id, name, slug, is_active FROM rag_tenants WHERE id = %s",
            (tenant_id,),
        ).fetchone()
        if tenant is None or not tenant["is_active"]:
            raise HTTPException(status_code=404, detail="Active tenant not found.")
        existing = None
        if document_id:
            existing = connection.execute(
                """
                SELECT id, current_version, access_scope, status
                FROM rag_documents
                WHERE id = %s AND tenant_id = %s AND status <> 'deleted'
                """,
                (document_id, tenant_id),
            ).fetchone()
            if existing is None:
                raise HTTPException(status_code=404, detail="Document not found in this tenant.")
            version_number = 0
        else:
            document_id = f"doc_{uuid4().hex[:16]}"
            version_number = 1

    version_id = f"ver_{uuid4().hex[:16]}"
    generated_name = f"{document_id}_{version_id}{extension}"
    base_key = f"tenants/{tenant_key(tenant)}"
    quarantine_key = f"{base_key}/quarantine/{generated_name}"
    original_key = f"{base_key}/originals/{generated_name}"
    quarantine_path = checked_storage_path(quarantine_key)
    original_path = checked_storage_path(original_key)

    try:
        size_bytes, checksum = await write_quarantine_file(upload, quarantine_path)
        validate_file_content(quarantine_path, extension)
        scan_for_malware(quarantine_path)
        original_path.parent.mkdir(parents=True, exist_ok=True)
        quarantine_path.replace(original_path)
    except DocumentValidationError as exc:
        quarantine_path.unlink(missing_ok=True)
        with connect() as connection:
            audit(
                connection,
                tenant_id=tenant_id,
                actor_id=actor["id"],
                document_id=document_id,
                version_id=version_id,
                action="document_upload",
                outcome="rejected",
                details={"filename": original_filename, "reason": str(exc)},
            )
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    approval_status = "approved" if approved else "pending"
    ingestion_status = "queued" if approved else "quarantined"
    document_status = "processing" if approved else "pending_approval"
    try:
        with connect() as connection:
            if existing is not None:
                existing = connection.execute(
                    """
                    SELECT id, current_version, access_scope, status
                    FROM rag_documents
                    WHERE id = %s AND tenant_id = %s AND status <> 'deleted'
                    FOR UPDATE
                    """,
                    (document_id, tenant_id),
                ).fetchone()
                if existing is None:
                    raise HTTPException(
                        status_code=404, detail="Document not found in this tenant."
                    )
                version_number = connection.execute(
                    "SELECT COALESCE(MAX(version_number), 0) + 1 AS next_version FROM rag_document_versions WHERE document_id = %s",
                    (document_id,),
                ).fetchone()["next_version"]
            duplicate = connection.execute(
                """
                SELECT d.id
                FROM rag_document_versions v
                JOIN rag_documents d ON d.id = v.document_id
                WHERE d.tenant_id = %s AND v.checksum = %s AND d.status <> 'deleted'
                LIMIT 1
                """,
                (tenant_id, checksum),
            ).fetchone()
            if duplicate:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="This document content already exists in the tenant.",
                )
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO rag_documents
                        (id, tenant_id, original_filename, storage_key, current_version,
                         status, access_scope, uploaded_by)
                    VALUES (%s, %s, %s, %s, %s, %s, 'employee', %s)
                    """,
                    (
                        document_id,
                        tenant_id,
                        original_filename,
                        original_key,
                        version_number,
                        document_status,
                        actor["id"],
                    ),
                )
            elif existing["status"] != "active":
                connection.execute(
                    "UPDATE rag_documents SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                    (document_status, document_id),
                )
            connection.execute(
                """
                INSERT INTO rag_document_versions
                    (id, document_id, version_number, checksum, storage_key, mime_type,
                     size_bytes, approval_status, ingestion_status, approved_by, approved_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s,
                        CASE WHEN %s THEN %s ELSE NULL END,
                        CASE WHEN %s THEN CURRENT_TIMESTAMP ELSE NULL END)
                """,
                (
                    version_id,
                    document_id,
                    version_number,
                    checksum,
                    original_key,
                    ALLOWED_EXTENSIONS[extension],
                    size_bytes,
                    approval_status,
                    ingestion_status,
                    approved,
                    actor["id"],
                    approved,
                ),
            )
            audit(
                connection,
                tenant_id=tenant_id,
                actor_id=actor["id"],
                document_id=document_id,
                version_id=version_id,
                action="document_upload",
                outcome="accepted",
                details={
                    "filename": original_filename,
                    "size_bytes": size_bytes,
                    "checksum": checksum,
                    "approval_status": approval_status,
                },
            )
    except Exception:
        original_path.unlink(missing_ok=True)
        raise

    return {
        "document_id": document_id,
        "version_id": version_id,
        "version_number": version_number,
        "status": document_status,
        "approval_status": approval_status,
        "ingestion_status": ingestion_status,
        "original_filename": original_filename,
        "size_bytes": size_bytes,
        "checksum": checksum,
    }


def list_documents(tenant_id: int) -> list[dict]:
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT d.id, d.tenant_id, d.original_filename, d.current_version, d.status,
                   d.access_scope, d.uploaded_by, d.created_at,
                   v.id AS version_id, v.version_number, v.checksum, v.mime_type,
                   v.size_bytes, v.approval_status, v.ingestion_status, v.chunk_count,
                   v.failure_reason, v.created_at AS version_created_at
            FROM rag_documents d
            JOIN LATERAL (
                SELECT * FROM rag_document_versions
                WHERE document_id = d.id
                ORDER BY version_number DESC LIMIT 1
            ) v ON TRUE
            WHERE d.tenant_id = %s AND d.status <> 'deleted'
            ORDER BY d.updated_at DESC, d.created_at DESC
            """,
            (tenant_id,),
        ).fetchall()
    return [document_payload(row) for row in rows]


def approve_document_version(version_id: str, administrator: dict) -> dict:
    with connect() as connection:
        version = connection.execute(
            """
            SELECT v.id, v.document_id, d.tenant_id
            FROM rag_document_versions v
            JOIN rag_documents d ON d.id = v.document_id
            WHERE v.id = %s AND v.approval_status = 'pending' AND d.status <> 'deleted'
            FOR UPDATE
            """,
            (version_id,),
        ).fetchone()
        if version is None:
            raise HTTPException(status_code=404, detail="Pending document version not found.")
        connection.execute(
            """
            UPDATE rag_document_versions
            SET approval_status = 'approved', ingestion_status = 'queued',
                approved_by = %s, approved_at = CURRENT_TIMESTAMP, failure_reason = NULL
            WHERE id = %s
            """,
            (administrator["id"], version_id),
        )
        connection.execute(
            """
            UPDATE rag_documents
            SET status = 'processing', updated_at = CURRENT_TIMESTAMP
            WHERE id = %s AND NOT EXISTS (
                SELECT 1 FROM rag_document_versions
                WHERE document_id = %s AND ingestion_status = 'active'
            )
            """,
            (version["document_id"], version["document_id"]),
        )
        audit(
            connection,
            tenant_id=version["tenant_id"],
            actor_id=administrator["id"],
            document_id=version["document_id"],
            version_id=version_id,
            action="document_approval",
            outcome="approved",
        )
    return {"version_id": version_id, "status": "queued"}


def reject_document_version(
    version_id: str, administrator: dict, reason: str
) -> dict:
    with connect() as connection:
        version = connection.execute(
            """
            SELECT v.id, v.document_id, v.storage_key, d.tenant_id, t.slug
            FROM rag_document_versions v
            JOIN rag_documents d ON d.id = v.document_id
            JOIN rag_tenants t ON t.id = d.tenant_id
            WHERE v.id = %s AND v.approval_status = 'pending' AND d.status <> 'deleted'
            FOR UPDATE
            """,
            (version_id,),
        ).fetchone()
        if version is None:
            raise HTTPException(status_code=404, detail="Pending document version not found.")
        current_path = checked_storage_path(version["storage_key"])
        rejected_key = version["storage_key"].replace("/originals/", "/quarantine/")
        rejected_path = checked_storage_path(rejected_key)
        rejected_path.parent.mkdir(parents=True, exist_ok=True)
        if current_path.exists():
            current_path.replace(rejected_path)
        connection.execute(
            """
            UPDATE rag_document_versions
            SET approval_status = 'rejected', ingestion_status = 'rejected',
                storage_key = %s, failure_reason = %s
            WHERE id = %s
            """,
            (rejected_key, reason or "Rejected by administrator.", version_id),
        )
        has_active = connection.execute(
            "SELECT 1 FROM rag_document_versions WHERE document_id = %s AND ingestion_status = 'active'",
            (version["document_id"],),
        ).fetchone()
        connection.execute(
            "UPDATE rag_documents SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
            ("active" if has_active else "rejected", version["document_id"]),
        )
        audit(
            connection,
            tenant_id=version["tenant_id"],
            actor_id=administrator["id"],
            document_id=version["document_id"],
            version_id=version_id,
            action="document_approval",
            outcome="rejected",
            details={"reason": reason},
        )
    return {"version_id": version_id, "status": "rejected"}


def revoke_document(document_id: str, tenant_id: int, actor: dict) -> None:
    with connect() as connection:
        document = connection.execute(
            """
            SELECT d.id, d.tenant_id, t.slug
            FROM rag_documents d
            JOIN rag_tenants t ON t.id = d.tenant_id
            WHERE d.id = %s AND d.tenant_id = %s AND d.status <> 'deleted'
            FOR UPDATE
            """,
            (document_id, tenant_id),
        ).fetchone()
        if document is None:
            raise HTTPException(status_code=404, detail="Document not found in this tenant.")
        connection.execute(
            "UPDATE rag_documents SET status = 'deleted', updated_at = CURRENT_TIMESTAMP WHERE id = %s",
            (document_id,),
        )
        connection.execute(
            "UPDATE rag_document_versions SET ingestion_status = 'revoked' WHERE document_id = %s",
            (document_id,),
        )
        audit(
            connection,
            tenant_id=tenant_id,
            actor_id=actor["id"],
            document_id=document_id,
            action="document_revocation",
            outcome="success",
            details={"originals_retained": True},
        )
    delete_vectors(tenant_key(document), document_id)


def queue_reindex(document_id: str, tenant_id: int, actor: dict) -> dict:
    """Clone the active version so reindexing cannot interrupt current retrieval."""
    version_id = f"ver_{uuid4().hex[:16]}"
    with connect() as connection:
        current = connection.execute(
            """
            SELECT d.id AS document_id, d.tenant_id, d.current_version,
                   v.checksum, v.storage_key, v.mime_type, v.size_bytes
            FROM rag_documents d
            JOIN rag_document_versions v
              ON v.document_id = d.id AND v.version_number = d.current_version
            WHERE d.id = %s AND d.tenant_id = %s AND d.status = 'active'
              AND v.ingestion_status = 'active'
            FOR UPDATE
            """,
            (document_id, tenant_id),
        ).fetchone()
        if current is None:
            raise HTTPException(status_code=404, detail="Active document not found in this tenant.")
        next_version = connection.execute(
            "SELECT COALESCE(MAX(version_number), 0) + 1 AS number FROM rag_document_versions WHERE document_id = %s",
            (document_id,),
        ).fetchone()["number"]
        connection.execute(
            """
            INSERT INTO rag_document_versions
                (id, document_id, version_number, checksum, storage_key, mime_type,
                 size_bytes, approval_status, ingestion_status, approved_by, approved_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'approved', 'queued', %s,
                    CURRENT_TIMESTAMP)
            """,
            (
                version_id,
                document_id,
                next_version,
                current["checksum"],
                current["storage_key"],
                current["mime_type"],
                current["size_bytes"],
                actor["id"],
            ),
        )
        audit(
            connection,
            tenant_id=tenant_id,
            actor_id=actor["id"],
            document_id=document_id,
            version_id=version_id,
            action="document_reindex",
            outcome="queued",
            details={"source_version": current["current_version"]},
        )
    return {
        "document_id": document_id,
        "version_id": version_id,
        "version_number": next_version,
        "status": "queued",
    }


def search_tenant_knowledge(
    *, tenant_id: int, query: str, access_scopes: tuple[str, ...] = ("employee",), k: int = 5
) -> list[dict]:
    """Search with Chroma filters, then enforce PostgreSQL's active-version authority."""
    with connect() as connection:
        tenant = connection.execute(
            "SELECT id, slug FROM rag_tenants WHERE id = %s AND is_active = TRUE",
            (tenant_id,),
        ).fetchone()
        if tenant is None:
            return []
        active = connection.execute(
            """
            SELECT v.id
            FROM rag_document_versions v
            JOIN rag_documents d ON d.id = v.document_id
            WHERE d.tenant_id = %s AND d.status = 'active'
              AND v.ingestion_status = 'active' AND d.access_scope = ANY(%s)
            """,
            (tenant_id, list(access_scopes)),
        ).fetchall()
    active_ids = {row["id"] for row in active}
    if not active_ids:
        return []
    query_embedding = OpenAIEmbeddings(model=EMBEDDING_MODEL).embed_query(query)
    result = chroma_collection().query(
        query_embeddings=[query_embedding],
        n_results=max(k * 3, k),
        where={
            "$and": [
                {"tenant_id": tenant_key(tenant)},
                {"status": "active"},
                {"access_scope": {"$in": list(access_scopes)}},
            ]
        },
        include=["documents", "metadatas", "distances"],
    )
    matches = []
    for text, metadata, distance in zip(
        result["documents"][0], result["metadatas"][0], result["distances"][0]
    ):
        if metadata["version_id"] not in active_ids:
            continue
        matches.append({"text": text, "metadata": metadata, "distance": distance})
        if len(matches) == k:
            break
    return matches


def create_document_router(
    require_admin: Callable[..., dict], require_manager: Callable[..., dict]
) -> APIRouter:
    router = APIRouter(tags=["document storage"])

    @router.post(
        "/api/admin/tenants/{tenant_id}/documents",
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def admin_upload_document(
        tenant_id: int,
        background_tasks: BackgroundTasks,
        file: UploadFile = File(...),
        administrator: dict = Depends(require_admin),
    ) -> dict:
        result = await register_upload(
            tenant_id=tenant_id, actor=administrator, upload=file, approved=True
        )
        background_tasks.add_task(process_document_version, result["version_id"])
        return result

    @router.post(
        "/api/admin/tenants/{tenant_id}/documents/{document_id}/versions",
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def admin_upload_version(
        tenant_id: int,
        document_id: str,
        background_tasks: BackgroundTasks,
        file: UploadFile = File(...),
        administrator: dict = Depends(require_admin),
    ) -> dict:
        result = await register_upload(
            tenant_id=tenant_id,
            actor=administrator,
            upload=file,
            approved=True,
            document_id=document_id,
        )
        background_tasks.add_task(process_document_version, result["version_id"])
        return result

    @router.get("/api/admin/tenants/{tenant_id}/documents")
    def admin_list_documents(
        tenant_id: int, _: dict = Depends(require_admin)
    ) -> list[dict]:
        return list_documents(tenant_id)

    @router.post("/api/admin/documents/{version_id}/approve", status_code=202)
    def admin_approve_document(
        version_id: str,
        background_tasks: BackgroundTasks,
        administrator: dict = Depends(require_admin),
    ) -> dict:
        result = approve_document_version(version_id, administrator)
        background_tasks.add_task(process_document_version, version_id)
        return result

    @router.post("/api/admin/documents/{version_id}/reject")
    def admin_reject_document(
        version_id: str,
        payload: DocumentDecisionRequest,
        administrator: dict = Depends(require_admin),
    ) -> dict:
        return reject_document_version(version_id, administrator, payload.reason.strip())

    @router.delete(
        "/api/admin/tenants/{tenant_id}/documents/{document_id}",
        status_code=status.HTTP_204_NO_CONTENT,
    )
    def admin_revoke_document(
        tenant_id: int,
        document_id: str,
        administrator: dict = Depends(require_admin),
    ) -> None:
        revoke_document(document_id, tenant_id, administrator)

    @router.post(
        "/api/admin/tenants/{tenant_id}/documents/{document_id}/reindex",
        status_code=status.HTTP_202_ACCEPTED,
    )
    def admin_reindex_document(
        tenant_id: int,
        document_id: str,
        background_tasks: BackgroundTasks,
        administrator: dict = Depends(require_admin),
    ) -> dict:
        result = queue_reindex(document_id, tenant_id, administrator)
        background_tasks.add_task(process_document_version, result["version_id"])
        return result

    @router.post("/api/manager/documents", status_code=status.HTTP_202_ACCEPTED)
    async def manager_upload_document(
        file: UploadFile = File(...),
        manager: dict = Depends(require_manager),
    ) -> dict:
        return await register_upload(
            tenant_id=manager["tenant_id"], actor=manager, upload=file, approved=False
        )

    @router.post(
        "/api/manager/documents/{document_id}/versions",
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def manager_upload_version(
        document_id: str,
        file: UploadFile = File(...),
        manager: dict = Depends(require_manager),
    ) -> dict:
        return await register_upload(
            tenant_id=manager["tenant_id"],
            actor=manager,
            upload=file,
            approved=False,
            document_id=document_id,
        )

    @router.get("/api/manager/documents")
    def manager_list_documents(manager: dict = Depends(require_manager)) -> list[dict]:
        return list_documents(manager["tenant_id"])

    @router.delete(
        "/api/manager/documents/{document_id}",
        status_code=status.HTTP_204_NO_CONTENT,
    )
    def manager_revoke_document(
        document_id: str, manager: dict = Depends(require_manager)
    ) -> None:
        revoke_document(document_id, manager["tenant_id"], manager)

    @router.post(
        "/api/manager/documents/{document_id}/reindex",
        status_code=status.HTTP_202_ACCEPTED,
    )
    def manager_reindex_document(
        document_id: str,
        background_tasks: BackgroundTasks,
        manager: dict = Depends(require_manager),
    ) -> dict:
        result = queue_reindex(document_id, manager["tenant_id"], manager)
        background_tasks.add_task(process_document_version, result["version_id"])
        return result

    return router
