# RAG security incident response

This feature turns suspicious questions and retrieved evidence into actionable,
tenant-scoped reports while preventing that content from reaching answer generation.

## Detection-to-response pipeline

```text
Authenticated question
        |
        v
Deterministic question screening ---- finding ----> block + incident report
        |
        v
Tenant/ACL-filtered retrieval
        |
        v
Screen every retrieved chunk -------- finding ----> block + incident report
        |
        v
Evidence-only generation -> citation/support validation -> answer or abstention
```

The LLM is never asked to interpret content that the detector has flagged. A
blocked response does not disclose which rule matched or echo the suspicious text.

## Report contents

Each row in `rag_security_incidents` includes:

- incident ID, status, category, severity, and detection/update timestamps;
- tenant, initiating user, request ID, and active contract ID/version;
- source (`user_query` or `retrieved_content`);
- document, version, and chunk IDs when retrieved evidence caused the finding;
- machine-readable indicator names;
- a SHA-256 evidence hash for correlation; and
- a short evidence excerpt with email addresses, long token-like values, and
  concealed Unicode redacted or visibly marked.

Raw questions are not added to the query audit. Incident excerpts are deliberately
limited, but they can still contain business information and must be treated as
sensitive operational data.

## Visibility and workflow

- Tenant managers use **Security reports** or
  `GET /api/manager/security/incidents`. The API always derives their tenant from
  the signed session and never accepts a client-selected tenant ID.
- Platform administrators use **Security incidents** or
  `GET /api/admin/security/incidents` for cross-tenant oversight and optional
  tenant/status filtering.
- `PATCH .../security/incidents/{incident_id}` accepts `acknowledged` or
  `resolved`. Resolved reports are terminal; an update to a resolved or inaccessible
  report returns 404 rather than revealing its existence.

Recommended triage:

1. verify the actor, tenant, time, source, contract version, and indicators;
2. for retrieved-content findings, quarantine or revoke the referenced document
   and inspect its original outside the LLM pipeline;
3. review nearby query and document audit events by request/document ID;
4. determine whether credentials, tenant boundaries, or source approvals were
   affected; and
5. record remediation externally as needed, then resolve the in-app report.

The current implementation creates in-app reports. Email, SMS, SIEM, or webhook
delivery is not yet implemented.

## Limitations

Pattern detection can produce false positives and cannot detect every obfuscated
attack. It complements—but does not replace—source approval, malware scanning,
tenant/ACL enforcement, contract validation, retrieval metadata verification,
least-privilege access, and human incident review.
