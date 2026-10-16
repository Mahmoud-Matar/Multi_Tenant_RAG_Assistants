export class TenantSelect {
  constructor(root, tenants = []) {
    this.root = root;
    this.tenants = tenants;
    this.trigger = root.querySelector(".tenant-select__trigger");
    this.menu = root.querySelector(".tenant-select__menu");
    this.valueLabel = root.querySelector(".tenant-select__value");
    this.badge = root.querySelector(".tenant-select__badge");
    this.input = root.querySelector('input[name="tenant"]');
    this.focusedIndex = -1;

    this.render();
    this.bindEvents();
  }

  setLoading(loading) {
    this.trigger.disabled = loading;
    if (loading) this.valueLabel.textContent = "Loading organizations…";
  }

  setTenants(tenants) {
    this.tenants = tenants;
    this.focusedIndex = -1;
    this.trigger.disabled = tenants.length === 0;
    this.valueLabel.textContent = tenants.length ? "Select your organization" : "No organizations available";
    this.render();
  }

  setError(message) {
    this.tenants = [];
    this.trigger.disabled = true;
    this.valueLabel.textContent = message;
    this.render();
  }

  render() {
    this.menu.replaceChildren(
      ...this.tenants.map((tenant, index) => {
        const item = document.createElement("li");
        item.setAttribute("role", "option");
        item.dataset.value = String(tenant.id);
        item.dataset.index = index;
        item.tabIndex = -1;
        item.className = "tenant-select__option";

        const mark = document.createElement("span");
        mark.className = "tenant-select__option-mark";
        mark.textContent = tenant.initials;

        const copy = document.createElement("span");
        const name = document.createElement("span");
        name.className = "tenant-select__option-name";
        name.textContent = tenant.name;
        const meta = document.createElement("span");
        meta.className = "tenant-select__option-meta";
        meta.textContent = tenant.meta;
        copy.append(name, meta);
        item.append(mark, copy);
        return item;
      }),
    );
  }

  bindEvents() {
    this.trigger.addEventListener("click", () => this.toggle());
    this.menu.addEventListener("click", (event) => {
      const option = event.target.closest('[role="option"]');
      if (option) this.select(Number(option.dataset.index));
    });
    this.trigger.addEventListener("keydown", (event) => this.handleKeydown(event));
    this.menu.addEventListener("keydown", (event) => this.handleKeydown(event));
    document.addEventListener("pointerdown", (event) => {
      if (!this.root.contains(event.target)) this.close();
    });
    this.root.closest("form")?.addEventListener("reset", () => {
      this.input.value = "";
      this.valueLabel.textContent = "Select your organization";
      this.valueLabel.classList.add("is-placeholder");
      this.badge.textContent = "";
      this.focusedIndex = -1;
    });
  }

  toggle() { this.root.classList.contains("is-open") ? this.close() : this.open(); }

  open() {
    this.root.classList.add("is-open");
    this.trigger.setAttribute("aria-expanded", "true");
    this.menu.hidden = false;
    this.focusOption(this.focusedIndex >= 0 ? this.focusedIndex : 0);
  }

  close({ returnFocus = false } = {}) {
    this.root.classList.remove("is-open");
    this.trigger.setAttribute("aria-expanded", "false");
    this.menu.hidden = true;
    if (returnFocus) this.trigger.focus();
  }

  select(index) {
    const tenant = this.tenants[index];
    if (!tenant) return;
    this.input.value = String(tenant.id);
    this.valueLabel.textContent = tenant.name;
    this.valueLabel.classList.remove("is-placeholder");
    this.badge.textContent = tenant.initials;
    this.root.closest(".field")?.classList.remove("has-error");
    this.close({ returnFocus: true });
  }

  focusOption(index) {
    const options = [...this.menu.querySelectorAll('[role="option"]')];
    if (!options.length) return;
    this.focusedIndex = (index + options.length) % options.length;
    options.forEach((option, itemIndex) => option.classList.toggle("is-focused", itemIndex === this.focusedIndex));
    options[this.focusedIndex].focus();
  }

  handleKeydown(event) {
    if (event.key === "Escape") {
      event.preventDefault();
      this.close({ returnFocus: true });
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      if (!this.root.classList.contains("is-open")) this.open();
      else this.focusOption(this.focusedIndex + 1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      if (!this.root.classList.contains("is-open")) this.open();
      else this.focusOption(this.focusedIndex - 1);
    } else if ((event.key === "Enter" || event.key === " ") && this.root.classList.contains("is-open")) {
      event.preventDefault();
      this.select(this.focusedIndex);
    }
  }
}
