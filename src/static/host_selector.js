(function () {
  function splitHosts(value) {
    return (value || "")
      .split(/[\s,]+/)
      .map((part) => part.trim())
      .filter(Boolean);
  }

  function initHostSelector(wrapper) {
    const targetId = wrapper.dataset.target;
    if (!targetId) {
      return;
    }
    const target = document.getElementById(targetId);
    if (!target) {
      return;
    }

    const searchInput = wrapper.querySelector("input[data-host-search]");
    const results = wrapper.querySelector(".host-selector-results");
    if (!searchInput || !results) {
      return;
    }

    let nodes = [];
    try {
      nodes = JSON.parse(wrapper.dataset.nodes || "[]");
      if (!Array.isArray(nodes)) {
        nodes = [];
      }
    } catch (err) {
      nodes = [];
    }

    let matches = [];
    let selectingFromResults = false;

    function closeResults() {
      results.hidden = true;
      matches = [];
      results.innerHTML = "";
    }

    function appendHost(rawValue) {
      const host = (rawValue || "").trim();
      if (!host) {
        return;
      }
      const existing = splitHosts(target.value);
      const normalized = existing.map((entry) => entry.toLowerCase());
      if (!normalized.includes(host.toLowerCase())) {
        existing.push(host);
        target.value = existing.join("\n");
      }
      results.hidden = false;
      window.requestAnimationFrame(() => {
        searchInput.focus();
        const qLen = searchInput.value.length;
        if (typeof searchInput.setSelectionRange === "function") {
          searchInput.setSelectionRange(qLen, qLen);
        }
      });
      window.setTimeout(() => {
        selectingFromResults = false;
      }, 160);
    }

    function renderMatches(term) {
      const query = term.trim().toLowerCase();
      if (!query) {
        closeResults();
        return;
      }

      matches = nodes.filter((node) => {
        const caption = (node.caption || "").toLowerCase();
        const value = (node.value || "").toLowerCase();
        const label = (node.label || "").toLowerCase();
        const organization = (node.organization || "").toLowerCase();
        const model = (node.model || "").toLowerCase();
        const vendor = (node.vendor || "").toLowerCase();
        return (
          caption.includes(query) ||
          value.includes(query) ||
          label.includes(query) ||
          organization.includes(query) ||
          model.includes(query) ||
          vendor.includes(query)
        );
      });

      if (!matches.length) {
        closeResults();
        return;
      }

      results.innerHTML = "";
      matches.forEach((node) => {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "host-selector-item";
        btn.dataset.value = node.value || "";

        const primary = document.createElement("div");
        primary.className = "host-selector-primary";
        primary.textContent = node.caption || node.value || "";
        btn.appendChild(primary);

        const secondaryParts = [];
        if (
          node.caption &&
          node.value &&
          node.caption.toLowerCase() !== node.value.toLowerCase()
        ) {
          secondaryParts.push(node.value);
        }
        if (node.organization) {
          secondaryParts.push(node.organization);
        } else if (node.model) {
          secondaryParts.push(node.model);
        }

        if (secondaryParts.length) {
          const secondary = document.createElement("div");
          secondary.className = "host-selector-secondary";
          secondary.textContent = secondaryParts.join(" · ");
          btn.appendChild(secondary);
        }

        results.appendChild(btn);
      });

      results.hidden = false;
    }

    searchInput.addEventListener("input", function () {
      renderMatches(searchInput.value);
    });

    searchInput.addEventListener("keydown", function (event) {
      if (event.key === "Enter") {
        event.preventDefault();
        if (matches[0]) {
          appendHost(matches[0].value);
        }
      } else if (event.key === "Escape") {
        searchInput.value = "";
        closeResults();
      }
    });

    results.addEventListener("mousedown", function (event) {
      const item = event.target.closest(".host-selector-item");
      if (!item || !item.dataset.value) {
        return;
      }
      event.preventDefault();
      selectingFromResults = true;
      appendHost(item.dataset.value);
    });

    document.addEventListener("mousedown", function (event) {
      if (!wrapper.contains(event.target)) {
        closeResults();
      }
    });

    searchInput.addEventListener("blur", function () {
      window.setTimeout(() => {
        if (selectingFromResults) {
          searchInput.focus();
          return;
        }
        if (!wrapper.contains(document.activeElement)) {
          closeResults();
        }
      }, 120);
    });

    if (!nodes.length) {
      closeResults();
      searchInput.disabled = true;
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    document
      .querySelectorAll("[data-host-selector]")
      .forEach((wrapper) => initHostSelector(wrapper));
  });
})();
