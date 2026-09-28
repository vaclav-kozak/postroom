// Progressive enhancements for the admin pages; everything works without this script.
//
// 1. Copy-to-clipboard for the MCP URL and a new API key. The buttons ship `hidden` and are
//    shown only when this script runs and the Clipboard API is available (it needs a secure
//    context: https, or http on localhost). Without it the value stays selectable
//    (`user-select: all`).
// 2. On the account form, an SMTP server suggested from the IMAP server while the SMTP host
//    is empty. It is only offered: the fields change when the owner clicks "Use these".
"use strict";

(function () {
  const imap = document.getElementById("imap_host");
  const host = document.getElementById("smtp_host");
  const port = document.getElementById("smtp_port");
  const security = document.getElementById("smtp_security");
  const box = document.getElementById("smtp-suggest");
  const use = document.getElementById("smtp-suggest-use");
  if (!imap || !host || !port || !security || !box || !use) return;
  const text = box.querySelector(".suggest-text");
  let current = null;

  // imap.example.com -> smtp.example.com; mail.example.com -> the same host; 465 SSL/TLS.
  function suggest(imapHost) {
    const h = imapHost.trim().toLowerCase();
    if (!/^[a-z0-9.-]+$/.test(h) || h.indexOf(".") < 0) return null;
    if (h === "outlook.office365.com") {
      return { host: "smtp.office365.com", port: "587", security: "starttls" };
    }
    if (h.indexOf("imap.") === 0 && h.length > 5) {
      return { host: "smtp." + h.slice(5), port: "465", security: "ssl" };
    }
    if (h.indexOf("mail.") === 0 && h.length > 5) {
      return { host: h, port: "465", security: "ssl" };
    }
    return null;
  }

  function update() {
    current = host.value.trim() ? null : suggest(imap.value);
    if (!current) {
      box.hidden = true;
      return;
    }
    const label = current.security === "ssl" ? "SSL/TLS" : "STARTTLS";
    text.textContent =
      "Suggested from the IMAP server: " + current.host + ", port " + current.port + ", " + label + ".";
    box.hidden = false;
  }

  use.addEventListener("click", function () {
    if (!current) return;
    host.value = current.host;
    port.value = current.port;
    security.value = current.security;
    box.hidden = true;
    host.focus();
  });
  imap.addEventListener("input", update);
  host.addEventListener("input", update);
  update();
})();

// Changing the SMTP security moves a default port along (465 <-> 587).
(function () {
  const port = document.getElementById("smtp_port");
  const security = document.getElementById("smtp_security");
  if (!port || !security) return;
  const defaults = { ssl: "465", starttls: "587" };
  security.addEventListener("change", function () {
    if (port.value === "" || port.value === "465" || port.value === "587") {
      port.value = defaults[security.value] || port.value;
    }
  });
})();

(function () {
  if (!navigator.clipboard || !window.isSecureContext) return;

  function selectText(el) {
    const range = document.createRange();
    range.selectNodeContents(el);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }

  document.querySelectorAll("button.copy[data-copy]").forEach(function (btn) {
    const target = document.getElementById(btn.dataset.copy);
    if (!target) return;
    const label = btn.textContent;
    let timer = 0;
    btn.setAttribute("aria-live", "polite");
    btn.hidden = false;
    btn.addEventListener("click", function () {
      navigator.clipboard.writeText(target.textContent.trim()).then(
        function () {
          btn.textContent = "Copied";
          btn.classList.add("is-done");
        },
        function () {
          selectText(target);
          btn.textContent = "Press Ctrl+C";
        },
      );
      clearTimeout(timer);
      timer = setTimeout(function () {
        btn.textContent = label;
        btn.classList.remove("is-done");
      }, 2000);
    });
  });
})();
