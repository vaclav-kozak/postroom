// Copy-to-clipboard for the MCP URL and a new API key. The buttons ship `hidden` and are shown
// only when this script runs and the Clipboard API is available (it needs a secure context:
// https, or http on localhost). Without it the value stays selectable (`user-select: all`).
"use strict";

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
