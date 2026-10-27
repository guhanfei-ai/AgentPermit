// 频道页原生 dialog 的焦点、遮罩与背景滚动增强，不读取或改写业务正文。
(function () {
  "use strict";

  document.querySelectorAll("dialog[data-channel-dialog]").forEach(function (dialog) {
    var trigger = null;
    var scroll = null;
    var bodyStyle = null;
    var startedOutside = false;

    function outside(event) {
      var rect = dialog.getBoundingClientRect();
      return event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom;
    }

    function open(button) {
      if (dialog.open) return;
      trigger = button;
      scroll = { x: window.scrollX, y: window.scrollY };
      bodyStyle = {};
      ["position", "top", "left", "width", "overflow"].forEach(function (property) {
        bodyStyle[property] = document.body.style[property];
      });
      document.body.style.position = "fixed";
      document.body.style.top = -scroll.y + "px";
      document.body.style.left = -scroll.x + "px";
      document.body.style.width = "100%";
      document.body.style.overflow = "hidden";
      dialog.showModal();
      var initial = dialog.querySelector("[data-channel-initial-focus]");
      if (initial) initial.focus({ preventScroll: true });
    }

    function restore() {
      if (!bodyStyle) return;
      Object.keys(bodyStyle).forEach(function (property) { document.body.style[property] = bodyStyle[property]; });
      window.scrollTo(scroll.x, scroll.y);
      bodyStyle = null;
      if (trigger && trigger.isConnected) trigger.focus({ preventScroll: true });
    }

    function closeDialog() {
      if (dialog.open) dialog.close();
      restore();
    }

    var buttons = document.querySelectorAll("[data-channel-dialog-open='" + dialog.id + "']");
    buttons.forEach(function (button) {
      button.addEventListener("click", function () { open(button); });
    });
    dialog.querySelectorAll("[data-channel-dialog-close]").forEach(function (button) {
      button.addEventListener("click", closeDialog);
    });
    dialog.addEventListener("pointerdown", function (event) { startedOutside = outside(event); });
    dialog.addEventListener("click", function (event) {
      if (event.target === dialog && startedOutside && outside(event)) closeDialog();
    });
    dialog.addEventListener("keydown", function (event) {
      if (event.key !== "Tab") return;
      var items = Array.from(dialog.querySelectorAll("a[href], button, input, select, textarea, [tabindex]:not([tabindex='-1'])")).filter(function (item) {
        return !item.disabled && item.getClientRects().length > 0;
      });
      var first = items[0], last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault(); last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault(); first.focus();
      }
    });
    dialog.addEventListener("close", restore);
    if (window.MutationObserver) {
      new MutationObserver(function () { if (!dialog.open) restore(); }).observe(dialog, { attributes: true, attributeFilter: ["open"] });
    }
    if (dialog.hasAttribute("data-channel-dialog-auto-open")) open(buttons[0] || null);
  });

  document.querySelectorAll("[data-channel-preview]").forEach(function (preview) {
    function update() { preview.classList.toggle("is-truncated", preview.scrollHeight > preview.clientHeight + 1); }
    update();
    if (window.ResizeObserver) new ResizeObserver(update).observe(preview);
    else window.addEventListener("resize", update);
  });
})();
