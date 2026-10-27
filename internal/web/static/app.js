// 危险操作确认 + 复制按钮，原生 JS，无外部依赖。
(function () {
  "use strict";

  // 账号下拉使用原生展开交互，点击外部或按 Esc 时收起。
  var accountMenus = document.querySelectorAll("[data-account-menu]");
  document.addEventListener("click", function (e) {
    accountMenus.forEach(function (menu) {
      if (!menu.contains(e.target)) menu.open = false;
    });
  });
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    accountMenus.forEach(function (menu) {
      if (menu.open) {
        menu.open = false;
        menu.querySelector("summary").focus();
      }
    });
  });

  // 先选禁言范围；账号级提交不携带凭证，单凭证范围要求明确选择。
  document.querySelectorAll("[data-ban-form]").forEach(function (form) {
    var scope = form.querySelector("[data-ban-scope]");
    var choice = form.querySelector("[data-credential-choice]");
    var credential = form.querySelector("[data-ban-credential]");
    var update = function () {
      var single = scope.value === "credential";
      choice.hidden = !single;
      credential.disabled = !single;
      credential.required = single;
    };
    scope.addEventListener("change", update);
    update();
  });

  // 表单危险操作确认
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (form && form.getAttribute && form.getAttribute("data-confirm")) {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        e.preventDefault();
      }
    }
  });

  // 复制按钮：data-copy 指向要复制的元素选择器
  document.addEventListener("click", function (e) {
    var btn = e.target.closest ? e.target.closest("[data-copy]") : null;
    if (!btn) return;
    var el = document.querySelector(btn.getAttribute("data-copy"));
    if (!el) return;
    var text = el.textContent || el.innerText || "";
    var done = function () {
      var old = btn.textContent;
      btn.textContent = "已复制";
      setTimeout(function () { btn.textContent = old; }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text, done); });
    } else {
      fallbackCopy(text, done);
    }
  });

  function fallbackCopy(text, done) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); done(); } catch (err) { /* 忽略 */ }
    document.body.removeChild(ta);
  }
})();
