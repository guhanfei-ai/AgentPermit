(function () {
  "use strict";
  document.querySelectorAll("[data-trust-credential-form]").forEach(function (form) {
    var person = form.querySelector("[data-trust-person]");
    var credential = form.querySelector("[data-trust-credential]");
    function update() {
      credential.value = "";
      Array.from(credential.options).forEach(function (option) {
        if (!option.value) return;
        var visible = person.value ? option.dataset.owner === person.value : false;
        option.hidden = !visible; option.disabled = !visible;
      });
    }
    person.addEventListener("change", update); update();
  });
  document.querySelectorAll("[data-trust-server]").forEach(function (select) {
    var group = select.form ? select.form.querySelector("[data-trust-group]") : null;
    if (!group) return;
    function update() {
      group.value = "";
      Array.from(group.options).forEach(function (option) {
        if (!option.value) return;
        var visible = option.dataset.server === select.value;
        option.hidden = !visible; option.disabled = !visible;
      });
    }
    select.addEventListener("change", update); update();
  });
  document.querySelectorAll("[data-trust-open]").forEach(function (button) {
    button.addEventListener("click", function () {
      var dialog = document.getElementById(button.dataset.trustOpen);
      if (!dialog) return;
      if (button.dataset.kind) {
        var form = dialog.querySelector("form"); var kind = button.dataset.kind;
        form.reset(); form.elements.kind.value = kind;
        form.elements.name.value = { person: "全局封人", credential: "全局封AI", condition: "条件封禁" }[kind];
        form.querySelector("[data-trust-person]").dispatchEvent(new Event("change"));
        form.elements.user_id.required = kind !== "condition";
        form.querySelectorAll("[data-ban-field]").forEach(function (field) {
          var show = field.dataset.banField === "condition" ? kind === "condition" : kind !== "person";
          field.hidden = !show;
          field.querySelectorAll("input,select").forEach(function (input) { input.disabled = !show; });
        });
        form.elements.credential_id.required = kind === "credential";
      }
      dialog.showModal();
    });
  });
  document.querySelectorAll("[data-trust-close]").forEach(function (button) {
    button.addEventListener("click", function () { button.closest("dialog").close(); });
  });
  var page = document.querySelector("[data-trust-page]");
  if (!page) return;
  var state = page.dataset.state;
  var serverTime = Number(page.dataset.now), syncedAt = performance.now();
  var lockAt = Number(page.dataset.lock || 0), endAt = Number(page.dataset.end || 0);
  var countdown = page.querySelector("[data-holiday-countdown]");
  var lastTick = 0;
  function draw() {
    var now = serverTime + (performance.now() - syncedAt) / 1000;
    var counting = state === "countdown" || state === "scheduled" && now >= Number(page.dataset.trigger);
    countdown.hidden = !counting;
    if (counting) {
      page.querySelector("[data-holiday-seconds]").textContent = Math.max(0, Math.ceil(lockAt - now));
      if (now >= lockAt && performance.now() - lastTick > 1000) { lastTick = performance.now(); sync(); }
    }
  }
  async function sync() {
    try {
      var response = await fetch("/trust/state", { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } });
      if (!response.ok) return;
      var data = await response.json();
      serverTime = data.now; syncedAt = performance.now();
      if (data.state !== state || (data.lock_at || 0) !== lockAt || (data.ends_at || 0) !== endAt) { location.reload(); return; }
      draw();
    } catch (_) { /* 服务端仍对所有写请求和核验执行封禁校验。 */ }
  }
  draw(); setInterval(draw, 200); setInterval(sync, 1500);
})();
