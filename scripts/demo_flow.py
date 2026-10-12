#!/usr/bin/env python3
"""本地演示自动化：所有操作均通过真实 HTTP 与网页表单完成，不绕过任何授权链路。

用法（由 scripts/demo.sh 调用，也可单独使用）：
  demo_flow.py setup                # 注册三个用户、创建调用凭证与能力、保存凭证
  demo_flow.py deny <owner> <user>  # owner 把 user 加入黑名单（网页表单）
  demo_flow.py allow <owner> <user> # owner 把 user 加入白名单
  demo_flow.py mode <owner> <team|allowlist>
  demo_flow.py revoke-credential <user>  # 撤销该账号的一条调用凭证（网页表单）
  demo_flow.py audit <user>         # 打印该用户可见的审计事件

环境变量：
  AGENTPERMIT_BASE_URL  平台地址（兼容旧名 AAD_BASE_URL），默认 http://127.0.0.1:8080
  DEMO_CREDS    凭证输出文件，默认 <repo>/data/demo-credentials.env（chmod 600）
"""
import http.cookiejar
import os
import re
import secrets
import sys
import urllib.parse
import urllib.request

BASE = os.environ.get("AGENTPERMIT_BASE_URL") or os.environ.get("AAD_BASE_URL") or "http://127.0.0.1:8080"
CREDS = os.environ.get(
    "DEMO_CREDS",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "demo-credentials.env"),
)

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
TOKEN_RE = re.compile(r'<code id="secret-token">([^<]+)</code>')
USER_ROW_RE = "<td>%s</td><td><code>%s</code></td>"


class Browser:
    """极简浏览器：Cookie Jar + 自动跟随重定向 + CSRF 提取。"""

    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def get(self, path):
        with self.opener.open(BASE + path, timeout=10) as resp:
            return resp.read().decode("utf-8"), resp.geturl()

    def post(self, path, fields):
        # 先 GET 同路径页面拿 CSRF（演示脚本专用，简化处理）
        html, _ = self.get(path if path in ("/login", "/register") else "/")
        m = CSRF_RE.search(html)
        if not m:
            raise RuntimeError("页面 %s 未找到 CSRF Token" % path)
        fields = dict(fields)
        fields["csrf_token"] = m.group(1)
        data = urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(BASE + path, data=data, method="POST")
        with self.opener.open(req, timeout=10) as resp:
            return resp.read().decode("utf-8"), resp.geturl()

    def csrf_from(self, path):
        html, _ = self.get(path)
        m = CSRF_RE.search(html)
        if not m:
            raise RuntimeError("页面 %s 未找到 CSRF Token" % path)
        return m.group(1), html


def register(username, display, password):
    b = Browser()
    _, csrf_html = b.csrf_from("/register")
    fields = {
        "csrf_token": CSRF_RE.search(csrf_html).group(1),
        "username": username,
        "display_name": display,
        "password": password,
        "password_confirm": password,
    }
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(BASE + "/register", data=data, method="POST")
    with b.opener.open(req, timeout=10) as resp:
        resp.read()
    return b


def login(username, password):
    b = Browser()
    _, csrf_html = b.csrf_from("/login")
    fields = {
        "csrf_token": CSRF_RE.search(csrf_html).group(1),
        "username": username,
        "password": password,
    }
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(BASE + "/login", data=data, method="POST")
    with b.opener.open(req, timeout=10) as resp:
        resp.read()
    return b


def create_credential(b, name):
    """创建调用凭证，跟随 303 提取 Token 与凭证记录 ID。"""
    html, url = b.post("/agents", {"name": name, "description": "演示调用凭证"})
    token = TOKEN_RE.search(html)
    if not token:
        raise RuntimeError("创建凭证 %s 后未能获取一次性 Token" % name)
    agent_id = url.rstrip("/").split("/")[-2]
    return agent_id, token.group(1)


def create_capability(b):
    html, url = b.post("/capabilities", {
        "name": "查询机器配置",
        "slug": "machine-spec",
        "description": "返回指定机器的 CPU、内存、磁盘、操作系统等模拟信息",
        "endpoint_url": "http://127.0.0.1:9090",
        "http_method": "GET",
        "api_path": "/machines/{machine_id}/spec",
        "spec_markdown": "## 查询机器配置\n\nGET /machines/{machine_id}/spec\n\nmachine_id 可选 machine-001、machine-002。\n认证：Bearer Agent Token（平台实时校验凭证归属与账号权限）。",
        "access_mode": "team",
    })
    token = TOKEN_RE.search(html)
    if not token:
        raise RuntimeError("创建能力后未能获取一次性 Service Token")
    cap_id = url.rstrip("/").split("/")[-2]
    return cap_id, token.group(1)


def find_user_id_on_access_page(b, cap_id, username, display):
    html, _ = b.get("/capabilities/%s/access?q=%s" % (cap_id, username))
    row_re = re.compile(
        USER_ROW_RE % (re.escape(display), re.escape(username)) + r".*?name=\"user_id\" value=\"([0-9a-f]+)\"",
        re.S,
    )
    m = row_re.search(html)
    if not m:
        raise RuntimeError("在权限管理页未找到用户 %s" % username)
    return m.group(1)


def cmd_setup():
    pw = "Demo-%s-9A" % secrets.token_urlsafe(9)
    creds = []
    users = {
        "wangwu": "王五",
        "zhangsan": "张三",
        "lisi": "李四",
    }
    # 1. 注册三个普通用户（真实走开放注册表单 + CSRF）
    for username, display in users.items():
        register(username, display, pw)
        creds.append(("PASS_%s" % username.upper(), pw))
        print("[setup] 已注册用户 %s（%s）" % (username, display))

    # 2. 张三创建两条调用凭证，李四创建一条
    zhang = login("zhangsan", pw)
    for i in (1, 2):
        agent_id, token = create_credential(zhang, "张三-Agent-%d" % i)
        creds.append(("AGENT_ZHANGSAN_%d" % i, token))
        creds.append(("AGENT_ZHANGSAN_%d_ID" % i, agent_id))
        print("[setup] 张三创建凭证: 张三-Agent-%d (%s)" % (i, agent_id))
    lisi = login("lisi", pw)
    lisi_agent_id, lisi_token = create_credential(lisi, "李四-Agent")
    creds.append(("AGENT_LISI", lisi_token))
    creds.append(("AGENT_LISI_ID", lisi_agent_id))
    print("[setup] 李四创建凭证: 李四-Agent (%s)" % lisi_agent_id)

    # 3. 王五发布能力并获取一次性展示的 Service Token
    wangwu = login("wangwu", pw)
    cap_id, svc_token = create_capability(wangwu)
    creds.append(("CAPABILITY_ID", cap_id))
    creds.append(("SERVICE_TOKEN", svc_token))
    print("[setup] 王五发布能力「查询机器配置」(%s) 并获得 Service Token" % cap_id)

    os.makedirs(os.path.dirname(CREDS), exist_ok=True)
    with open(CREDS, "w") as f:
        for k, v in creds:
            f.write("%s=%s\n" % (k, v))
        f.write("DEMO_PASSWORD=%s\n" % pw)
    os.chmod(CREDS, 0o600)
    print("[setup] 凭证已写入 %s（chmod 600，已被 .gitignore 排除）" % CREDS)


def load_creds():
    creds = {}
    with open(CREDS) as f:
        for line in f:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                creds[k] = v
    return creds


def cmd_deny(owner, target_username):
    c = load_creds()
    pw = c["DEMO_PASSWORD"]
    display = {"zhangsan": "张三", "lisi": "李四", "wangwu": "王五"}[target_username]
    b = login(owner, pw)
    cap_id = c["CAPABILITY_ID"]
    target_id = find_user_id_on_access_page(b, cap_id, target_username, display)
    b.post("/capabilities/%s/denylist/add" % cap_id, {"user_id": target_id})
    print("[deny] %s 已把 %s（%s）加入黑名单" % (owner, display, target_username))


def cmd_allow(owner, target_username):
    c = load_creds()
    pw = c["DEMO_PASSWORD"]
    display = {"zhangsan": "张三", "lisi": "李四", "wangwu": "王五"}[target_username]
    b = login(owner, pw)
    cap_id = c["CAPABILITY_ID"]
    target_id = find_user_id_on_access_page(b, cap_id, target_username, display)
    b.post("/capabilities/%s/allowlist/add" % cap_id, {"user_id": target_id})
    print("[allow] %s 已把 %s（%s）加入白名单" % (owner, display, target_username))


def cmd_mode(owner, mode):
    c = load_creds()
    b = login(owner, c["DEMO_PASSWORD"])
    cap_id = c["CAPABILITY_ID"]
    b.post("/capabilities/%s/access/mode" % cap_id, {"access_mode": mode})
    print("[mode] 能力访问模式已切换为 %s" % mode)


def cmd_revoke_credential(username):
    c = load_creds()
    b = login(username, c["DEMO_PASSWORD"])
    agent_id = c["AGENT_LISI_ID"] if username == "lisi" else c["AGENT_ZHANGSAN_1_ID"]
    b.post("/agents/%s/revoke" % agent_id, {})
    print("[revoke] 已撤销 %s 的调用凭证 %s" % (username, agent_id))


def cmd_audit(username):
    c = load_creds()
    b = login(username, c["DEMO_PASSWORD"])
    html, _ = b.get("/audit")
    events = re.findall(r'data-audit-event="([a-z_]+)"', html)
    print("[audit] %s 可见的审计事件（最近）：" % username)
    for e in events[:20]:
        print("       - %s" % e)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    cmd = sys.argv[1]
    if cmd == "setup":
        cmd_setup()
    elif cmd == "deny" and len(sys.argv) == 4:
        cmd_deny(sys.argv[2], sys.argv[3])
    elif cmd == "allow" and len(sys.argv) == 4:
        cmd_allow(sys.argv[2], sys.argv[3])
    elif cmd == "mode" and len(sys.argv) == 4:
        cmd_mode(sys.argv[2], sys.argv[3])
    elif cmd in ("revoke-credential", "revoke-agent") and len(sys.argv) == 3:
        cmd_revoke_credential(sys.argv[2])
    elif cmd == "audit" and len(sys.argv) == 3:
        cmd_audit(sys.argv[2])
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
