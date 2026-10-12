#!/usr/bin/env bash
# 端到端演示：平台 + 独立机器服务，全部经真实 HTTP 链路，不绕过任何授权。
# 依赖：go、curl、python3（标准库）。jq 可选。
#
# 重复运行：脚本使用专用数据库 data/demo.db；如已存在需 DEMO_FRESH=1 显式重置
# （只删除 demo 数据库，不影响开发库 data/agentpermit.db 或兼容旧库 data/aad.db，也不修改任何已有用户密码）。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DB="$ROOT/data/demo.db"
CREDS="$ROOT/data/demo-credentials.env"
PLATFORM_LOG="$ROOT/data/demo-platform.log"
MACHINE_LOG="$ROOT/data/demo-machine.log"
DEMO_RESPONSE="$ROOT/data/demo-last.json"
BIN_DIR="$ROOT/data/bin"

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

if [ -f "$DB" ]; then
  if [ "${DEMO_FRESH:-0}" = "1" ]; then
    rm -f "$DB" "$DB-wal" "$DB-shm" "$CREDS"
    echo "已重置演示数据库 $DB"
  else
    echo "演示数据库已存在：$DB"
    echo "如需重新完整演示，请运行：DEMO_FRESH=1 $0"
    exit 1
  fi
fi

command -v go >/dev/null || { echo "缺少 go"; exit 1; }
command -v python3 >/dev/null || { echo "缺少 python3"; exit 1; }
command -v curl >/dev/null || { echo "缺少 curl"; exit 1; }

if curl -sf -o /dev/null http://127.0.0.1:8080/healthz; then
  echo "127.0.0.1:8080 已被占用（可能已有平台在运行），请先停止后重试。"; exit 1
fi
if curl -sf -o /dev/null http://127.0.0.1:9090/healthz; then
  echo "127.0.0.1:9090 已被占用，请先停止后重试。"; exit 1
fi

PLAT_PID=""; MACHINE_PID=""
cleanup() {
  [ -n "$MACHINE_PID" ] && kill "$MACHINE_PID" 2>/dev/null || true
  [ -n "$PLAT_PID" ] && kill "$PLAT_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

mkdir -p "$BIN_DIR" data

say "编译两个进程"
go build -o "$BIN_DIR/agentpermit" ./cmd/server
go build -o "$BIN_DIR/agentpermit-demo-machine-service" ./cmd/demo-machine-service

say "1-2. 启动平台（独立数据库 ${DB}）"
AGENTPERMIT_DB_PATH="$DB" AGENTPERMIT_LISTEN_ADDR=127.0.0.1:8080 AGENTPERMIT_BASE_URL=http://127.0.0.1:8080 \
  "$BIN_DIR/agentpermit" >"$PLATFORM_LOG" 2>&1 &
PLAT_PID=$!
for i in $(seq 1 50); do
  curl -sf -o /dev/null http://127.0.0.1:8080/healthz && break
  sleep 0.2
done
curl -sf -o /dev/null http://127.0.0.1:8080/healthz || { echo "平台启动失败，查看 $PLATFORM_LOG"; exit 1; }
echo "平台已启动: http://127.0.0.1:8080（日志 ${PLATFORM_LOG}）"

say "3-6. 注册用户 / 创建调用凭证 / 发布能力（全部走网页表单 + CSRF）"
python3 scripts/demo_flow.py setup
# shellcheck disable=SC1090
. "$CREDS"

say "7. 启动独立 Demo 机器服务（127.0.0.1:9090，携带 Service Token）"
AGENTPERMIT_BASE_URL=http://127.0.0.1:8080 AGENTPERMIT_SERVICE_TOKEN="$SERVICE_TOKEN" AGENTPERMIT_DEMO_LISTEN_ADDR=127.0.0.1:9090 \
  "$BIN_DIR/agentpermit-demo-machine-service" >"$MACHINE_LOG" 2>&1 &
MACHINE_PID=$!
for i in $(seq 1 50); do
  curl -sf -o /dev/null http://127.0.0.1:9090/healthz && break
  sleep 0.2
done
curl -sf -o /dev/null http://127.0.0.1:9090/healthz || { echo "机器服务启动失败，查看 $MACHINE_LOG"; exit 1; }
echo "机器服务已启动: http://127.0.0.1:9090"

call() { # call <agent_token> <machine> <预期说明>
  local code
  code=$(curl -s -o "$DEMO_RESPONSE" -w '%{http_code}' \
    -H "Authorization: Bearer $1" "http://127.0.0.1:9090/machines/$2/spec")
  printf '%s  %s  %s\n' "$code" "$2" "$(cat "$DEMO_RESPONSE")"
  LAST_CODE=$code
}

expect() { # expect <code> <说明>
  if [ "$LAST_CODE" != "$1" ]; then
    echo "断言失败：期望 HTTP $1，实际 ${LAST_CODE}（$2）"
    exit 1
  fi
  echo "  ✓ $2"
}

say "8. 张三（两条调用凭证）、李四（一条调用凭证）调用机器服务，均成功"
call "$AGENT_ZHANGSAN_1" machine-001 "张三-Agent-1"; expect 200 "张三-Agent-1 成功"
call "$AGENT_ZHANGSAN_2" machine-002 "张三-Agent-2"; expect 200 "张三-Agent-2 成功"
call "$AGENT_LISI" machine-001 "李四-Agent"; expect 200 "李四-Agent 成功"

say "9. 王五把张三（真人账号）加入黑名单"
python3 scripts/demo_flow.py deny wangwu zhangsan

say "10. 张三的两条调用凭证全部被拒（user_blacklisted）"
call "$AGENT_ZHANGSAN_1" machine-001; expect 403 "张三-Agent-1 被拒绝"
call "$AGENT_ZHANGSAN_2" machine-001; expect 403 "张三-Agent-2 被拒绝（黑名单按账号生效）"

say "11. 李四不受影响"
call "$AGENT_LISI" machine-001; expect 200 "李四仍成功"

say "12. 王五切换到白名单模式，仅加入李四"
python3 scripts/demo_flow.py mode wangwu allowlist
python3 scripts/demo_flow.py allow wangwu lisi

say "13. 李四成功；其他非所有者用户（张三）失败"
call "$AGENT_LISI" machine-001; expect 200 "李四（白名单内）成功"
call "$AGENT_ZHANGSAN_1" machine-001; expect 403 "张三（非白名单且被拉黑）失败"

say "14. 撤销李四的调用凭证"
python3 scripts/demo_flow.py revoke-credential lisi

say "15. 李四原有 Token 不能再发现能力或调用服务"
call "$AGENT_LISI" machine-001; expect 401 "撤销后调用服务 → 401"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $AGENT_LISI" \
  http://127.0.0.1:8080/api/v1/capabilities)
echo "  Agent API 能力列表 → HTTP $code"
[ "$code" = "401" ] && echo "  ✓ 撤销后不能发现能力" || { echo "  ✗ 期望 401"; exit 1; }

say "16. 审计记录（王五视角：自己能力的访问事件）"
python3 scripts/demo_flow.py audit wangwu

say "演示完成 ✓  平台 http://127.0.0.1:8080 / 机器服务 http://127.0.0.1:9090 仍在运行"
echo "  - 登录账号：wangwu / zhangsan / lisi，密码见 ${CREDS}（chmod 600）"
echo "  - 浏览器打开 http://127.0.0.1:8080 登录王五可查看能力、黑名单与审计"
echo "  - 停止两个进程：kill $MACHINE_PID ${PLAT_PID}（或 Ctrl+C）"
wait
