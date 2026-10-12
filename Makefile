# 加载 .env（若存在）。Go 程序本身不读取 .env，由这里的 shell 完成注入。
ENV_FILE := $(wildcard .env)
LOAD_ENV := set -a; [ -f .env ] && . ./.env; set +a

BINARY_PLATFORM := agentpermit
BINARY_DEMO := agentpermit-demo-machine-service

# 后台运行期的 pid / 日志（data/ 与 *.log 已在 .gitignore 中）
RUN_DIR := data
PID_PLATFORM := $(RUN_DIR)/agentpermit.pid
LOG_PLATFORM := $(RUN_DIR)/agentpermit.log
PID_DEMO := $(RUN_DIR)/agentpermit-demo-machine-service.pid
LOG_DEMO := $(RUN_DIR)/agentpermit-demo-machine-service.log
PLATFORM_HEALTH ?= http://127.0.0.1:8080/healthz
DEMO_HEALTH ?= http://127.0.0.1:9090/healthz
# 端口占用检测 / 兜底停止用（改了 .env 里的 LISTEN_ADDR 时需同步修改）
PLATFORM_PORT ?= 8080
DEMO_PORT ?= 9090

.PHONY: run run-demo-service test race build fmt vet clean create-admin \
	start start-demo-service stop stop-demo-service \
	restart restart-demo-service status

$(RUN_DIR):
	@mkdir -p $(RUN_DIR)

# 启动平台（127.0.0.1:8080）
run:
	@sh -c '$(LOAD_ENV); exec go run ./cmd/server'

# 启动独立 Demo 机器服务（127.0.0.1:9090），需要先设置 AGENTPERMIT_SERVICE_TOKEN
run-demo-service:
	@sh -c '$(LOAD_ENV); exec go run ./cmd/demo-machine-service'

# 后台启动 / 停止 / 重启：进程 pid 写入 data/*.pid，日志写入 data/*.log
# $(call start_proc,<pid文件>,<名称>,<restart目标>,<二进制>,<日志>,<健康检查URL>,<端口>)
define start_proc
@if [ -f "$(1)" ] && kill -0 "$$(cat $(1))" 2>/dev/null; then \
	echo "$(2) 已在运行（pid $$(cat $(1))）；需要重启请执行：make $(3)"; exit 0; \
 fi; \
 rm -f "$(1)"; \
 if [ -n "$(8)" ] && command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:$(8) -sTCP:LISTEN -t 2>/dev/null | grep -q .; then \
	echo "端口 $(8) 已被占用，$(2) 未启动（先 make stop，或直接 make $(3)）"; exit 1; \
 fi; \
 $(MAKE) --no-print-directory build || { echo "编译失败，$(2) 未启动"; exit 1; }; \
 mkdir -p $(RUN_DIR); \
 sh -c '$(LOAD_ENV); exec ./bin/$(4)' >>$(5) 2>&1 & echo $$! > $(1); \
 echo "$(2) 已启动：pid $$(cat $(1))，日志 $(5)"; \
 ok=0; \
 for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do \
	 if curl -sf -o /dev/null "$(6)"; then ok=1; break; fi; \
	 sleep 0.25; \
 done; \
 if [ "$$ok" = "1" ]; then echo "$(2) 已就绪：$(6)"; else echo "$(2) 尚未响应健康检查 $(6)，请查看日志 $(5)"; fi
endef

# $(call stop_proc,<pid文件>,<名称>,<端口>)
define stop_proc
@sh -c 'f="$(1)"; name="$(2)"; port="$(3)"; pids=""; \
if [ -f "$$f" ]; then \
	pid=$$(cat "$$f"); \
	if kill -0 "$$pid" 2>/dev/null; then pids="$$pid"; else echo "$$name 的 pid 文件已过期，清理 $$f"; rm -f "$$f"; fi; \
fi; \
if [ -z "$$pids" ] && [ -n "$$port" ] && command -v lsof >/dev/null 2>&1; then \
	found=$$(lsof -nP -iTCP:$$port -sTCP:LISTEN -t 2>/dev/null | tr "\n" " "); \
	if [ -n "$$found" ]; then echo "$$name 无有效 pid 文件，按监听端口 $$port 找到进程：$$found"; pids="$$found"; fi; \
fi; \
if [ -z "$$pids" ]; then echo "$$name 未运行"; exit 0; fi; \
for pid in $$pids; do echo "停止 $$name（pid $$pid）"; kill "$$pid" 2>/dev/null; done; \
waited=0; \
while [ $$waited -lt 10 ]; do \
	alive=0; \
	for pid in $$pids; do kill -0 "$$pid" 2>/dev/null && alive=1; done; \
	[ "$$alive" = "0" ] && break; \
	sleep 0.5; waited=$$((waited+1)); \
done; \
for pid in $$pids; do \
	if kill -0 "$$pid" 2>/dev/null; then echo "$$name（pid $$pid）未在 5 秒内退出，发送 SIGKILL"; kill -9 "$$pid" 2>/dev/null; fi; \
done; \
rm -f "$$f"; echo "$$name 已停止"'
endef

# $(call status_proc,<pid文件>,<名称>,<健康检查URL>)
define status_proc
@sh -c 'f="$(1)"; name="$(2)"; url="$(3)"; \
if [ -f "$$f" ] && kill -0 "$$(cat $$f)" 2>/dev/null; then \
	echo "$$name: 运行中 pid=$$(cat $$f)"; \
else \
	echo "$$name: 未运行"; \
fi; \
if command -v curl >/dev/null 2>&1; then \
	if curl -sf -o /dev/null "$$url"; then echo "  健康检查 OK:  $$url"; else echo "  健康检查失败: $$url"; fi; \
else \
	echo "  未安装 curl，跳过健康检查: $$url"; \
fi'
endef

# 后台启动平台（先 build，再按 pid 文件托管进程）
start: | $(RUN_DIR)
	$(call start_proc,$(PID_PLATFORM),平台,restart,$(BINARY_PLATFORM),$(LOG_PLATFORM),$(PLATFORM_HEALTH),$(PLATFORM_PORT))

# 后台启动 Demo 机器服务（需先设置 AGENTPERMIT_SERVICE_TOKEN，可写在 .env 中）
start-demo-service: | $(RUN_DIR)
	$(call start_proc,$(PID_DEMO),Demo 机器服务,restart-demo-service,$(BINARY_DEMO),$(LOG_DEMO),$(DEMO_HEALTH),$(DEMO_PORT))

stop:
	$(call stop_proc,$(PID_PLATFORM),平台,$(PLATFORM_PORT))

stop-demo-service:
	$(call stop_proc,$(PID_DEMO),Demo 机器服务,$(DEMO_PORT))

# 重启平台：先优雅停止旧进程（优先按 pid 文件；无 pid 文件时按监听端口兜底，
# 最多等待 5 秒，超时 SIGKILL），再重新编译并后台启动
restart: stop start

restart-demo-service: stop-demo-service start-demo-service

status:
	$(call status_proc,$(PID_PLATFORM),平台,$(PLATFORM_HEALTH))
	$(call status_proc,$(PID_DEMO),Demo 机器服务,$(DEMO_HEALTH))

# 创建管理员（示例：make create-admin ADMIN_USERNAME=admin ADMIN_PASSWORD='ChangeMe-Please-1')
create-admin:
	@sh -c 'go run ./cmd/server -create-admin \
		-admin-username "$(ADMIN_USERNAME)" \
		-admin-password "$(ADMIN_PASSWORD)" \
		-admin-display-name "$(ADMIN_DISPLAY_NAME)"'

test:
	go test ./...

race:
	go test -race ./...

# 产物命名规范：agentpermit / agentpermit-demo-machine-service
build:
	mkdir -p bin
	go build -o bin/$(BINARY_PLATFORM) ./cmd/server
	go build -o bin/$(BINARY_DEMO) ./cmd/demo-machine-service

fmt:
	gofmt -w .

vet:
	go vet ./...

clean:
	rm -rf bin
