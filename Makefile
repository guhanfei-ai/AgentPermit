# 加载 .env（若存在）。Go 程序本身不读取 .env，由这里的 shell 完成注入。
ENV_FILE := $(wildcard .env)
LOAD_ENV := set -a; [ -f .env ] && . ./.env; set +a

BINARY_PLATFORM := agentpermit
BINARY_DEMO := agentpermit-demo-machine-service

.PHONY: run run-demo-service test race build fmt vet clean create-admin

# 启动平台（127.0.0.1:8080）
run:
	@sh -c '$(LOAD_ENV); exec go run ./cmd/server'

# 启动独立 Demo 机器服务（127.0.0.1:9090），需要先设置 AGENTPERMIT_SERVICE_TOKEN
run-demo-service:
	@sh -c '$(LOAD_ENV); exec go run ./cmd/demo-machine-service'

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
