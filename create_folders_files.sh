#!/bin/bash

echo "Creating WAF project folder structure..."

# Create main directories
mkdir -p cmd internal pkg configs scripts docs test docker

# Create subdirectories and files within cmd/
mkdir -p cmd/waf cmd/admin cmd/cli
touch cmd/waf/main.go
touch cmd/admin/main.go
touch cmd/cli/main.go

# Create subdirectories and files within internal/
mkdir -p internal/admin/handlers internal/admin/middleware internal/admin/templates internal/admin/api
mkdir -p internal/core/engine internal/core/rules internal/core/filters internal/core/analyzer
mkdir -p internal/config
touch internal/config/loader.go
touch internal/config/validator.go
touch internal/config/watcher.go
mkdir -p internal/storage/database internal/storage/cache internal/storage/logs
mkdir -p internal/auth/jwt internal/auth/rbac internal/auth/session
mkdir -p internal/monitoring/metrics internal/monitoring/alerts internal/monitoring/health
mkdir -p internal/utils/logger internal/utils/crypto internal/utils/network

# Create subdirectories and files within pkg/
mkdir -p pkg/waf pkg/models pkg/errors

# Create subdirectories and files within configs/
mkdir -p configs/rules
touch configs/waf.yaml
touch configs/rules/sql-injection.yaml
touch configs/rules/xss.yaml
touch configs/rules/csrf.yaml
touch configs/rules/rate-limiting.yaml
touch configs/admin.yaml

# Create files within scripts/
touch scripts/build.sh
touch scripts/deploy.sh
touch scripts/test.sh

# Create subdirectories within docs/
mkdir -p docs/api docs/admin docs/deployment

# Create subdirectories within test/
mkdir -p test/integration test/e2e test/fixtures

# Create subdirectories and files within docker/
touch docker/Dockerfile.waf
touch docker/Dockerfile.admin
touch docker/docker-compose.yml

# Create root files
touch Makefile

echo "WAF project structure created successfully!"

