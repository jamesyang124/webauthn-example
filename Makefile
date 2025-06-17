.PHONY: help build run docker-build docker-up docker-down docker-restart clean lint test

# Default target
help:
	@echo "Available commands:"
	@echo "  build         				- Build the Go application"
	@echo "  run           				- Run the Go application locally"
	@echo "  docker-build  				- Build Docker image"
	@echo "  docker-up     				- Start docker-compose services"
	@echo "  docker-up-detach     - Start docker-compose services detach mode"
	@echo "  docker-down   				- Stop docker-compose services"
	@echo "  docker-restart				- Restart docker-compose services"
	@echo "  clean         				- Clean build artifacts"
	@echo "  lint          				- Run linter (if available)"
	@echo "  test          				- Run tests"

# Go commands
build:
	go build -o bin/webauthn-example .

run:
	go run .

# Docker commands
docker-build:
	docker-compose build

docker-up:
	docker-compose up

docker-up-detach:
	docker-compose up -d

docker-down:
	docker-compose down

docker-restart: docker-down docker-up

# Development commands
clean:
	rm -rf bin/
	go clean

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed, skipping lint"; \
	fi

test:
	go test ./...