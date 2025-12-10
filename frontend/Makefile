# Frontend Makefile for convenience

.PHONY: help dev build clean docker-build docker-run

help:
	@echo "Credo Frontend - Make Commands"
	@echo ""
	@echo "  make dev          - Start development server (Python)"
	@echo "  make dev-node     - Start development server (Node.js)"
	@echo "  make docker-build - Build Docker image"
	@echo "  make docker-run   - Run Docker container"
	@echo "  make clean        - Clean build artifacts"

dev:
	@echo "Starting development server on http://localhost:8000"
	@cd public && python3 -m http.server 8000

dev-node:
	@echo "Starting development server on http://localhost:8000"
	@npx http-server public -p 8000

docker-build:
	@echo "Building frontend Docker image..."
	docker build -t credo-frontend .

docker-run:
	@echo "Running frontend container on http://localhost:3000"
	docker run -p 3000:80 credo-frontend

clean:
	@echo "Cleaning up..."
	@rm -rf node_modules/
	@echo "Done!"
