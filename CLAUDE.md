# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a WebAuthn example application built with Go backend and React frontend (TypeScript + Vite). The application demonstrates WebAuthn registration and authentication flows with PostgreSQL and Redis for persistence.

## Architecture

### Backend (Go)
- **main.go**: Entry point that initializes logger, database connections, Redis, and starts the FastHTTP server
- **routes.go**: Defines HTTP routes and handlers for WebAuthn endpoints and static file serving
- **handlers/**: Contains WebAuthn registration and authentication handlers
- **internal/**: Core business logic modules:
  - `user/`: User repository and validation logic
  - `session/`: Session management with Redis
  - `util/`: Utility functions for WebAuthn, JSON, base64, and HTTP operations
- **types/**: Type definitions for HTTP responses, persistence, and WebAuthn users
- **middlewares/**: CORS middleware

### Frontend (React + TypeScript)
- **views/**: React application built with Vite
- **src/**: TypeScript source files with WebAuthn client-side implementation

### Database
- **PostgreSQL**: User data with WebAuthn credentials
- **Redis**: Session storage for WebAuthn flows
- **db/**: SQL schema and migration files

## Development Commands

### Backend Development
- `make run` - Run Go application locally
- `make build` - Build Go binary to bin/webauthn-example
- `make test` - Run Go tests
- `make lint` - Run linter (requires golangci-lint)

### Frontend Development
- `cd views && npm run dev` - Start Vite dev server
- `cd views && npm run build` - Build for production
- `cd views && npm run build:watch` - Build with watch mode
- `cd views && npm run lint` - Run ESLint and TypeScript checks

### Docker Operations
- `make docker-up` - Start all services (app, postgres, redis)
- `make docker-down` - Stop all services
- `make docker-restart` - Restart all services
- `make docker-build` - Build Docker images

### Full Development Setup
```bash
# Frontend build (required for backend to serve static files)
cd views
echo "VITE_API_URL=http://localhost:8080" > .env
npm run build:watch

# In another terminal, start containers
make docker-up
```

## Key Implementation Details

### WebAuthn Flow
- Registration: `/webauthn/register/options` → `/webauthn/register/verification`
- Authentication: `/webauthn/authenticate/options` → `/webauthn/authenticate/verification`
- Session data stored in Redis with TTL
- Credentials stored in PostgreSQL users table

### Error Handling
- Centralized error response handling via `types.RespondWithError`
- Structured logging with zap

### Database Schema
- Users table with WebAuthn fields (user_id, credential_id, public_key, sign_count, display_name)
- Uses PostgreSQL with connection pooling

### Code Patterns
- Repository pattern for database operations
- Utility functions with error handling that set HTTP responses
- FastHTTP for high-performance HTTP handling
- Dependency injection via persistence struct

## Environment Variables
Based on `.env` file configuration:

### Go Application Runtime
- `DATABASE_URL`: PostgreSQL connection string used by Go application
- `REDIS_URL`: Redis server address and port used by Go application

### Database Configuration (Docker Compose)
- `PGPORT`: PostgreSQL port (default: 5432)
- `PGPASSWORD`: PostgreSQL password
- `PGHOST`: PostgreSQL host
- `PGUSER`: PostgreSQL username
- `PGDATABASE`: PostgreSQL database name

### Frontend Configuration
- `VITE_API_URL`: Frontend API endpoint configuration (configured in views/.env)

## Testing
Currently no test files exist. When adding tests, follow Go conventions with `*_test.go` files.