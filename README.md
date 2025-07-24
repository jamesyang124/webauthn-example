# WebAuthn Example

![Go](https://img.shields.io/badge/go-%2300ADD8.svg?style=for-the-badge&logo=go&logoColor=white)
![React](https://img.shields.io/badge/react-%2320232a.svg?style=for-the-badge&logo=react&logoColor=%2361DAFB)
![TypeScript](https://img.shields.io/badge/typescript-%23007ACC.svg?style=for-the-badge&logo=typescript&logoColor=white)
![Postgres](https://img.shields.io/badge/postgres-%23316192.svg?style=for-the-badge&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/redis-%23DD0031.svg?style=for-the-badge&logo=redis&logoColor=white)

A WebAuthn passwordless authentication demo built with Go backend and React frontend. Features functional programming patterns with try monads for robust error handling.

**Stack**: Go + FastHTTP, React + TypeScript + Vite, PostgreSQL, Redis

## Getting Started

```sh
# 1. Copy environment configuration  
cp .env.example .env

# 2. Start all services with hot reload
docker-compose up --watch
```

**Access:**
- Frontend: `http://localhost:5173` (Vite dev server with hot reload)
- Backend API: `http://localhost:8080` (Go with hot reload)
- Database: `localhost:5555` (PostgreSQL)

**Hot Reload:** Both frontend and backend automatically reload on file changes.

### Environment Variables

Copy `.env.example` to `.env` and adjust values as needed:
```sh
cp .env.example .env
```

**Note**: Remove `user: 501:501` in docker-compose.yml if using mount volumes.

## Architecture

**Functional Programming Approach**: Uses IBM/fp-go inspired try monad pattern for clean error handling and functional composition.

**Key Features**:
- Custom try monad implementation in `types/try_monad.go`
- Centralized error system in `internal/weberror/`
- Functional composition in handlers and utilities
- Clean separation between business logic and HTTP concerns

**Development Commands**:
- `make run` - Run Go app locally
- `make build` - Build binary
- `make docker-up` - Start all services
- `cd views && npm run dev` - Frontend dev server

## TODOs

- UI and persist display name
- persist credentials table for 1 to many relationship with user table.

## Reference
- https://www.corbado.com/blog/webauthn-user-id-userhandle#webauthn-credential-id
- https://www.corbado.com/blog/passkey-webauthn-database-guide
