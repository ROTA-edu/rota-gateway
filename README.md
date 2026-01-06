# ROTA Gateway

API Gateway for ROTA Education Platform - Authentication, Authorization, Rate Limiting.

## Architecture

```
┌─────────────────────────────────────────┐
│         ROTA Gateway (Go)               │
├─────────────────────────────────────────┤
│  Authentication                         │
│  - Google OAuth 2.0                     │
│  - JWT Issuance & Validation            │
│  - Session Management (Redis)           │
│                                         │
│  Authorization                          │
│  - Role-based access control            │
│  - Resource-level permissions           │
│                                         │
│  Rate Limiting                          │
│  - Per-user limits                      │
│  - Per-endpoint limits                  │
│  - Token bucket algorithm               │
│                                         │
│  Request Routing                        │
│  - Service discovery                    │
│  - Load balancing                       │
│  - Health checks                        │
└─────────────────────────────────────────┘
           │
           ├──► rota-platform (Student)
           ├──► rota-atlas (Teacher)
           ├──► rota-ai-engine
           └──► rota-course-engine
```

## Tech Stack

- **Runtime:** Go 1.25+
- **Router:** Chi (lightweight, idiomatic)
- **Auth:** golang-jwt/jwt
- **Database:** PostgreSQL (user data) + Redis (sessions)
- **Logging:** zerolog (structured)
- **Testing:** testify + httptest
- **Deployment:** Docker + Kubernetes

## Project Structure

```
rota-gateway/
├── cmd/
│   └── server/
│       └── main.go              # Entry point
├── internal/
│   ├── auth/
│   │   ├── google.go            # OAuth implementation
│   │   ├── google_test.go       # OAuth tests
│   │   ├── jwt.go               # JWT utilities
│   │   ├── jwt_test.go          # JWT tests
│   │   └── session.go           # Session management
│   ├── middleware/
│   │   ├── auth.go              # Auth middleware
│   │   ├── ratelimit.go         # Rate limiting
│   │   └── logging.go           # Request logging
│   ├── handler/
│   │   ├── auth.go              # Auth endpoints
│   │   ├── health.go            # Health check
│   │   └── routes.go            # Route setup
│   └── config/
│       └── config.go            # Configuration
├── pkg/
│   ├── proto/                   # Generated from rota-proto
│   └── logger/                  # Logging utilities
├── deployments/
│   └── k8s/                     # Kubernetes manifests
├── tests/
│   ├── integration/             # Integration tests
│   └── e2e/                     # End-to-end tests
├── go.mod
├── go.sum
├── Dockerfile
└── README.md
```

## Development

### Prerequisites

- Go 1.25+
- Docker & Docker Compose
- PostgreSQL 15+
- Redis 7+

### Setup

```bash
# Install dependencies
go mod download

# Run tests (TDD - tests written first!)
go test ./... -v -cover

# Run locally
go run cmd/server/main.go

# Run with Docker Compose
docker-compose up
```

### Environment Variables

```bash
# Auth
GOOGLE_CLIENT_ID=your_client_id
GOOGLE_CLIENT_SECRET=your_client_secret
JWT_SECRET=your_jwt_secret
SESSION_REDIS_URL=redis://localhost:6379

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/rota_gateway

# Server
PORT=8080
ENV=development
```

## Testing

**Target Coverage: 90%+**

```bash
# Run all tests with coverage
go test ./... -coverprofile=coverage.out

# View coverage report
go tool cover -html=coverage.out

# Run specific tests
go test ./internal/auth -v
```

## API Endpoints

### Authentication

```
POST   /auth/google/login         # Initiate OAuth flow
GET    /auth/google/callback      # OAuth callback
POST   /auth/logout               # Invalidate session
GET    /auth/me                   # Get current user
POST   /auth/refresh              # Refresh access token
```

### Health

```
GET    /health                    # Health check
GET    /health/ready              # Readiness probe
GET    /health/live               # Liveness probe
```

### Metrics

```
GET    /metrics                   # Prometheus metrics
```

## Deployment

### Kubernetes

```bash
# Apply manifests
kubectl apply -f deployments/k8s/

# Check status
kubectl get pods -l app=rota-gateway
```

### Docker

```bash
# Build image
docker build -t rota-gateway:latest .

# Run container
docker run -p 8080:8080 \
  -e GOOGLE_CLIENT_ID=$GOOGLE_CLIENT_ID \
  -e JWT_SECRET=$JWT_SECRET \
  rota-gateway:latest
```

## Security

- ✅ OAuth 2.0 with PKCE
- ✅ JWT with RS256 signing
- ✅ HTTPS only (TLS 1.3)
- ✅ Rate limiting per IP and user
- ✅ CORS configured for allowed origins
- ✅ Secrets in environment variables (never hardcoded)
- ✅ SQL injection prevention (parameterized queries)
- ✅ XSS prevention (sanitized inputs)

## License

MIT

---

**Built with ❤️ for ROTA Education**
