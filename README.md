# Auth Service

A state-of-the-art FastAPI application designed to provide authentication and authorization services. Built with deployment to Kubernetes in mind.

## 1. Architecture

The application follows a layered architecture:

- `app/`: Main application package
  - `main.py`: FastAPI application entry point
  - `api/`: API routes and endpoints
  - `core/`: Core functionality (config, security, health)

### Features

- FastAPI application with modern Python 3.11+
- JWT Authentication
- Health check endpoints for Kubernetes probes
- Dockerized application with multi-stage builds
- Process management with Gunicorn and Uvicorn

### API Endpoints

- **Authentication**
  - `POST /api/v1/auth/token`: Get access token
  - `GET /api/v1/auth/me`: Get current user info

- **Health Checks**
  - `GET /health`: General health check (used by Docker healthcheck)
  - `GET /readiness`: Kubernetes readiness probe
  - `GET /liveness`: Kubernetes liveness probe

- **API Documentation**
  - `/api/v1/docs`: Swagger UI (interactive API testing)
  - `/api/v1/redoc`: ReDoc (clean documentation reading)

## 2. Development: How to Run and Test

### Quick Start with Docker

```bash
# Start the development server with live code reloading
docker-compose up

# Start in detached mode
docker-compose up -d

# View logs
docker-compose logs -f

# Access API docs at http://localhost:8000/api/v1/docs
```

The development configuration:
- Maps your local code into the container (changes apply instantly)
- Automatically reloads when code changes
- Includes development environment variables

### After Changing Requirements

```bash
# Rebuild and restart the container
docker-compose down
docker-compose build
docker-compose up -d
```

## 3. Production Deployment

### Running in Production-like Mode Locally

```bash
# Run with production configuration
SECRET_KEY=yoursecretkey docker-compose -f docker-compose.prod.yml up

# Run with custom number of workers
GUNICORN_WORKERS=4 SECRET_KEY=yoursecretkey docker-compose -f docker-compose.prod.yml up
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ENVIRONMENT` | Environment name (dev, staging, production) | `dev` |
| `SECRET_KEY` | Secret key for JWT token generation | Random in dev |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Token expiration time | `30` |
| `LOG_LEVEL` | Logging level | `INFO` |
| `CORS_ORIGINS` | CORS allowed origins (comma-separated) | Local URLs |
| `GUNICORN_WORKERS` | Number of Gunicorn workers (production only) | `2` |

### Kubernetes Deployment

The application includes:
- Health check endpoints for liveness and readiness probes
- Resource specification in Docker Compose
- Container optimization for Kubernetes 