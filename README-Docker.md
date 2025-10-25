# Chorus Stage Docker Setup

## Overview

This project uses two separate Docker Compose files for clean separation between live and test environments.

## Files

- `docker-compose.live.yml` - Production/live environment
- `docker-compose.test.yml` - Test environment  
- `Dockerfile` - Production-optimized container
- `Dockerfile.dev` - Development container with dev dependencies
- `Makefile` - Easy management commands

## Quick Start

```bash
# Start live environment
make live-up

# Start test environment
make test-up

# Run migrations
make live-migrate
make test-migrate

# View logs
make live-logs
make test-logs

# Development
make dev-up      # Start test environment with dev Dockerfile
make dev-shell   # Open shell in dev container
make dev-down    # Stop dev environment

# Stop environments
make live-down
make test-down
```

## Environment URLs

### Live Environment
- **API**: http://localhost:8000
- **Database**: `chorus_live` (PostgreSQL on port 5432)
- **Redis**: localhost:6379
- **Adminer**: http://localhost:8080
- **Grafana**: http://localhost:3001
- **Prometheus**: http://localhost:9091

### Test Environment  
- **API**: http://localhost:8001
- **Database**: `chorus_testing` (PostgreSQL on port 5433)
- **Redis**: localhost:6380
- **Adminer**: http://localhost:8081
- **Grafana**: http://localhost:3002
- **Prometheus**: http://localhost:9092

## Key Differences

### Live Environment
- **Dockerfile**: Production-optimized
- **Database**: Production credentials
- **PoW**: Higher difficulties (20/15/18/16/18/16)
- **Debug**: Disabled
- **Monitoring**: Full stack (Prometheus + Grafana)

### Test Environment  
- **Dockerfile**: Development (with dev dependencies)
- **Database**: Test credentials
- **PoW**: Lower difficulties (8/2/4/8/10/10) for faster testing
- **Debug**: Enabled
- **Monitoring**: Full stack (Prometheus + Grafana)

## Environment Variables

Both environments use the same `.env` file but with different database configurations:

- **Live**: Uses `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`
- **Test**: Uses `POSTGRES_TEST_USER`, `POSTGRES_TEST_PASSWORD`, `POSTGRES_TEST_DB`

## Clean Architecture

- **Separate networks**: `chorus-network` vs `chorus-test-network`
- **Separate volumes**: `*_live_data` vs `*_test_data`  
- **No conflicts**: Can run both environments simultaneously
- **No USE_TEST_DATABASE**: Each compose file is hardcoded to its specific database
