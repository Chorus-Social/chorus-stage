# Chorus Stage

**Anonymous-by-design social network backend**

Chorus Stage is the user-facing server component of the Chorus Network, providing a FastAPI-based REST API for anonymous social networking with cryptographic authentication, proof-of-work requirements, and federation capabilities.

## 🏗️ Architecture

Chorus Stage operates as **Layer 3** in the Chorus Network architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                    Chorus Network                          │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Clients (Web, Mobile, Desktop)                   │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Stage (User-facing servers) ← THIS COMPONENT     │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Bridge (Federation & Replication)                │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Conductor (Consensus & Time)                    │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Features

### **Core Functionality**
- **Anonymous Authentication** - Ed25519 public-key cryptography (no usernames/passwords)
- **Proof-of-Work** - Cryptographic challenges to prevent spam and Sybil attacks
- **Privacy-First Design** - No real-world timestamps, only day numbers and order IDs
- **Federation Ready** - Integrates with Chorus Bridge for network-wide replication
- **End-to-End Encryption** - Direct messages encrypted client-side with NaCl

### **API Capabilities**
- **Posts & Communities** - Create, view, and moderate content
- **Voting System** - Upvote/downvote posts with cryptographic verification
- **Direct Messages** - Encrypted private messaging between users
- **Moderation** - Community-driven content moderation with transparency
- **User Management** - Account creation, tier-based access controls

### **Technical Features**
- **FastAPI Framework** - High-performance async Python web server
- **PostgreSQL Database** - Robust data storage with migrations
- **Redis Caching** - Session management and rate limiting
- **Docker Support** - Containerized deployment with separate test/live environments
- **Comprehensive Testing** - Unit, integration, and end-to-end tests

## 🛠️ Quick Start

### **Prerequisites**
- Python 3.11+
- PostgreSQL 13+
- Redis 6+
- Docker & Docker Compose (optional)

### **Installation**

1. **Clone the repository**
   ```bash
   git clone https://github.com/Chorus-Social/chorus-stage.git
   cd chorus-stage
   ```

2. **Install dependencies**
   ```bash
   poetry install
   ```

3. **Set up environment**
   ```bash
   cp .env.example .env
   # Edit .env with your database and Redis configuration
   ```

4. **Run database migrations**
   ```bash
   poetry run alembic upgrade head
   ```

5. **Start the server**
   ```bash
   poetry run uvicorn src.chorus_stage.main:app --reload
   ```

### **Docker Setup**

For easier deployment, use Docker Compose:

```bash
# Start live environment
make live-up

# Start test environment  
make test-up

# View logs
make live-logs
```

## 📡 API Documentation

### **Base URLs**
- **Development**: `http://localhost:8000`
- **API Docs**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

### **Key Endpoints**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/auth/challenge` | POST | Request cryptographic challenge |
| `/api/v1/auth/login` | POST | Authenticate with signature |
| `/api/v1/posts` | GET/POST | List/create posts |
| `/api/v1/votes` | POST | Vote on posts |
| `/api/v1/messages` | GET/POST | Send/receive messages |
| `/api/v1/communities` | GET | List communities |
| `/api/v1/moderation` | GET/POST | Moderation queue/actions |
| `/api/v1/system/config` | GET | Public configuration |

### **Authentication Flow**

1. **Generate Ed25519 keypair** (client-side)
2. **Request challenge** via `/auth/challenge`
3. **Sign challenge** with private key
4. **Submit signature** via `/auth/login`
5. **Receive JWT token** for authenticated requests

## 🔧 Configuration

### **Environment Variables**

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `REDIS_URL` | Redis connection string | Required |
| `JWT_SECRET_KEY` | JWT signing secret | Required |
| `BRIDGE_BASE_URL` | Chorus Bridge endpoint | Optional |
| `DEBUG` | Enable debug mode | `false` |
| `CORS_ORIGINS` | Allowed CORS origins | `["*"]` |

### **PoW Configuration**

Proof-of-work difficulties can be configured per action type:

```python
POW_DIFFICULTIES = {
    "register": 20,      # User registration
    "post": 15,          # Creating posts
    "vote": 18,          # Voting on posts
    "message": 16,       # Sending messages
    "moderation": 18,    # Moderation actions
    "community": 16      # Community creation
}
```

## 🧪 Testing

### **Run Tests**
```bash
# All tests
poetry run pytest

# Specific test categories
poetry run pytest tests/v1/test_auth.py
poetry run pytest tests/v1/test_posts.py
poetry run pytest tests/services/

# With coverage
poetry run pytest --cov=src/chorus_stage
```

### **Test Environment**
```bash
# Start test database
make test-up

# Run tests against test environment
poetry run pytest

# Clean up
make test-down
```

## 🚀 Deployment

### **Production Deployment**

1. **Set up PostgreSQL and Redis**
2. **Configure environment variables**
3. **Run database migrations**
4. **Deploy with Docker or directly**

```bash
# Using Docker
docker-compose -f docker-compose.live.yml up -d

# Or directly with uvicorn
poetry run uvicorn src.chorus_stage.main:app --host 0.0.0.0 --port 8000
```

### **Monitoring**

The application includes built-in monitoring endpoints:

- **Health Check**: `GET /health`
- **System Config**: `GET /api/v1/system/config`
- **Bridge Status**: `GET /api/v1/system/bridge/health`
- **Metrics**: Prometheus metrics available at `/metrics`

## 🔗 Federation

Chorus Stage integrates with the broader Chorus Network through:

- **Chorus Bridge** - Handles federation and replication
- **Chorus Conductor** - Provides consensus and day proofs
- **Event Synchronization** - Automatic sync of posts, votes, and messages

When Bridge integration is enabled, Stage automatically:
- Submits new user actions to Bridge for federation
- Receives and applies federated events from other Stage instances
- Maintains synchronization with the network

## 📚 Documentation

- **[API Reference](docs/Stage-API-Reference.md)** - Complete API documentation
- **[Architecture Overview](docs/Chorus-Architecture.md)** - System architecture
- **[Development Setup](docs/Development-Setup.md)** - Development environment
- **[Deployment Guide](docs/Deployment-Guide.md)** - Production deployment
- **[Security Guide](docs/Security-Guide.md)** - Security considerations

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

### **Development Guidelines**

- Follow the existing code style
- Add type hints for all functions
- Include docstrings for public APIs
- Write tests for new features
- Update documentation as needed

## 📄 License

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: Report bugs and request features on GitHub
- **Discussions**: Ask questions in GitHub Discussions
- **Documentation**: Check the docs/ directory for detailed guides

---

**Chorus Stage** - Building the future of anonymous social networking through cryptography and federation.
