# Contributing to Chorus Stage

Thanks for your interest in contributing! This project is early but growing.

## Getting Started

1. Fork and clone the repository.
2. Install dependencies via Poetry: `poetry install`.
3. Run the alpha check: `make alpha-check`.
4. Start services: `docker compose up -d` and `make dev`.

## Development Guidelines

- Keep changes focused and minimal; include tests when practical.
- Follow existing code style and structure; prefer FastAPI dependency injection
  patterns and service modules for cross‑cutting logic.
- Document new endpoints or settings in `docs/` and link from `README.md`.

## Security

Please do not open public issues for security vulnerabilities. Instead, email
the maintainer listed in `README.md` to coordinate a private disclosure.

## Ways to Help

- Improve documentation (API edge cases, examples, diagrams).
- Add tests for replay protection, PoW leases, and error handling.
- Build reference clients implementing the E2E messaging expectations.
- Triage issues and propose fixes.

## Code of Conduct

Be kind, inclusive, and assume good intent. We aim to keep discussions focused
on technical merit and user safety.

