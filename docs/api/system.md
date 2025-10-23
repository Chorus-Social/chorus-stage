# System & Utility Endpoints

These endpoints provide operational insight and are unauthenticated unless noted.

## GET `/health`

- **Summary:** Simple liveness probe exposed by the FastAPI gateway.
- **Authentication:** None
- **Response — `200 OK`**
  ```json
  { "status": "ok" }
  ```

## GET `/`

- **Summary:** Root metadata describing the API and documentation locations.
- **Authentication:** None
- **Response — `200 OK`**
  ```json
  {
    "name": "Chorus API",
    "version": "1.0.0",
    "description": "Anonymous-by-design social network API",
    "docs": "/docs",
    "redoc": "/redoc"
  }
  ```

## OpenAPI Schema `/openapi.json`

- Machine-readable OpenAPI specification. Useful for code generation or
  documentation systems.

## Interactive Docs `/docs` and `/redoc`

- Swagger UI (`/docs`) and ReDoc (`/redoc`) are enabled by default when the app
  is running. Both reference the live schema at `/openapi.json`.
