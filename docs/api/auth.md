# Authentication Endpoints

The authentication flow validates an Ed25519 keypair via proof-of-work (PoW) and
signature challenges, then issues JWT bearer tokens for subsequent requests.

All payloads use the following shared schemas:

| Field | Type | Description |
|-------|------|-------------|
| `pow` | object | Proof-of-work envelope with `nonce`, `difficulty`, and `target`. |
| `proof` | object | Signature proof containing the issued `challenge` (base64) and the client-generated `signature` (base64). |

## POST `/api/v1/auth/challenge`

- **Summary:** Issue PoW and signature material for either registration or login.
- **Authentication:** None

### Request Body
```json
{
  "pubkey": "BASE64_ED25519_PUBLIC_KEY",
  "intent": "register"
}
```

| Field | Type | Notes |
|-------|------|-------|
| `pubkey` | string | URL-safe base64 encoded Ed25519 public key (32 bytes). |
| `intent` | string | `"register"` or `"login"`. |

### Successful Response — `200 OK`
```json
{
  "pow_target": "1d31a5…",
  "pow_difficulty": 10,
  "signature_challenge": "3hJa…"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `pow_target` | string | Hexadecimal target used when solving PoW. |
| `pow_difficulty` | integer | Minimum leading-zero difficulty required for the supplied target. |
| `signature_challenge` | string | Base64 challenge to be signed with the private key. |

## POST `/api/v1/auth/register`

- **Summary:** Register a new anonymous identity.
- **Authentication:** None
- **Status Codes:** `201 Created`, `400 Bad Request`, `401 Unauthorized`

### Request Body
```json
{
  "pubkey": "BASE64_ED25519_PUBLIC_KEY",
  "display_name": "Optional alias",
  "accent_color": "#ffaa33",
  "pow": {
    "nonce": "a1b2c3…",
    "difficulty": 10,
    "target": "1d31a5…"
  },
  "proof": {
    "challenge": "3hJa…",
    "signature": "Xh8f…"
  }
}
```

### Successful Response — `201 Created`
```json
{
  "user_id": "URL_SAFE_BASE64_HASH",
  "created": true
}
```

| Field | Type | Description |
|-------|------|-------------|
| `user_id` | string | URL-safe base64 representation of the BLAKE3 hash of the public key. |
| `created` | boolean | `true` if a new record was inserted; `false` if the key already existed and profile fields were updated. |

## POST `/api/v1/auth/login`

- **Summary:** Exchange a valid challenge response for a JWT token.
- **Authentication:** None
- **Status Codes:** `200 OK`, `400 Bad Request`, `401 Unauthorized`, `404 Not Found`

### Request Body
```json
{
  "pubkey": "BASE64_ED25519_PUBLIC_KEY",
  "pow": {
    "nonce": "7410…",
    "difficulty": 6,
    "target": "4e8bc…"
  },
  "proof": {
    "challenge": "IhPs…",
    "signature": "6YpS…"
  }
}
```

### Successful Response — `200 OK`
```json
{
  "access_token": "JWT_STRING",
  "token_type": "bearer",
  "session_nonce": "client-session-nonce"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `access_token` | string | Signed JWT containing the `sub` claim set to the user hash. |
| `token_type` | string | Always `"bearer"`. |
| `session_nonce` | string | Server-generated nonce clients can bind to the session. |

### Error Responses

| Status | Description |
|--------|-------------|
| `400 Bad Request` | Malformed payload, insufficient PoW, or invalid signature. |
| `401 Unauthorized` | Signature does not match the provided public key. |
| `404 Not Found` | Login attempted for a non-existent user. |

