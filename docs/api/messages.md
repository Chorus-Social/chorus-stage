# Direct Messaging Endpoints

Messages are stored as opaque ciphertext blobs after clients perform proof-of-work.
All messaging endpoints require bearer authentication.

## POST `/api/v1/messages`

- **Summary:** Submit an end-to-end encrypted direct message.
- **Authentication:** Required
- **Status Codes:** `201 Created`, `400 Bad Request`, `401 Unauthorized`,
  `404 Not Found`, `429 Too Many Requests`

### Request Body
```json
{
  "ciphertext": "BASE64_ENCRYPTED_PAYLOAD",
  "recipient_pubkey_hex": "HEX_ED25519_PUBLIC_KEY",
  "header_blob": "BASE64_OPTIONAL_HEADER",
  "pow_nonce": "3f0a…"
}
```

| Field | Type | Notes |
|-------|------|-------|
| `ciphertext` | string | Base64-encoded ciphertext. For sealed box encryption, the raw bytes are stored verbatim. |
| `recipient_pubkey_hex` | string | Hex-encoded Ed25519 public key for the intended recipient. |
| `header_blob` | string | Optional base64 metadata (e.g. encrypted headers). |
| `pow_nonce` | string | Nonce satisfying message PoW difficulty. |

### Successful Response — `201 Created`
```json
{
  "status": "message_sent",
  "message_id": 15
}
```

### Error Responses

| Status | Description |
|--------|-------------|
| `400 Bad Request` | Invalid recipient key or ciphertext not valid base64. |
| `401 Unauthorized` | Missing or invalid bearer token. |
| `404 Not Found` | Recipient not found. |
| `429 Too Many Requests` | PoW nonce replay detected. |

## GET `/api/v1/messages/inbox`

- **Summary:** Retrieve encrypted messages addressed to the caller.
- **Authentication:** Required
- **Query Parameters:** `limit` (default `50`, max `100`), `before` (integer)
- **Response:** `200 OK` with an array of message objects:

```json
{
  "id": 15,
  "order_index": 12345,
  "sender_user_id": "URL_SAFE_B64",
  "recipient_user_id": "URL_SAFE_B64",
  "ciphertext": "BASE64_ENCRYPTED_PAYLOAD",
  "header_blob": null,
  "delivered": false
}
```

## GET `/api/v1/messages/sent`

- **Summary:** Fetch messages sent by the caller.
- **Authentication:** Required
- **Query Parameters:** Same as inbox.
- **Response:** `200 OK` with array of message objects.

## PUT `/api/v1/messages/{message_id}/read`

- **Summary:** Mark a message as delivered/read.
- **Authentication:** Required
- **Status Codes:** `200 OK`, `401 Unauthorized`, `404 Not Found`
- **Response:**
```json
{ "status": "marked_as_read" }
```

## Encryption Guidance

- Recipients expect ciphertext to be base64 encoded. Internally the server
  stores raw bytes; it does **not** attempt decryption.
- A common pattern is to convert Ed25519 keys to Curve25519 and use NaCl sealed
  boxes. In Python (`nacl` package):

```python
from nacl.bindings import crypto_sign_ed25519_pk_to_curve25519
from nacl.public import PublicKey, SealedBox
import base64

recipient_curve = PublicKey(crypto_sign_ed25519_pk_to_curve25519(bytes.fromhex(pubkey_hex)))
sealed = SealedBox(recipient_curve)
ciphertext = base64.b64encode(sealed.encrypt(plaintext)).decode()
```

Remember to manage keys securely; the backend only stores hashes of public keys
and never decrypts payloads.
