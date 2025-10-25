# Chorus Stage - API Reference

## 📚 **API Overview**

The Chorus Stage API provides a comprehensive REST API for anonymous social networking with cryptographic authentication, proof-of-work requirements, and federation capabilities. This document provides complete API reference with examples and detailed specifications.

## 🔗 **Base URL**

```
Production: https://stage.chorus.network/api/v1
Development: http://localhost:8000/api/v1
```

## 🔐 **Authentication**

### **JWT Authentication**

Most API endpoints require JWT authentication using the `Authorization` header:

```http
Authorization: Bearer <jwt_token>
```

### **JWT Token Structure**

```json
{
  "sub": "base64_encoded_user_id",
  "iat": 1640995200,
  "exp": 1640998800
}
```

### **Token Generation**

JWT tokens are obtained through the `/auth/login` endpoint after successful authentication with Ed25519 key signatures and proof-of-work.

## 📡 **API Endpoints**

### **Authentication Endpoints**

#### **POST /auth/challenge**

Request a cryptographic challenge for login/registration.

**Request:**
```json
{
  "pubkey": "base64_encoded_ed25519_public_key",
  "intent": "register" | "login"
}
```

**Response:**
```json
{
  "pow_target": "challenge_identifier",
  "pow_difficulty": 15,
  "signature_challenge": "base64_encoded_challenge"
}
```

**Status Codes:**
- `200 OK` - Challenge issued successfully
- `400 Bad Request` - Invalid public key format

#### **POST /auth/register**

Register a new anonymous identity with proof-of-work and signature verification.

**Request:**
```json
{
  "pubkey": "base64_encoded_ed25519_public_key",
  "display_name": "Optional persona name",
  "accent_color": "#FF5733",
  "pow": {
    "nonce": "proof_of_work_nonce",
    "difficulty": 15,
    "target": "challenge_identifier"
  },
  "proof": {
    "challenge": "base64_encoded_challenge",
    "signature": "base64_encoded_signature"
  }
}
```

**Response:**
```json
{
  "user_id": "base64_encoded_user_id",
  "created": true
}
```

**Status Codes:**
- `201 Created` - Registration successful
- `400 Bad Request` - Invalid proof-of-work or signature
- `429 Too Many Requests` - Proof-of-work nonce already used

#### **POST /auth/login**

Authenticate with existing Ed25519 key.

**Request:**
```json
{
  "pubkey": "base64_encoded_ed25519_public_key",
  "pow": {
    "nonce": "proof_of_work_nonce",
    "difficulty": 10,
    "target": "challenge_identifier"
  },
  "proof": {
    "challenge": "base64_encoded_challenge",
    "signature": "base64_encoded_signature"
  }
}
```

**Response:**
```json
{
  "access_token": "jwt_token",
  "token_type": "bearer",
  "session_nonce": "ephemeral_nonce"
}
```

**Status Codes:**
- `200 OK` - Login successful
- `401 Unauthorized` - Invalid signature or user not found
- `429 Too Many Requests` - Proof-of-work nonce already used

### **Post Endpoints**

#### **GET /posts/**

List posts in deterministic order with optional filters.

**Query Parameters:**
- `limit` (int, optional): Maximum number of posts (default: 50, max: 100)
- `before` (int, optional): Return posts before this order_index
- `community_slug` (str, optional): Filter by community slug

**Response:**
```json
[
  {
    "id": 123,
    "order_index": 456,
    "author_user_id": "base64_encoded_user_id",
    "author_pubkey": "hex_encoded_public_key",
    "parent_post_id": null,
    "community_id": 1,
    "body_md": "# Hello World",
    "content_hash": "hex_encoded_hash",
    "moderation_state": 0,
    "harmful_vote_count": 0,
    "upvotes": 5,
    "downvotes": 1,
    "deleted": false,
    "federation_post_id": "hex_encoded_id",
    "federation_origin": "stage-001"
  }
]
```

#### **GET /posts/{post_id}**

Get a specific post by ID.

**Response:**
```json
{
  "id": 123,
  "order_index": 456,
  "author_user_id": "base64_encoded_user_id",
  "author_pubkey": "hex_encoded_public_key",
  "parent_post_id": null,
  "community_id": 1,
  "body_md": "# Hello World",
  "content_hash": "hex_encoded_hash",
  "moderation_state": 0,
  "harmful_vote_count": 0,
  "upvotes": 5,
  "downvotes": 1,
  "deleted": false,
  "federation_post_id": "hex_encoded_id",
  "federation_origin": "stage-001"
}
```

#### **GET /posts/{post_id}/children**

Get replies to a post in deterministic order.

**Query Parameters:**
- `limit` (int, optional): Maximum number of replies (default: 50, max: 100)
- `before` (int, optional): Return replies before this order_index

**Response:** Array of Post objects (same format as above)

#### **POST /posts/**

Create a new post with proof-of-work verification.

**Headers:**
```http
Authorization: Bearer <jwt_token>
```

**Request:**
```json
{
  "content_md": "# Hello World",
  "parent_post_id": null,
  "community_internal_slug": "general",
  "pow_nonce": "proof_of_work_nonce",
  "pow_difficulty": 15,
  "content_hash": "hex_encoded_sha256_hash"
}
```

**Response:**
```json
{
  "id": 123,
  "order_index": 456,
  "author_user_id": "base64_encoded_user_id",
  "author_pubkey": "hex_encoded_public_key",
  "parent_post_id": null,
  "community_id": 1,
  "body_md": "# Hello World",
  "content_hash": "hex_encoded_hash",
  "moderation_state": 0,
  "harmful_vote_count": 0,
  "upvotes": 0,
  "downvotes": 0,
  "deleted": false,
  "federation_post_id": "hex_encoded_id",
  "federation_origin": "stage-001"
}
```

**Status Codes:**
- `201 Created` - Post created successfully
- `400 Bad Request` - Invalid proof-of-work or content hash
- `401 Unauthorized` - Invalid or missing JWT token
- `404 Not Found` - Parent post or community not found
- `429 Too Many Requests` - Proof-of-work nonce already used

#### **DELETE /posts/{post_id}**

Soft-delete a post (visible to author only).

**Headers:**
```http
Authorization: Bearer <jwt_token>
```

**Response:**
- `204 No Content` - Post deleted successfully
- `403 Forbidden` - Can only delete your own posts
- `404 Not Found` - Post not found

### **Community Endpoints**

#### **GET /communities/**

List all communities.

**Response:**
```json
[
  {
    "id": 1,
    "internal_slug": "general",
    "display_name": "General Discussion",
    "description_md": "Welcome to the general discussion community",
    "is_profile_like": false,
    "order_index": 1
  }
]
```

#### **GET /communities/{community_id}**

Get a specific community by ID.

**Response:**
```json
{
  "id": 1,
  "internal_slug": "general",
  "display_name": "General Discussion",
  "description_md": "Welcome to the general discussion community",
  "is_profile_like": false,
  "order_index": 1
}
```

#### **POST /communities/**

Create a new community.

**Headers:**
```http
Authorization: Bearer <jwt_token>
```

**Request:**
```json
{
  "internal_slug": "tech",
  "display_name": "Technology",
  "description_md": "Technology discussions and news"
}
```

**Response:**
```json
{
  "id": 2,
  "internal_slug": "tech",
  "display_name": "Technology",
  "description_md": "Technology discussions and news",
  "is_profile_like": false,
  "order_index": 2
}
```

#### **POST /communities/{community_id}/join**

Join a community.

**Headers:**
```http
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "status": "joined"
}
```

#### **DELETE /communities/{community_id}/leave**

Leave a community.

**Headers:**
```http
Authorization: Bearer <jwt_token>
```

**Response:**
- `204 No Content` - Successfully left community

#### **GET /communities/{community_id}/posts**

Get posts from a specific community.

**Query Parameters:**
- `limit` (int, optional): Maximum number of posts (default: 50)
- `before` (int, optional): Return posts before this order_index

**Response:** Array of Post objects

#### **GET /communities/{community_id}/top-authors**

Get top authors in a community by selected metric.

**Query Parameters:**
- `limit` (int, optional): Maximum number of authors (default: 10)
- `metric` (str, optional): "posts", "engagement", or "harmful_ratio" (default: "posts")

**Response:**
```json
[
  {
    "author_user_id": "base64_encoded_user_id",
    "posts": 25,
    "upvotes": 150,
    "downvotes": 10,
    "harmful_ratio": 0.0625
  }
]
```

### **Direct Message Endpoints**

#### **POST /messages/**

Send an end-to-end encrypted direct message.

**Headers:**
```http
Authorization: Bearer <jwt_token>
```

**Request:**
```json
{
  "recipient_pubkey_hex": "hex_encoded_recipient_public_key",
  "ciphertext": "base64_encoded_encrypted_message",
  "header_blob": "base64_encoded_encryption_header",
  "pow_nonce": "proof_of_work_nonce"
}
```

**Response:**
```json
{
  "status": "message_sent",
  "message_id": 123
}
```

#### **GET /messages/inbox**

Get encrypted messages for current user (as recipient).

**Headers:**
```http
Authorization: Bearer <jwt_token>
```

**Query Parameters:**
- `limit` (int, optional): Maximum number of messages (default: 50, max: 100)
- `before` (int, optional): Return messages before this order_index

**Response:**
```json
[
  {
    "id": 123,
    "order_index": 456,
    "sender_user_id": "base64_encoded_sender_id",
    "recipient_user_id": "base64_encoded_recipient_id",
    "ciphertext": "base64_encoded_encrypted_message",
    "header_blob": "base64_encoded_encryption_header",
    "delivered": false
  }
]
```

#### **GET /messages/sent**

Get encrypted messages sent by current user.

**Headers:**
```http
Authorization: Bearer <jwt_token>
```

**Query Parameters:**
- `limit` (int, optional): Maximum number of messages (default: 50, max: 100)
- `before` (int, optional): Return messages before this order_index

**Response:** Array of message objects (same format as inbox)

#### **PUT /messages/{message_id}/read**

Mark a direct message as read/delivered.

**Headers:**
```http
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "status": "marked_as_read"
}
```

### **Voting Endpoints**

#### **POST /votes/**

Cast a vote on a post with proof-of-work verification.

**Headers:**
```http
Authorization: Bearer <jwt_token>
```

**Request:**
```json
{
  "post_id": 123,
  "direction": 1,
  "pow_nonce": "proof_of_work_nonce",
  "client_nonce": "client_generated_nonce"
}
```

**Response:**
```json
{
  "status": "success"
}
```

**Status Codes:**
- `201 Created` - Vote recorded successfully
- `400 Bad Request` - Invalid proof-of-work
- `404 Not Found` - Post not found
- `429 Too Many Requests` - Vote already processed or cooldown active

#### **GET /votes/{post_id}/my-vote**

Get current user's vote on a specific post.

**Headers:**
```http
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "direction": 1
}
```

### **Moderation Endpoints**

#### **GET /moderation/queue**

Get posts currently in the moderation queue.

**Query Parameters:**
- `limit` (int, optional): Maximum number of posts (default: 50, max: 100)
- `before` (int, optional): Return posts before this order_index

**Response:** Array of Post objects

#### **POST /moderation/trigger**

Trigger moderation for a post using a moderation token.

**Headers:**
```http
Authorization: Bearer <jwt_token>
```

**Request:**
```json
{
  "post_id": 123
}
```

**Response:**
```json
{
  "status": "moderation_triggered",
  "case_id": 123
}
```

#### **POST /moderation/vote**

Vote on whether a post is harmful.

**Headers:**
```http
Authorization: Bearer <jwt_token>
```

**Query Parameters:**
- `is_harmful` (bool, required): Whether the post is considered harmful

**Response:**
```json
{
  "status": "vote_recorded"
}
```

#### **GET /moderation/history**

Get moderation history for posts authored by the current user.

**Headers:**
```http
Authorization: Bearer <jwt_token>
```

**Query Parameters:**
- `limit` (int, optional): Maximum number of cases (default: 50, max: 100)
- `before` (int, optional): Return cases before this order_index

**Response:**
```json
[
  {
    "post_id": 123,
    "state": 1,
    "opened_order_index": 456
  }
]
```

#### **GET /moderation/community/{internal_slug}/stats**

Get aggregated moderation stats for a community.

**Response:**
```json
{
  "community_id": 1,
  "internal_slug": "general",
  "cases": {
    "total": 25,
    "open": 5,
    "cleared": 15,
    "hidden": 5
  },
  "votes": {
    "harmful": 30,
    "not_harmful": 45
  },
  "top_flagged_posts": [
    {
      "post_id": 123,
      "harmful_vote_count": 8,
      "moderation_state": 1
    }
  ]
}
```

#### **GET /moderation/ledger**

Get public anonymized ledger of moderation activity.

**Query Parameters:**
- `limit` (int, optional): Maximum number of events (default: 50, max: 200)
- `before` (int, optional): Return events before this order_index

**Response:**
```json
[
  {
    "type": "case_opened",
    "post_id": 123,
    "community_id": 1,
    "order_index": 456
  }
]
```

### **System Endpoints**

#### **GET /system/config**

Get public runtime configuration.

**Response:**
```json
{
  "app": {
    "name": "Chorus Stage",
    "version": "1.0.0",
    "jwt_algorithm": "HS256",
    "access_token_expire_minutes": 60,
    "debug": false
  },
  "pow": {
    "difficulties": {
      "register": 15,
      "login": 10,
      "post": 15,
      "vote": 8,
      "message": 12
    },
    "challenge_window_seconds": 300,
    "leases": {
      "enabled": true,
      "seconds": 3600,
      "actions": ["post", "vote"]
    }
  },
  "moderation": {
    "thresholds": {
      "harmful_votes": 5,
      "clear_votes": 3
    },
    "min_community_size": 10,
    "cooldowns": {
      "harmful_vote_author_seconds": 3600,
      "harmful_vote_post_seconds": 1800,
      "trigger_seconds": 300
    }
  },
  "bridge": {
    "enabled": true,
    "instance_id": "stage-001",
    "base_url": "https://bridge.chorus.network"
  }
}
```

#### **GET /system/clock**

Get the monotonic system clock for transparency.

**Response:**
```json
{
  "day_seq": 1234,
  "hour_seq": 5678
}
```

#### **GET /system/health**

Get comprehensive health check for monitoring.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": 1640995200,
  "components": {
    "database": "healthy",
    "bridge": "healthy"
  },
  "version": "1.0.0",
  "instance_id": "stage-001"
}
```

#### **GET /system/metrics**

Get comprehensive system metrics.

**Response:**
```json
{
  "timestamp": 1640995200,
  "database": {
    "healthy": true,
    "status": "connected"
  },
  "activity": {
    "users": 1250,
    "posts": 5670,
    "votes": 12340,
    "messages": 890,
    "communities": 25
  },
  "moderation": {
    "total_cases": 45,
    "open_cases": 8
  },
  "bridge": {
    "enabled": true,
    "status": "connected"
  }
}
```

### **User Transparency Endpoints**

#### **GET /users/me/profile**

Get current user's profile information.

**Authentication:** Required (JWT Bearer token)

**Response:**
```json
{
  "display_name": "Anonymous User",
  "accent_color": "#FF5733"
}
```

#### **PATCH /users/me/profile**

Update current user's profile information.

**Authentication:** Required (JWT Bearer token)

**Request:**
```json
{
  "display_name": "New Display Name",
  "accent_color": "#00FF00"
}
```

**Request Fields:**
- `display_name` (string, optional): User's display name (1-100 characters)
- `accent_color` (string, optional): Hex color code (e.g., #FF5733)

**Response:**
```json
{
  "display_name": "New Display Name",
  "accent_color": "#00FF00"
}
```

**Notes:**
- Both fields are optional - only provided fields will be updated
- Display name must be 1-100 characters long
- Accent color must be a valid hex color code (#RRGGBB format)
- No proof-of-work required for profile updates

#### **GET /users/{user_id}/summary**

Get anonymized overview of a user's activity.

**Response:**
```json
{
  "user_id": "base64_encoded_user_id",
  "profile": {
    "display_name": "Anonymous User",
    "accent_color": "#FF5733"
  },
  "posts": {
    "total": 25,
    "comments": 10
  },
  "votes_cast": {
    "up": 150,
    "down": 5
  },
  "moderation": {
    "votes": {
      "harmful": 3,
      "not_harmful": 12
    },
    "triggers": 1,
    "tokens_remaining": 4
  },
  "communities": {
    "count": 3
  }
}
```

#### **GET /users/{user_id}/recent-posts**

Get recent posts authored by the user (anonymized fields only).

**Query Parameters:**
- `limit` (int, optional): Maximum number of posts (default: 20, max: 100)
- `before` (int, optional): Return posts before this order_index

**Response:**
```json
[
  {
    "id": 123,
    "order_index": 456,
    "community_id": 1,
    "moderation_state": 0,
    "upvotes": 5,
    "downvotes": 1
  }
]
```

#### **GET /users/{user_id}/communities**

Get communities a user has posted in with post counts.

**Response:**
```json
[
  {
    "community_id": 1,
    "internal_slug": "general",
    "posts": 15
  }
]
```

## 🔒 **Security Features**

### **Proof-of-Work Requirements**

All major operations require proof-of-work to prevent spam:

- **Registration**: Difficulty 15 (configurable)
- **Login**: Difficulty 10 (configurable)
- **Posts**: Difficulty 15 (configurable)
- **Votes**: Difficulty 8 (configurable)
- **Messages**: Difficulty 12 (configurable)

### **Replay Protection**

- Proof-of-work nonces can only be used once
- Client nonces prevent duplicate requests
- Cooldown periods for harmful votes and moderation triggers

### **Cryptographic Authentication**

- Ed25519 public key authentication
- JWT tokens for session management
- End-to-end encrypted direct messages

## 📊 **Response Format Guidelines**

### **Success Responses**

- **200 OK**: Successful GET requests
- **201 Created**: Successful POST requests that create resources
- **204 No Content**: Successful DELETE requests

### **Error Responses**

All errors follow this format:

```json
{
  "detail": "Error description"
}
```

**Common Status Codes:**
- **400 Bad Request**: Invalid request data or proof-of-work
- **401 Unauthorized**: Invalid or missing authentication
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource not found
- **409 Conflict**: Resource already exists or conflict
- **429 Too Many Requests**: Rate limit exceeded or cooldown active
- **503 Service Unavailable**: Bridge service unavailable

### **Pagination**

Many endpoints support pagination using:
- `limit`: Maximum number of items (default varies by endpoint)
- `before`: Return items before this order_index

### **Data Encoding**

- **User IDs**: Base64 URL-safe encoded BLAKE3 hashes
- **Public Keys**: Hex-encoded Ed25519 keys
- **Content Hashes**: Hex-encoded SHA-256 hashes
- **Binary Data**: Base64 encoded

## 🔄 **Federation**

When bridge integration is enabled, many operations are automatically federated to other Stage instances:

- User registrations
- Post announcements
- Vote events
- Moderation triggers and votes
- Community operations
- Direct message events

Federation uses protobuf envelopes with cryptographic signatures for authenticity and integrity.

## 📝 **Example Usage**

### **Complete Registration Flow**

1. **Get Challenge**:
```bash
curl -X POST "https://stage.chorus.network/api/v1/auth/challenge" \
  -H "Content-Type: application/json" \
  -d '{"pubkey": "base64_public_key", "intent": "register"}'
```

2. **Compute Proof-of-Work and Sign Challenge** (client-side)

3. **Register**:
```bash
curl -X POST "https://stage.chorus.network/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "pubkey": "base64_public_key",
    "display_name": "Anonymous User",
    "accent_color": "#FF5733",
    "pow": {"nonce": "pow_nonce", "difficulty": 15, "target": "challenge_target"},
    "proof": {"challenge": "base64_challenge", "signature": "base64_signature"}
  }'
```

### **Creating a Post**

1. **Login** (similar to registration but with existing key)

2. **Create Post**:
```bash
curl -X POST "https://stage.chorus.network/api/v1/posts/" \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "content_md": "# Hello World",
    "community_internal_slug": "general",
    "pow_nonce": "pow_nonce",
    "pow_difficulty": 15,
    "content_hash": "sha256_hash_of_content"
  }'
```

This API provides a complete anonymous social networking platform with strong cryptographic guarantees, spam protection, and transparent moderation systems.
