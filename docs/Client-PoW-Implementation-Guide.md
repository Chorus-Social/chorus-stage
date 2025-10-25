# Client Proof-of-Work Implementation Guide

This guide provides complete implementation details for handling PoW with SHA-256 fallback support in Chorus Stage clients.

## API Request Structure

### For Post Creation:
```json
{
  "content_md": "Your post content here",
  "parent_post_id": null,
  "community_internal_slug": "general",
  "pow_nonce": "1a2b3c4d5e6f7890",
  "pow_difficulty": 16,
  "pow_hash_algorithm": "sha256",
  "content_hash": "sha256-hash-of-content"
}
```

### For Authentication (Register/Login):
```json
{
  "pubkey": "base64-encoded-ed25519-public-key",
  "pow": {
    "nonce": "1a2b3c4d5e6f7890",
    "difficulty": 16,
    "target": "server-provided-challenge",
    "hash_algorithm": "sha256"
  },
  "proof": {
    "challenge": "base64-encoded-challenge",
    "signature": "ed25519-signature"
  }
}
```

## Client-Side PoW Computation

### JavaScript/TypeScript Implementation:

```typescript
class ChorusPoWClient {
  private preferredAlgorithm: 'blake3' | 'sha256' = 'sha256';
  
  constructor() {
    this.detectPreferredAlgorithm();
  }
  
  private async detectPreferredAlgorithm(): Promise<void> {
    // Try Blake3 first, fall back to SHA-256
    try {
      const { blake3 } = await import('blake3-wasm');
      this.preferredAlgorithm = 'blake3';
      console.log('Using Blake3 for PoW');
    } catch {
      console.log('Blake3 not available, using SHA-256 fallback');
    }
  }
  
  async computePoW(
    action: string,
    pubkeyHex: string,
    challengeStr: string,
    targetBits: number
  ): Promise<{ nonce: string; hashAlgorithm: string; success: boolean }> {
    
    const saltBytes = this.hexToBytes(challengeStr);
    const payloadDigest = await this.computePayloadDigest(
      action, pubkeyHex, challengeStr, this.preferredAlgorithm
    );
    
    // Brute force search for valid nonce
    for (let nonce = 0; nonce < 1000000; nonce++) {
      const hashResult = await this.computePowHash(
        saltBytes, payloadDigest, nonce, this.preferredAlgorithm
      );
      
      if (this.countLeadingZeroBits(hashResult) >= targetBits) {
        return {
          nonce: nonce.toString(16),
          hashAlgorithm: this.preferredAlgorithm,
          success: true
        };
      }
    }
    
    return { nonce: '0', hashAlgorithm: this.preferredAlgorithm, success: false };
  }
  
  private async computePayloadDigest(
    action: string,
    pubkeyHex: string,
    challengeStr: string,
    algorithm: 'blake3' | 'sha256'
  ): Promise<Uint8Array> {
    const combinedPayload = `${action}:${pubkeyHex}:${challengeStr}`;
    const payloadBytes = new TextEncoder().encode(combinedPayload);
    
    if (algorithm === 'sha256') {
      const hashBuffer = await window.crypto.subtle.digest('SHA-256', payloadBytes);
      return new Uint8Array(hashBuffer);
    } else {
      // Blake3 implementation
      const { blake3 } = await import('blake3-wasm');
      return blake3(payloadBytes);
    }
  }
  
  private async computePowHash(
    saltBytes: Uint8Array,
    payloadDigest: Uint8Array,
    nonce: number,
    algorithm: 'blake3' | 'sha256'
  ): Promise<Uint8Array> {
    const nonceBytes = new Uint8Array(8);
    const view = new DataView(nonceBytes.buffer);
    view.setBigUint64(0, BigInt(nonce), true); // little-endian
    
    const inputBytes = new Uint8Array(
      saltBytes.length + payloadDigest.length + nonceBytes.length
    );
    inputBytes.set(saltBytes, 0);
    inputBytes.set(payloadDigest, saltBytes.length);
    inputBytes.set(nonceBytes, saltBytes.length + payloadDigest.length);
    
    if (algorithm === 'sha256') {
      const hashBuffer = await window.crypto.subtle.digest('SHA-256', inputBytes);
      return new Uint8Array(hashBuffer);
    } else {
      const { blake3 } = await import('blake3-wasm');
      return blake3(inputBytes);
    }
  }
  
  private countLeadingZeroBits(hashBytes: Uint8Array): number {
    let zeros = 0;
    for (const byte of hashBytes) {
      if (byte === 0) {
        zeros += 8;
        continue;
      }
      for (let bit = 7; bit >= 0; bit--) {
        if (((byte >> bit) & 1) === 0) {
          zeros++;
        } else {
          break;
        }
      }
      break;
    }
    return zeros;
  }
  
  private hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }
}
```

## Complete Client Workflow

### Step 1: Get Challenge from Server
```typescript
// For posts, get challenge from server
const challengeResponse = await fetch('/api/v1/posts/challenge', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    action: 'post',
    pubkey: 'your-pubkey-hex'
  })
});

const { salt_hex, target_bits } = await challengeResponse.json();
```

### Step 2: Compute PoW
```typescript
const powClient = new ChorusPoWClient();
const powResult = await powClient.computePoW(
  'post',
  'your-pubkey-hex',
  salt_hex,
  target_bits
);

if (!powResult.success) {
  throw new Error('Failed to compute proof of work');
}
```

### Step 3: Submit with PoW
```typescript
// For post creation
const postData = {
  content_md: 'Your post content',
  parent_post_id: null,
  community_internal_slug: 'general',
  pow_nonce: powResult.nonce,
  pow_difficulty: target_bits,
  pow_hash_algorithm: powResult.hashAlgorithm,
  content_hash: await computeContentHash('Your post content')
};

const response = await fetch('/api/v1/posts/', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer your-jwt-token'
  },
  body: JSON.stringify(postData)
});
```

## Python Client Implementation

```python
from chorus_stage.utils.pow_client import (
    find_pow_solution,
    get_preferred_hash_algorithm,
    compute_payload_digest
)

def compute_pow_for_post(action: str, pubkey_hex: str, challenge_str: str, target_bits: int):
    """Compute PoW for a post."""
    # Get preferred algorithm
    algorithm = get_preferred_hash_algorithm()
    
    # Find solution
    nonce, success = find_pow_solution(
        action, pubkey_hex, challenge_str, target_bits, algorithm
    )
    
    if not success:
        raise ValueError("Failed to compute proof of work")
    
    return {
        'nonce': hex(nonce),
        'hash_algorithm': algorithm,
        'difficulty': target_bits
    }

# Usage
pow_data = compute_pow_for_post('post', 'your-pubkey', 'challenge', 16)
```

## Server Response Handling

### Successful PoW Validation:
```json
{
  "id": 123,
  "order_index": 456,
  "author_user_id": "user-id",
  "author_pubkey": "pubkey-hex",
  "body_md": "Your post content",
  "content_hash": "content-hash",
  "moderation_state": 0,
  "harmful_vote_count": 0,
  "upvotes": 0,
  "downvotes": 0,
  "deleted": false
}
```

### PoW Validation Errors:
```json
{
  "detail": "Invalid proof of work for post creation"
}
```

## Error Handling

```typescript
try {
  const powResult = await powClient.computePoW(action, pubkey, challenge, difficulty);
  
  if (!powResult.success) {
    // Handle PoW computation failure
    console.error('PoW computation failed');
    return;
  }
  
  // Submit with PoW
  const response = await submitWithPoW(powResult);
  
} catch (error) {
  if (error.message.includes('Blake3 is not available')) {
    // Fall back to SHA-256
    powClient.preferredAlgorithm = 'sha256';
    // Retry computation
  } else {
    console.error('PoW error:', error);
  }
}
```

## Performance Optimization

```typescript
class OptimizedPoWClient extends ChorusPoWClient {
  private worker: Worker | null = null;
  
  async computePoWAsync(
    action: string,
    pubkeyHex: string,
    challengeStr: string,
    targetBits: number
  ): Promise<{ nonce: string; hashAlgorithm: string; success: boolean }> {
    
    // Use Web Worker for non-blocking computation
    return new Promise((resolve) => {
      this.worker = new Worker('/pow-worker.js');
      
      this.worker.postMessage({
        action, pubkeyHex, challengeStr, targetBits,
        algorithm: this.preferredAlgorithm
      });
      
      this.worker.onmessage = (e) => {
        resolve(e.data);
        this.worker?.terminate();
      };
    });
  }
}
```

## Web Worker Implementation (pow-worker.js)

```javascript
// pow-worker.js
self.onmessage = async function(e) {
  const { action, pubkeyHex, challengeStr, targetBits, algorithm } = e.data;
  
  try {
    const result = await computePoWInWorker(action, pubkeyHex, challengeStr, targetBits, algorithm);
    self.postMessage(result);
  } catch (error) {
    self.postMessage({ success: false, error: error.message });
  }
};

async function computePoWInWorker(action, pubkeyHex, challengeStr, targetBits, algorithm) {
  // Implementation similar to main thread but optimized for worker
  const saltBytes = hexToBytes(challengeStr);
  const payloadDigest = await computePayloadDigest(action, pubkeyHex, challengeStr, algorithm);
  
  for (let nonce = 0; nonce < 1000000; nonce++) {
    const hashResult = await computePowHash(saltBytes, payloadDigest, nonce, algorithm);
    
    if (countLeadingZeroBits(hashResult) >= targetBits) {
      return {
        nonce: nonce.toString(16),
        hashAlgorithm: algorithm,
        success: true
      };
    }
  }
  
  return { nonce: '0', hashAlgorithm: algorithm, success: false };
}
```

## Browser Compatibility

### Blake3 Support
- **Modern browsers**: Use `blake3-wasm` package
- **Older browsers**: Falls back to SHA-256
- **Node.js**: Use `blake3` package directly

### SHA-256 Support
- **All modern browsers**: Web Crypto API
- **Older browsers**: Use a polyfill like `crypto-js`

## Package Dependencies

### For JavaScript/TypeScript:
```json
{
  "dependencies": {
    "blake3-wasm": "^1.0.0",
    "crypto-js": "^4.1.1"
  }
}
```

### For Python:
```toml
[tool.poetry.dependencies]
blake3 = "^1.0.8"
```

## Key Implementation Points

1. **Algorithm Detection**: Always try Blake3 first, fall back to SHA-256
2. **Nonce Format**: Return nonce as hexadecimal string
3. **Hash Algorithm**: Include the algorithm used in the request
4. **Error Handling**: Handle both computation failures and algorithm unavailability
5. **Performance**: Consider using Web Workers for intensive computation
6. **Security**: Never expose private keys in PoW computation

## Testing Your Implementation

### Test with SHA-256:
```typescript
// Force SHA-256 usage
const powClient = new ChorusPoWClient();
powClient.preferredAlgorithm = 'sha256';

const result = await powClient.computePoW('post', 'test-pubkey', 'test-challenge', 8);
console.log('SHA-256 result:', result);
```

### Test with Blake3:
```typescript
// Force Blake3 usage (if available)
const powClient = new ChorusPoWClient();
powClient.preferredAlgorithm = 'blake3';

const result = await powClient.computePoW('post', 'test-pubkey', 'test-challenge', 8);
console.log('Blake3 result:', result);
```

## Troubleshooting

### Common Issues:

1. **"Blake3 is not available"**: This is expected in some browsers. The client will automatically fall back to SHA-256.

2. **PoW computation timeout**: Increase the maximum attempts or use Web Workers for better performance.

3. **Invalid nonce format**: Ensure nonce is returned as a hexadecimal string.

4. **Algorithm mismatch**: Make sure the `hash_algorithm` field in the request matches the algorithm used for computation.

### Debug Mode:
```typescript
class DebugPoWClient extends ChorusPoWClient {
  async computePoW(...args) {
    console.log('Computing PoW with algorithm:', this.preferredAlgorithm);
    const result = await super.computePoW(...args);
    console.log('PoW result:', result);
    return result;
  }
}
```

The client should automatically detect the best available algorithm and seamlessly fall back to SHA-256 when Blake3 is not available, ensuring compatibility across all web browsers and environments.
