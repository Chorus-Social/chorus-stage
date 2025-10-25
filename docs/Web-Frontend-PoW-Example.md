# Web Frontend Proof-of-Work Implementation

This document provides examples for implementing proof-of-work in web frontends with Blake3/SHA-256 fallback support.

## JavaScript/TypeScript Implementation

### 1. Hash Algorithm Detection

```typescript
// Check if Blake3 is available in the browser
async function isBlake3Available(): Promise<boolean> {
  try {
    // Try to import Blake3 (if using a bundler that supports it)
    const { blake3 } = await import('blake3-wasm');
    return true;
  } catch {
    return false;
  }
}

// Alternative: Check for Web Crypto API support
function isWebCryptoAvailable(): boolean {
  return typeof window !== 'undefined' && 
         window.crypto && 
         window.crypto.subtle;
}
```

### 2. SHA-256 Implementation (Always Available)

```typescript
async function sha256Hash(data: Uint8Array): Promise<Uint8Array> {
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hashBuffer);
}
```

### 3. Blake3 Implementation (When Available)

```typescript
// Using blake3-wasm (recommended for browsers)
async function blake3Hash(data: Uint8Array): Promise<Uint8Array> {
  const { blake3 } = await import('blake3-wasm');
  return blake3(data);
}

// Alternative: Using a different Blake3 library
async function blake3HashAlternative(data: Uint8Array): Promise<Uint8Array> {
  const { blake3 } = await import('@noble/hashes/blake3');
  return blake3(data);
}
```

### 4. Proof-of-Work Computation

```typescript
interface PowParams {
  action: string;
  pubkeyHex: string;
  challengeStr: string;
  targetBits: number;
  hashAlgorithm: 'blake3' | 'sha256';
}

class ProofOfWork {
  private hashFunction: (data: Uint8Array) => Promise<Uint8Array>;
  
  constructor(hashAlgorithm: 'blake3' | 'sha256') {
    this.hashFunction = hashAlgorithm === 'blake3' ? blake3Hash : sha256Hash;
  }
  
  async computePayloadDigest(
    action: string,
    pubkeyHex: string,
    challengeStr: string
  ): Promise<Uint8Array> {
    const combinedPayload = `${action}:${pubkeyHex}:${challengeStr}`;
    const payloadBytes = new TextEncoder().encode(combinedPayload);
    return this.hashFunction(payloadBytes);
  }
  
  async computePowHash(
    saltBytes: Uint8Array,
    payloadDigest: Uint8Array,
    nonce: number
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
    
    return this.hashFunction(inputBytes);
  }
  
  countLeadingZeroBits(hashBytes: Uint8Array): number {
    let zeros = 0;
    for (const byte of hashBytes) {
      if (byte === 0) {
        zeros += 8;
        continue;
      }
      // Count bits in first non-zero byte
      for (let bit = 7; bit >= 0; bit--) {
        if (((byte >> bit) & 1) === 0) {
          zeros++;
        } else {
          break; // Found first non-zero bit
        }
      }
      break; // Exit outer loop after processing the first non-zero byte
    }
    return zeros;
  }
  
  async findSolution(
    params: PowParams,
    maxAttempts: number = 1000000
  ): Promise<{ nonce: number; success: boolean }> {
    const saltBytes = this.hexToBytes(params.challengeStr);
    const payloadDigest = await this.computePayloadDigest(
      params.action,
      params.pubkeyHex,
      params.challengeStr
    );
    
    for (let nonce = 0; nonce < maxAttempts; nonce++) {
      const hashResult = await this.computePowHash(saltBytes, payloadDigest, nonce);
      if (this.countLeadingZeroBits(hashResult) >= params.targetBits) {
        return { nonce, success: true };
      }
    }
    
    return { nonce: 0, success: false };
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

### 5. Automatic Fallback Implementation

```typescript
class AdaptiveProofOfWork {
  private preferredAlgorithm: 'blake3' | 'sha256';
  
  constructor() {
    this.preferredAlgorithm = 'sha256'; // Default fallback
  }
  
  async initialize(): Promise<void> {
    // Try to use Blake3 if available
    try {
      const { blake3 } = await import('blake3-wasm');
      this.preferredAlgorithm = 'blake3';
      console.log('Using Blake3 for proof-of-work');
    } catch {
      console.log('Blake3 not available, using SHA-256 fallback');
    }
  }
  
  async computeProofOfWork(
    action: string,
    pubkeyHex: string,
    challengeStr: string,
    targetBits: number
  ): Promise<{ nonce: number; hashAlgorithm: string; success: boolean }> {
    const pow = new ProofOfWork(this.preferredAlgorithm);
    const result = await pow.findSolution({
      action,
      pubkeyHex,
      challengeStr,
      targetBits,
      hashAlgorithm: this.preferredAlgorithm
    });
    
    return {
      ...result,
      hashAlgorithm: this.preferredAlgorithm
    };
  }
}
```

### 6. Usage Example

```typescript
// Initialize the adaptive PoW system
const pow = new AdaptiveProofOfWork();
await pow.initialize();

// Compute proof-of-work for a post
const result = await pow.computeProofOfWork(
  'post',
  'your-pubkey-hex',
  'challenge-from-server',
  16 // target difficulty
);

if (result.success) {
  // Submit to server with the computed nonce and hash algorithm
  const postData = {
    content_md: 'Your post content',
    pow_nonce: result.nonce.toString(16),
    pow_difficulty: 16,
    pow_hash_algorithm: result.hashAlgorithm,
    content_hash: 'sha256-hash-of-content'
  };
  
  // Send to server...
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

## Performance Considerations

1. **Blake3**: Faster on modern hardware, especially for large inputs
2. **SHA-256**: More widely supported, consistent performance
3. **Fallback strategy**: Try Blake3 first, fall back to SHA-256 if unavailable

## Security Notes

- Both Blake3 and SHA-256 are cryptographically secure
- The fallback maintains the same security properties
- Server validates both algorithms equally
- No security degradation from using SHA-256 fallback
