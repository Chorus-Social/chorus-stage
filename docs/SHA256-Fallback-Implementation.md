# SHA-256 Fallback Implementation for Web Frontend PoW

## Overview

This document describes the implementation of SHA-256 fallback support for proof-of-work (PoW) in the Chorus Stage system. The implementation allows web frontends to use SHA-256 when Blake3 is not available, while maintaining compatibility with the existing Blake3-based system.

## Problem Statement

Web frontends may encounter issues with Blake3 due to:
- WebAssembly compatibility issues
- Browser support limitations
- Build system constraints
- Performance considerations on certain devices

## Solution Architecture

### 1. Server-Side Changes

#### Core PoW Module (`src/chorus_stage/core/pow.py`)
- Added `hash_algorithm` parameter to `validate_solution()`
- Support for both "blake3" and "sha256" algorithms
- Maintains backward compatibility (defaults to "blake3")

#### PoW Service (`src/chorus_stage/services/pow.py`)
- Added `hash_algorithm` parameter to `verify_pow()`
- Automatic payload digest computation based on algorithm
- Maintains existing API compatibility

#### API Schemas
- **PostCreate** (`src/chorus_stage/schemas/post.py): Added `pow_hash_algorithm` field
- **PowEnvelope** (`src/chorus_stage/schemas/user.py): Added `hash_algorithm` field
- Both fields default to "blake3" for backward compatibility

#### API Endpoints
- **Posts endpoint**: Updated to pass `hash_algorithm` to PoW verification
- **Auth endpoints**: Updated to use `hash_algorithm` from PowEnvelope

### 2. Client-Side Utilities

#### PoW Client Utilities (`src/chorus_stage/utils/pow_client.py`)
- `compute_payload_digest()`: Compute payload digest with specified algorithm
- `compute_pow_hash()`: Compute final PoW hash with specified algorithm
- `count_leading_zero_bits()`: Count leading zero bits in hash
- `find_pow_solution()`: Brute force PoW solution finding
- `get_available_hash_algorithms()`: Get list of available algorithms
- `get_preferred_hash_algorithm()`: Get preferred algorithm (Blake3 if available)

### 3. Web Frontend Integration

#### JavaScript/TypeScript Support
- Automatic algorithm detection
- Fallback mechanism from Blake3 to SHA-256
- Browser compatibility handling
- Performance optimization

## Implementation Details

### Hash Algorithm Support

| Algorithm | Server Support | Client Support | Browser Compatibility |
|-----------|---------------|----------------|---------------------|
| Blake3    | ✅ Full       | ✅ Full        | ⚠️ Limited         |
| SHA-256   | ✅ Full       | ✅ Full        | ✅ Universal       |

### API Changes

#### New Fields
```typescript
// Post creation
interface PostCreate {
  // ... existing fields
  pow_hash_algorithm: "blake3" | "sha256"; // Default: "blake3"
}

// Authentication
interface PowEnvelope {
  // ... existing fields
  hash_algorithm: "blake3" | "sha256"; // Default: "blake3"
}
```

#### Backward Compatibility
- All new fields have default values
- Existing clients continue to work without changes
- Server accepts both algorithms seamlessly

### Security Considerations

1. **Cryptographic Security**: Both Blake3 and SHA-256 are cryptographically secure
2. **No Security Degradation**: SHA-256 fallback maintains same security properties
3. **Algorithm Validation**: Server validates both algorithms equally
4. **Replay Protection**: Works identically for both algorithms

### Performance Impact

1. **Server Performance**: Minimal impact - same validation logic
2. **Client Performance**: SHA-256 may be slower than Blake3 on modern hardware
3. **Network**: No additional data transfer required
4. **Storage**: No additional storage requirements

## Usage Examples

### Server-Side (Python)

```python
from chorus_stage.services.pow import PowService

pow_service = PowService()

# Verify PoW with Blake3 (default)
result = pow_service.verify_pow("post", "pubkey", "nonce")

# Verify PoW with SHA-256
result = pow_service.verify_pow("post", "pubkey", "nonce", hash_algorithm="sha256")
```

### Client-Side (Python)

```python
from chorus_stage.utils.pow_client import (
    compute_payload_digest,
    find_pow_solution,
    get_preferred_hash_algorithm
)

# Get preferred algorithm
algorithm = get_preferred_hash_algorithm()  # "blake3" or "sha256"

# Find PoW solution
nonce, success = find_pow_solution(
    "post", "pubkey", "challenge", 16, algorithm
)
```

### Web Frontend (JavaScript/TypeScript)

```typescript
// Automatic fallback implementation
class AdaptiveProofOfWork {
  async computeProofOfWork(params: PowParams) {
    try {
      // Try Blake3 first
      return await this.computeWithBlake3(params);
    } catch {
      // Fall back to SHA-256
      return await this.computeWithSHA256(params);
    }
  }
}
```

## Testing

### Test Coverage
- ✅ SHA-256 algorithm support
- ✅ Blake3 algorithm support (when available)
- ✅ Fallback mechanism
- ✅ API compatibility
- ✅ Security validation
- ✅ Performance characteristics

### Test Files
- `tests/v1/test_pow_sha256_fallback.py`: Comprehensive test suite
- Existing PoW tests continue to pass
- Integration tests verify end-to-end functionality

## Migration Guide

### For Existing Clients
1. **No changes required**: Existing clients continue to work
2. **Optional upgrade**: Add `pow_hash_algorithm` field for explicit control
3. **Gradual migration**: Can migrate to SHA-256 as needed

### For New Clients
1. **Detect algorithm availability**: Use `get_available_hash_algorithms()`
2. **Choose preferred algorithm**: Use `get_preferred_hash_algorithm()`
3. **Implement fallback**: Handle algorithm unavailability gracefully

## Bridge and Conductor Impact

### No Impact on Core Systems
- **Bridge**: Continues to use Blake3 for federation and event hashing
- **Conductor**: Continues to use Blake3 for VDF and consensus
- **No changes required**: Deep system layers remain unchanged

### Separation of Concerns
- **User-facing PoW**: Can use SHA-256 fallback
- **System PoW**: Continues to use Blake3
- **Clear boundaries**: User PoW vs system PoW are separate

## Future Considerations

### Potential Enhancements
1. **Algorithm negotiation**: Client-server algorithm selection
2. **Performance metrics**: Algorithm performance monitoring
3. **Dynamic switching**: Runtime algorithm changes
4. **Additional algorithms**: Support for other hash functions

### Monitoring
1. **Usage statistics**: Track algorithm usage patterns
2. **Performance metrics**: Monitor computation times
3. **Error rates**: Track fallback frequency
4. **User experience**: Monitor client satisfaction

## Conclusion

The SHA-256 fallback implementation provides a robust solution for web frontend PoW compatibility while maintaining the security and performance characteristics of the existing system. The implementation is backward-compatible, secure, and provides a clear migration path for clients experiencing Blake3 issues.

The solution successfully addresses the original problem while preserving the integrity of the deeper system layers (Bridge and Conductor) that depend on Blake3 for their core functionality.
