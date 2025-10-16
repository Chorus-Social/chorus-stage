import binascii
from chorus_stage.core.pow import generate_challenge, validate_solution
import hashlib

def test_pow_trivial_solution():
    ch = generate_challenge("post", target_bits=0)
    digest = hashlib.sha256(b"hello").digest()
    assert validate_solution(ch, digest, nonce=0) is True

def test_pow_basic():
    ch = generate_challenge("post", target_bits=8)
    digest = hashlib.sha256(b"payload").digest()
    # naive search for small difficulty
    nonce = 0
    while True:
        if validate_solution(ch, digest, nonce):
            break
        nonce += 1
    assert nonce >= 0
