import bcrypt

def hash_key(plain_key: str) -> str:
    key_bytes = plain_key.encode('utf-8')
    hashed = bcrypt.hashpw(key_bytes, bcrypt.gensalt())

    return hashed.decode('utf-8')

def verify_key(plain_key: str, hashed_key: str) -> bool:
    key_bytes = plain_key.encode('utf-8')
    hashed_bytes = hashed_key.encode('utf-8')
    
    return bcrypt.checkpw(key_bytes, hashed_bytes)