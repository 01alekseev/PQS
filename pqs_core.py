import os

VERSION = b'PQS1'
SALT_LENGTH = 16
FAKEPAD_LENGTH = 8
INTEGRITY_LENGTH = 4
MAX_DATA_SIZE = 1_048_576


def entropy_bytes(length: int) -> bytes:
    return os.urandom(length)


def pqs_hash(data: bytes, salt: bytes) -> bytes:
    state = [0xB7, 0xC3, 0x91, 0xD1]
    for i, b in enumerate(data + salt):
        state[i % 4] ^= (b + (state[(i+1) % 4] << 1)) & 0xFF
        state[i % 4] = ((state[i % 4] << 3) | (state[i % 4] >> 5)) & 0xFF
    return bytes(state * 8)


def cube_ab_hash(data: bytes, salt: bytes) -> bytes:
    A = pqs_hash(data, salt)
    B = pqs_hash(salt, data)
    return bytes([(A[i] ^ B[i] ^ A[i - 1]) & 0xFF for i in range(len(A))])


def apply_fakepad(data: bytes, salt: bytes) -> bytes:
    head = pqs_hash(salt, b'HEAD')[:FAKEPAD_LENGTH]
    tail = pqs_hash(salt, b'TAIL')[:FAKEPAD_LENGTH]
    return head + data + tail


def remove_fakepad(padded: bytes) -> bytes:
    if len(padded) < FAKEPAD_LENGTH * 2:
        raise ValueError("Corrupted padding")
    return padded[FAKEPAD_LENGTH:-FAKEPAD_LENGTH]


def str_to_bytes(s: str) -> bytes:
    return bytes([ord(c) % 256 for c in s])


def embed_integrity(data: bytes, key: bytes) -> bytes:
    check = pqs_hash(data, key)[:INTEGRITY_LENGTH]
    return check + data


def verify_integrity(data: bytes, key: bytes) -> bytes:
    if len(data) < INTEGRITY_LENGTH:
        raise ValueError("Corrupted integrity")
    check = data[:INTEGRITY_LENGTH]
    core = data[INTEGRITY_LENGTH:]
    expected = pqs_hash(core, key)[:INTEGRITY_LENGTH]
    if check != expected:
        raise ValueError("Integrity check failed")
    return core


def pqs_encrypt(data: bytes, password: str) -> bytes:
    if not password:
        raise ValueError("Password must not be empty")
    if len(data) > MAX_DATA_SIZE:
        raise ValueError("Data too large for PQS block")
    salt = entropy_bytes(SALT_LENGTH)
    pwd = str_to_bytes(password)
    key = cube_ab_hash(pwd, salt)
    masked = bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
    secured = embed_integrity(masked, key)
    padded = apply_fakepad(secured, salt)
    return VERSION + salt + padded


def pqs_decrypt(encrypted: bytes, password: str) -> bytes:
    if len(encrypted) < 4 + SALT_LENGTH + FAKEPAD_LENGTH * 2 + INTEGRITY_LENGTH:
        raise ValueError("Corrupted PQS data")
    if not encrypted.startswith(VERSION):
        raise ValueError("Invalid PQS header")
    salt = encrypted[4:4 + SALT_LENGTH]
    padded = encrypted[4 + SALT_LENGTH:]
    secured = remove_fakepad(padded)
    pwd = str_to_bytes(password)
    key = cube_ab_hash(pwd, salt)
    core = verify_integrity(secured, key)
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(core)])

