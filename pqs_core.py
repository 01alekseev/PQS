import os
import struct
import hashlib
import hmac

VERSION = b'PQS1'
SALT_LENGTH = 16
FAKEPAD_LENGTH = 8
ORIGSIZE_LENGTH = 4
MAX_DATA_SIZE = 134_217_728
TAG_LENGTH = 16
KDF_ITERS = int(os.getenv("PQS_KDF_ITERS", "200000"))

def _rotl32(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
def _u32(x): return x & 0xFFFFFFFF
def _pack32(*ws): return struct.pack(">" + "I"*len(ws), *ws)
def _unpack32(b):
    n = len(b)//4
    return list(struct.unpack(">" + "I"*n, b[:n*4]))

def entropy_bytes(n: int) -> bytes: return os.urandom(n)

def str_to_bytes(s: str) -> bytes:
    b = s.encode("utf-8", "strict")
    return len(b).to_bytes(2, "big") + b

def _arx_round(state):
    a,b,c,d,e,f,g,h = state
    a = _u32(a + b); d ^= a; d = _rotl32(d, 16)
    e = _u32(e + f); h ^= e; h = _rotl32(h, 12)
    c = _u32(c + d); b ^= c; b = _rotl32(b, 8)
    g = _u32(g + h); f ^= g; f = _rotl32(f, 7)
    a = _u32(a + b); d ^= a; d = _rotl32(d, 16)
    e = _u32(e + f); h ^= e; h = _rotl32(h, 12)
    c = _u32(c + d); b ^= c; b = _rotl32(b, 8)
    g = _u32(g + h); f ^= g; f = _rotl32(f, 7)
    return [a,b,c,d,e,f,g,h]

def _arx_permute(state, rounds=12):
    s = list(state)
    for _ in range(rounds):
        s = _arx_round(s)
        s = [s[0], s[3], s[6], s[1], s[4], s[7], s[2], s[5]]
    return s

def _sponge_absorb(initial_state, data: bytes):
    s = list(initial_state); rate = 32
    for i in range(0, len(data), rate):
        block = data[i:i+rate]
        words = _unpack32(block.ljust(rate, b"\x00"))
        for j in range(8): s[j] ^= words[j]
        s = _arx_permute(s)
    return s

def _sponge_squeeze(state, out_len: int) -> bytes:
    s = list(state); out = bytearray()
    while len(out) < out_len:
        s = _arx_permute(s)
        out.extend(_pack32(*s))
    return bytes(out[:out_len])

def pqs_hash(data: bytes, salt: bytes, out_len: int = 32) -> bytes:
    init = [
        0x61707865 ^ 0x50515332, 0x3320646E ^ 0xA5A5A5A5,
        0x79622D32 ^ 0xDEADBEEF, 0x6B206574 ^ 0xC3D2E1F0,
        0x9E3779B9, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A
    ]
    s = _sponge_absorb(init, b"HASH" + salt + b"|" + data)
    return _sponge_squeeze(s, out_len)

def _pbkdf2_master(password_b: bytes, salt: bytes, iters: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password_b, b"PQS1|" + salt, iters, dklen=64)

def _derive_keys_from_master(master: bytes, salt: bytes):
    he = hashlib.blake2s(key=master[:32], digest_size=32); he.update(b"ENC"); he.update(salt)
    hm = hashlib.blake2s(key=master[32:], digest_size=32); hm.update(b"MAC"); hm.update(salt)
    return he.digest(), hm.digest()

def _keystream(key_enc: bytes, salt: bytes, nbytes: int) -> bytes:
    out = bytearray(); counter = 0
    while len(out) < nbytes:
        h = hashlib.blake2s(key=key_enc, digest_size=32)
        h.update(salt); h.update(counter.to_bytes(8, "big"))
        out.extend(h.digest()); counter += 1
    return bytes(out[:nbytes])

def _mac_tag(key_mac: bytes, ad: bytes, ciphertext: bytes) -> bytes:
    h = hashlib.blake2s(key=key_mac, digest_size=TAG_LENGTH)
    h.update(ad); h.update(ciphertext)
    return h.digest()

def apply_fakepad(data: bytes, salt: bytes) -> bytes:
    head = pqs_hash(salt, b'HEAD', FAKEPAD_LENGTH)
    tail = pqs_hash(salt, b'TAIL', FAKEPAD_LENGTH)
    return head + data + tail

def remove_fakepad(padded: bytes) -> bytes:
    if len(padded) < FAKEPAD_LENGTH * 2: raise ValueError("Corrupted padding")
    return padded[FAKEPAD_LENGTH:-FAKEPAD_LENGTH]

def pqs_encrypt(data: bytes, password: str) -> bytes:
    if not password: raise ValueError("Password must not be empty")
    if len(data) > MAX_DATA_SIZE: raise ValueError("Data too large for PQS block")

    salt = entropy_bytes(SALT_LENGTH)
    pwd = str_to_bytes(password)

    iters = KDF_ITERS
    master = _pbkdf2_master(pwd, salt, iters)
    key_enc, key_mac = _derive_keys_from_master(master, salt)

    ks = _keystream(key_enc, salt, len(data))
    masked = bytes(db ^ kb for db, kb in zip(data, ks))
    sized = len(data).to_bytes(ORIGSIZE_LENGTH, "big") + masked

    iters_be = iters.to_bytes(4, "big")
    ad = VERSION + salt + iters_be
    tag = _mac_tag(key_mac, ad, sized)

    secured = tag + sized
    padded = apply_fakepad(secured, salt)
    return VERSION + salt + iters_be + padded

def pqs_decrypt(encrypted: bytes, password: str) -> bytes:
    min_len = 4 + SALT_LENGTH + 4 + FAKEPAD_LENGTH*2 + TAG_LENGTH + ORIGSIZE_LENGTH
    if len(encrypted) < min_len: raise ValueError("Corrupted PQS data")
    if not encrypted.startswith(VERSION): raise ValueError("Invalid PQS header")

    salt = encrypted[4:4+SALT_LENGTH]
    iters_be = encrypted[4+SALT_LENGTH:4+SALT_LENGTH+4]
    if len(iters_be) != 4: raise ValueError("Corrupted PQS header")
    iters = int.from_bytes(iters_be, "big")

    padded = encrypted[4+SALT_LENGTH+4:]
    secured = remove_fakepad(padded)

    tag = secured[:TAG_LENGTH]
    rest = secured[TAG_LENGTH:]
    if len(rest) < ORIGSIZE_LENGTH: raise ValueError("Corrupted PQS body")

    pwd = str_to_bytes(password)
    master = _pbkdf2_master(pwd, salt, iters)
    key_enc, key_mac = _derive_keys_from_master(master, salt)

    ad = VERSION + salt + iters_be
    expected_tag = _mac_tag(key_mac, ad, rest)
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Integrity/auth check failed")

    orig_size = int.from_bytes(rest[:ORIGSIZE_LENGTH], "big")
    masked = rest[ORIGSIZE_LENGTH:]
    if len(masked) < orig_size: raise ValueError("Truncated payload")

    ks = _keystream(key_enc, salt, orig_size)
    data = bytes(mb ^ kb for mb, kb in zip(masked[:orig_size], ks))
    return data
