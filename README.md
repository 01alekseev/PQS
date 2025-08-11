Petoron Quantum Standard (PQS)

A fully independent, self-contained encryption standard — built from the ground up with zero reliance on external cryptographic libraries, third-party hashes, or encodings.

---

What is PQS ?:))

Petoron Quantum Standard is a custom cryptographic engine designed for absolute offline file protection - minimalistic, auditable, and brutally transparent.
- PBKDF2-HMAC-SHA256 (200k iterations, adjustable) for password hardening.
- Key separation via BLAKE2s — independent keys for encryption and MAC.
- BLAKE2s-MAC authentication — 16-byte tag, modification = instant rejection.
- Streaming keystream generator — no key reuse, secure for large payloads.
- Fake padding (HEAD/TAIL) — obfuscates binary boundaries and structure.
- Precise size encoding — restores original payload exactly.
- Supports files up to 128 MB per encrypted block.

---

PQS File Structure:
VERSION (4B)  
SALT (16B)  
FAKEPAD_HEAD (8B)  
TAG (16B)  
ORIG_SIZE (4B)  
CIPHERTEXT (n bytes)  
FAKEPAD_TAIL (8B)  

Every byte is placed with purpose:
- Non-traceable
- Impossible to predict
- Secure against tampering

---

Features:
Full symmetric encryption (XOR + streaming keystream)
Salt-based randomness for every file
Obfuscated binary format with fake padding
Strict size limit: 128 MB per block
Works fully offline
---

Commands:

- Encrypt a file - python3 pqs_cli.py encrypt test_eqs.txt test.pqs
- Decrypt a file - python3 pqs_cli.py decrypt test.pqs test_eqs.txt

---

- Example:
python3 pqs_cli.py encrypt test_eqs.txt test.pqs
Enter password
Done.

- Example:
python3 pqs_cli.py decrypt test.pqs test_eqs.txt
Enter password
Done.

---

Failure Cases:
- Wrong password: Integrity/auth check failed
- File modified: Corrupted padding or tag mismatch
- Empty password: Error raised

---

You can run it anywhere.
It doesn't talk to the internet. It doesn't log anything. It simply does what it says: encrypt and protect - with brutal transparency :))

---

Licensed under the PQS Fair Use License by Ivan Alekseev | Petoron

