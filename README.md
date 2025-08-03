Petoron Quantum Standard (PQS)

A fully independent, self-contained encryption standard written 100% from scratch without relying on any cryptographic libraries, third-party hashes, or encodings.

---

What is PQS ?:))

Petoron Quantum Standard is a custom cryptographic core built from the ground up for absolute offline protection.
- Own hash function - pqs_hash()
- Cube A+B logic - a one-of-a-kind key derivation method
- Fake padding - masks file structure from attackers
- Integrity embedded - modification = automatic failure
- No dependencies - works on any system

---

Each .pqs file contains:
VERSION(4B) + SALT(16B) + HEAD(8B) + INTEGRITY(4B) + DATA(n) + TAIL(8B)

Every byte is placed with purpose:
- Non-traceable
- Impossible to predict
- Secure against tampering

---

Features:
- Full symmetric encryption (XOR + dynamic key)
- Salt-based randomness
- Obfuscated binary format
- Hardcoded size limit 1MB - prevents abuse or flooding

---

Commands:

- Encrypt a file - python3 pqs_cli.py encrypt test_eqs.txt test.pqs my_pass
- Decrypt a file - python3 pqs_cli.py decrypt test.pqs test_eqs.txt my_pass

---

- Example:
python3 pqs_cli.py encrypt test_eqs.txt test.pqs 123456789

- Example:
python3 pqs_cli.py decrypt test.pqs test_eqs.txt 123456789

---

What happens if...
Wrong password - integrity check fails
File modified - corrupted padding error
Empty password - error is raised
File too large >1MB - rejected instantly

---

You can run it anywhere.
It doesn't talk to the internet. It doesn't log anything. It simply does what it says: encrypt and protect - with brutal transparency :))

---

Licensed under the PQS Fair Use License by Ivan Alekseev | Petoron

