import sys
import os
import getpass
from pqs_core import pqs_encrypt, pqs_decrypt

def read_file(path):
    if not os.path.exists(path):
        raise FileNotFoundError("File not found: " + path)
    with open(path, "rb") as f:
        return f.read()

def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

def main():
    if len(sys.argv) < 4:
        print("Usage:\n  python3 pqs_cli.py encrypt <input> <output>\n  python3 pqs_cli.py decrypt <input> <output>")
        sys.exit(1)

    mode, input_path, output_path = sys.argv[1:4]
    if mode not in ("encrypt", "decrypt"):
        print("Mode must be 'encrypt' or 'decrypt'")
        sys.exit(1)

    if os.path.exists(output_path):
        confirm = input(f"File '{output_path}' exists. Overwrite? [y/N]: ")
        if confirm.strip().lower() != "y":
            print("Cancelled.")
            sys.exit(0)

    try:
        password = getpass.getpass("Enter password: ")
        sys.argv = ["<purged>"]

        raw = read_file(input_path)
        if mode == "encrypt":
            result = pqs_encrypt(raw, password)
        else:
            result = pqs_decrypt(raw, password)

        del password

        write_file(output_path, result)
        print("Done")
    except Exception as e:
        print("Error:", str(e))
        sys.exit(1)

if __name__ == "__main__":
    main()
