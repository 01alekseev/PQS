import sys
import os
from pqs_core import pqs_encrypt, pqs_decrypt


def print_usage():
    print("Usage:")
    print("  python3 pqs_cli.py encrypt <input_file> <output_file> <password>")
    print("  python3 pqs_cli.py decrypt <input_file> <output_file> <password>")
    sys.exit(1)


def read_file(path):
    if not os.path.exists(path):
        raise FileNotFoundError("File not found: " + path)
    with open(path, "rb") as f:
        return f.read()


def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)


def main():
    if len(sys.argv) != 5:
        print_usage()

    mode, input_path, output_path, password = sys.argv[1:]
    if mode not in ("encrypt", "decrypt"):
        print_usage()

    try:
        raw = read_file(input_path)
        if mode == "encrypt":
            result = pqs_encrypt(raw, password)
        else:
            result = pqs_decrypt(raw, password)
        write_file(output_path, result)
        print("Done:", mode, output_path)
    except Exception as e:
        print("Error:", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()

