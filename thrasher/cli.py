import argparse
import getpass
import sys

from .main import encrypt, decrypt


def main():
    parser = argparse.ArgumentParser(description="Thrasher")
    parser.add_argument("file", help="file to encrypt or decrypt")
    parser.add_argument("-w", "--overwrite", action="store_true", help="overwrite the input file on decryption")
    args = parser.parse_args()

    try:
        if not args.file.endswith(".thrash"):
            if args.overwrite:
                print("-w/--overwrite is only supported when decrypting", file=sys.stderr)
                sys.exit(1)

            password = getpass.getpass("Password: ").encode()

            if password == b"":
                print("Password field cannot be empty", file=sys.stderr)
                sys.exit(1)

            password2 = getpass.getpass("Confirm: ").encode()
            if password != password2:
                print("Passwords do not match", file=sys.stderr)
                sys.exit(1)

            encrypt(args.file, password)

        else:
            password = getpass.getpass("Password: ").encode()
            decrypt(args.file, password, args.overwrite)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
