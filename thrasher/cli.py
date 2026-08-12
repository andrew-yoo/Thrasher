import argparse
import getpass
import sys

from .main import encrypt, decrypt


def main():
    parser = argparse.ArgumentParser(description="Thrasher")
    parser.add_argument("file", help="file to encrypt or decrypt")
    parser.add_argument("-w", "--overwrite", action="store_true", help="allow overwriting an existing file")
    args = parser.parse_args()

    try:
        if not args.file.endswith(".thrash"):
            password = getpass.getpass("Password: ").encode()

            if not password:
                print("Password field cannot be empty", file=sys.stderr)
                sys.exit(1)

            password2 = getpass.getpass("Confirm: ").encode()
            if password != password2:
                print("Passwords do not match", file=sys.stderr)
                sys.exit(1)

            encrypt(args.file, password, args.overwrite)

        else:
            password = getpass.getpass("Password: ").encode()

            if not password:
                print("Password field cannot be empty", file=sys.stderr)
                sys.exit(1)

            decrypt(args.file, password, args.overwrite)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
