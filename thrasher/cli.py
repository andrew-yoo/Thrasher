import argparse
import getpass
import sys

from .main import encrypt, decrypt
from .shared import Header


def main():
    parser = argparse.ArgumentParser(description="Thrasher")
    parser.add_argument("file", help="file to encrypt or decrypt")
    parser.add_argument("-o", "--overkill", action="store_true", help="use overkill mode (encrypt only)")
    parser.add_argument("-v", "--verify", action="store_true", help="verify before decrypting")
    parser.add_argument("-w", "--overwrite", action="store_true", help="overwrite the input file")
    args = parser.parse_args()

    # getpass doesn't work on web assembly

    try:
        extension = str(args.file).split(".")[-1]
    except:
        extension = None

    try:
        if extension != "thrash":
            password = getpass.getpass("Password: ").encode()
            
            if password == b"":
                print("Password field cannot be empty", file=sys.stderr)
                sys.exit(1)

            password2 = getpass.getpass("Confirm: ").encode()
            if password != password2:
                print("Passwords do not match", file=sys.stderr)
                sys.exit(1)

            mode = Header.OVERKILL if args.overkill else Header.NORMAL
            encrypt(args.file, password, mode, args.overwrite)

        else:
            password = getpass.getpass("Password: ").encode()
            decrypt(args.file, password, args.verify, args.overwrite)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
