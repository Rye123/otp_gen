from pathlib import Path
from util import create_key_file
from base64 import b32decode
from binascii import Error as BinAsciiError

KEYDIR = Path("./keys")

if __name__ == "__main__":
    KEYDIR.mkdir(exist_ok=True)
    if not KEYDIR.is_dir():
        raise Exception("Ensure ./keys is a directory.")

    label = input("Enter the label to be associated with the key: ")
    setupkey = input("Enter the setup key: ").upper()
    if ' ' in setupkey:
        setupkey = ''.join(setupkey.split(' '))

    try:
        b32decode(setupkey)
    except BinAsciiError:
        raise Exception("Invalid setup key.")

    print("Enter a PIN to be associated with this setup key. This CAN be unique for each setup key, but it's easier "
          "if you keep it the same.")
    pin = input("PIN: ")

    create_key_file(pin, label, setupkey)


