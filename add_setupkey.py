from pathlib import Path
from util import create_key_file
from base64 import b32decode
from binascii import Error as BinAsciiError
from getpass import getpass

KEYDIR = Path(__file__).parent.joinpath("keys")

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
    pin_accepted = False
    pin = 0000

    while not pin_accepted:
        pin = getpass("PIN: ")
        pin_r = getpass("Repeat PIN: ")
        if pin == pin_r:
            pin_accepted = True
        else:
            print("PINs don't match, try again.")

    keyfile = create_key_file(pin, label, setupkey)
    print(f"Keyfile created at: {str(keyfile)}")


