import hmac
from time import time, sleep, asctime, localtime
from math import floor
from hashlib import sha1
from base64 import b32decode
from pathlib import Path
from util import parse_key_dir

from getpass import getpass
from os import system as osystem
from platform import system as psystem

KEYDIR = Path(__file__).parent.joinpath("keys")
TIME_STEP = 30  # timestep in seconds


def clear_screen():
    if psystem() == "Windows":
        osystem("cls")
    else:
        osystem("clear")


def get_timestep(seconds_since_epoch: float = time()) -> int:
    """
    Gets the timestep for the given time
    """
    return floor(seconds_since_epoch / TIME_STEP)


def get_time_left(seconds_since_epoch: float = time()) -> int:
    """
    Gets the number of seconds left in this time step
    """
    return TIME_STEP - int(seconds_since_epoch % TIME_STEP)


def truncate(value: bytes, digits: int = 6) -> int:
    """
    Performs Step 2 (dynamic truncation) and \
        Step 3 (reduction modulo 10^digits) of the HOTP \
            algorithm.

    Inputs:
    - `value`: A 160-bit (20-byte) HMAC-SHA-1 result.
    - `digits`: Number of digits in the OTP.
    """
    if not len(value) == 20:
        raise ValueError("truncate expects a 20-byte value.")

    # low-order 4 bits of the last byte
    offset = value[19] & 0xf

    # obtain dynamic binary code
    byte1 = (value[offset] & 0x7f) << 24  # mask with 0x7f
    byte2 = (value[offset+1] & 0xff) << 16
    byte3 = (value[offset+2] & 0xff) << 8
    byte4 = (value[offset+3] & 0xff)

    dbc = byte1 | byte2 | byte3 | byte4

    # reduction module 10^digits
    hotp = dbc % pow(10, digits)

    return hotp


def hotp_generate(setupkey: bytes, counter: bytes, digits: int = 6) -> int:
    """
    Obtains the OTP associated with `setupkey` and `counter`.

    Defined in RFC4226 (https://www.rfc-editor.org/rfc/rfc4226)

    Inputs:
    - `setupkey`: A bytestring of AT LEAST 128 bits.
    - `counter`: An 8-byte counter value, synchronised \
        between the HOTP generator (client) and the HOTP \
            validator (server).
    - `digits`: Number of digits in the OTP.

    Algorithm:
    `HOTP(key, counter) = Truncate(HMAC-SHA-1(key, counter))`
    """
    # if len(key) < 16:
    #     raise ValueError(f"Key used for HOTP generation should be AT LEAST 128 bits. Key is of length {len(key)}")
    if not len(counter) == 8:
        raise ValueError("Counter expects an 8-byte value.")

    # Generate HMAC-SHA1 value (20 bytes)
    hmac_obj = hmac.new(setupkey, counter, sha1)
    hs = hmac_obj.digest()

    # Truncate hs (31-bit string)
    return truncate(hs, digits)


def totp_generate(setupkey: bytes, t: int, digits: int = 6):
    """
    Generates a time-based OTP based on HOTP.

    Defined in RFC-6238 (https://www.ietf.org/rfc/rfc6238.txt)

    Inputs:
    - `setupkey`: Unique secret for each prover.
    - `t`: Integer representing number of time steps between initial counter T0 and current Unix Time.
    - `digits`: Number of digits in the OTP.
    """
    return hotp_generate(setupkey, t.to_bytes(8, 'big'), digits)


def get_totp(setupkey: bytes):
    return totp_generate(setupkey, get_timestep())


if __name__ == "__main__":
    time_step = 30

    # Load keys
    pin = getpass("Enter PIN: ")
    keys = parse_key_dir(pin)
    if len(keys) == 0:
        print("No keys detected.")
        exit(1)

    try:
        while True:
            clear_screen()
            t = time()
            timestep = get_timestep(t)
            time_left = 0

            if time_left == 0:
                time_left = get_time_left(t)
                for label, key in keys.items():
                    key_b = b32decode(key)
                    print(f"---{label}---")
                    print(f"Previous OTP: {totp_generate(key_b, timestep-1):06d}")
                    print(f"Current OTP : {totp_generate(key_b, timestep):06d}")
                    print(f"Next OTP    : {totp_generate(key_b, timestep+1):06d}")
            else:
                time_left -= 1
            print(f"\n\rTime left: {time_left:02d}")
            sleep(1)

    except KeyboardInterrupt:
        print("\nProgram Ended.")
