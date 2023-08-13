from hashlib import sha1
import hmac
import time
from math import floor
from pathlib import Path
from util import parse_key_dir
from base64 import b32decode

KEYDIR = Path("./keys")

def get_current_timestep() -> int:
    """
    Gets the current timestep.
    """
    T0 = 0
    TIME_STEP = 30  # time step in seconds
    return floor((time.time() - T0) / TIME_STEP)


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
    return totp_generate(setupkey, get_current_timestep())


if __name__ == "__main__":
    time_step = 30
    prev_step = 0
    epoch_time = 0

    # Load keys
    pin = input("Enter PIN: ")
    keys = parse_key_dir(pin)
    if len(keys) == 0:
        print("No keys detected.")
        exit(1)

    try:
        while True:
            cur_step = get_current_timestep()
            if prev_step < cur_step:
                prev_step = cur_step
                time_str = time.asctime(time.localtime(time.time()))
                timestep = get_current_timestep()

                print(f"Time: {time_str}")
                for label, key in keys.items():
                    key_b = b32decode(key)
                    print(f"---{label}---")
                    print(f"Previous OTP: {totp_generate(key_b, timestep-1):06d}")
                    print(f"Current OTP : {totp_generate(key_b, timestep):06d}")
                    print(f"Next OTP    : {totp_generate(key_b, timestep+1):06d}")
    except KeyboardInterrupt:
        print("\nProgram Ended.")
