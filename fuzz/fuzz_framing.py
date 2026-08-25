"""atheris libFuzzer harness for vynkor.framing.read_frame (T-14, Python half).

Build/run (requires clang, atheris via `pip install atheris`):
    python sdk/python/fuzz/fuzz_framing.py -max_len=1100000

Mirrors sdk/cpp/fuzz/fuzz_framing.cpp: same two paths (no session key, and a
MAC-verifying read against a fixed key) over the same input bytes, exercising
FLAG_COMPRESSED/FLAG_MAC_PRESENT handling and verify_tag without needing a
live socket — read_frame operates on an in-memory io.BytesIO stream.
"""
import io
import os
import sys

import atheris

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

with atheris.instrument_imports():
    from vynkor.framing import read_frame
    from vynkor.errors import VeyronError

FIXED_KEY = bytes(range(32))


def test_one_input(data: bytes) -> None:
    try:
        read_frame(io.BytesIO(data))
    except VeyronError:
        pass  # rejecting malformed input is expected, correct behavior

    try:
        read_frame(io.BytesIO(data), session_key=FIXED_KEY)
    except VeyronError:
        pass


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
