#!/usr/bin/env python3
"""Generate Python protobuf bindings from ../vynkor-wire/proto/vynkor_protocol.proto."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
PROTO_DIR = ROOT.parent / "vynkor-wire" / "proto"
PROTO = PROTO_DIR / "vynkor_protocol.proto"
OUT = ROOT / "vynkor"

if __name__ == "__main__":
    if not PROTO.exists():
        print(
            f"skip: {PROTO} not found (vynkor-wire not checked out side-by-side); "
            "proto is vendored — re-sync manually when wire changes",
            file=sys.stderr,
        )
        sys.exit(0)
    OUT.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            sys.executable, "-m", "grpc_tools.protoc",
            f"-I{PROTO_DIR}",
            f"--python_out={OUT}",
            str(PROTO),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    print(f"Generated {OUT}/vynkor_protocol_pb2.py")
