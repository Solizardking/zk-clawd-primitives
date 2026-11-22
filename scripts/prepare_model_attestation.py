"""Prepare the model and payload digests for a Clawd publish attestation."""

import argparse
import hashlib
import json
import re
from pathlib import Path


def prepare(payload_path: Path, artifact_path: Path) -> dict[str, str]:
    raw = payload_path.read_bytes()
    payload = json.loads(raw)
    if not isinstance(payload, dict) or payload.get("protocol") != "CAAP/1.0":
        raise ValueError("expected the CAAP/1.0 payload from a Model Kit preview")
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError("expected Model Kit payload metadata")
    if metadata.get("hash_source") == "generated_from_registration_fields":
        raise ValueError("supply an artifact digest when generating the preview")
    expected = payload.get("model_hash")
    if not isinstance(expected, str) or not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", expected):
        raise ValueError("expected model_hash to contain a full SHA-256 digest")
    with artifact_path.open("rb") as artifact:
        actual = hashlib.file_digest(artifact, "sha256").hexdigest()
    if actual != expected[7:].lower():
        raise ValueError("artifact bytes do not match the registration model_hash")
    return {"modelHash": actual, "payloadCommitment": hashlib.sha256(raw).hexdigest()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("payload", type=Path)
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.payload, args.artifact)))
    except (OSError, ValueError) as exc:
        parser.exit(1, f"{parser.prog}: {exc}\n")
