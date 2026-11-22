import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.prepare_model_attestation import prepare


class ModelKitHandoff(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.artifact = Path(temp.name) / "adapter.bin"
        self.payload = Path(temp.name) / "payload.json"
        self.artifact.write_bytes(b"abc")
        self.digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        self.record = {"protocol": "CAAP/1.0", "model_hash": "sha256:" + self.digest,
                       "metadata": {}}

    def test_digests_cover_exact_files(self):
        for indent in (None, 2):
            raw = json.dumps(self.record, indent=indent).encode()
            self.payload.write_bytes(raw)
            self.assertEqual(prepare(self.payload, self.artifact), {
                "modelHash": self.digest, "payloadCommitment": hashlib.sha256(raw).hexdigest()})

    def test_rejects_provisional_malformed_or_mismatched_inputs(self):
        for override in [
            {"metadata": {"hash_source": "generated_from_registration_fields"}},
            {"model_hash": "sha256:abc"},
            {"model_hash": "sha256:" + "0" * 64},
            {"protocol": "other"},
        ]:
            with self.subTest(override=override):
                self.payload.write_text(json.dumps(self.record | override))
                with self.assertRaises(ValueError):
                    prepare(self.payload, self.artifact)
