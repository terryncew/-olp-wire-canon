from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from reference import (
    canonical_json,
    validate_disclosure,
    validate_profile,
    verify_chain,
    verify_receipt,
)
from scripts.generate_vectors import generate


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
VALID = ROOT / "vectors" / "valid"
INVALID = ROOT / "vectors" / "invalid"
def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="ascii"))


def validate(receipt: dict) -> None:
    validate_profile(receipt)


class WireCanonConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        generate()

    def test_valid_vectors_pass_schema_and_signature(self):
        for path in sorted(VALID.glob("*.json")):
            with self.subTest(path=path.name):
                receipt = read(path)
                if receipt.get("kind") == "coherence_input_disclosure":
                    continue
                validate(receipt)
                self.assertTrue(verify_receipt(receipt))

    def test_schema_documents_are_valid_json(self):
        schemas = [read(path) for path in sorted(SCHEMAS.glob("*.json"))]
        self.assertEqual(len(schemas), 6)
        self.assertTrue(all(schema["$schema"] == "https://json-schema.org/draft/2020-12/schema" for schema in schemas))

    def test_released_openline_otel_vector_conforms(self):
        receipt = read(VALID / "openline-otel-conformance.json")
        validate(receipt)
        self.assertTrue(verify_receipt(receipt))

    def test_tampered_payload_is_rejected(self):
        receipt = read(INVALID / "tampered-coherence-input-receipt.json")
        validate(receipt)
        self.assertFalse(verify_receipt(receipt))

    def test_coherence_disclosure_reproduces_signed_commitments(self):
        receipt = read(VALID / "coherence-input-receipt.json")
        disclosure = read(VALID / "coherence-input-disclosure.json")
        validate_disclosure(disclosure, receipt)

    def test_altered_coherence_disclosure_is_rejected(self):
        receipt = read(VALID / "coherence-input-receipt.json")
        disclosure = read(INVALID / "altered-coherence-input-disclosure.json")
        with self.assertRaises(ValueError):
            validate_disclosure(disclosure, receipt)

    def test_valid_amendment_chain(self):
        chain = [
            read(VALID / "trace-receipt.json"),
            read(VALID / "amendment-receipt.json"),
            read(VALID / "capture-loss-amendment.json"),
        ]
        self.assertTrue(verify_chain(chain))

    def test_broken_amendment_chain_is_rejected(self):
        chain = [
            read(VALID / "trace-receipt.json"),
            read(VALID / "amendment-receipt.json"),
            read(INVALID / "broken-chain-loss-amendment.json"),
        ]
        self.assertFalse(verify_chain(chain))

    def test_trust_label_cannot_be_silently_upgraded(self):
        receipt = read(VALID / "trace-receipt.json")
        receipt["attestation"] = "gateway"
        with self.assertRaises(Exception):
            validate(receipt)

    def test_canonical_profile_rejects_floats_and_large_integers(self):
        with self.assertRaises(ValueError):
            canonical_json({"value": 0.5})
        with self.assertRaises(ValueError):
            canonical_json({"value": 9007199254740992})

    def test_unknown_field_requires_profile_revision(self):
        receipt = copy.deepcopy(read(VALID / "trace-receipt.json"))
        receipt["new_field"] = "not admitted by profile 0.1"
        with self.assertRaises(Exception):
            validate(receipt)


if __name__ == "__main__":
    unittest.main()
