"""Generate deterministic OLP Wire Canon 0.1 conformance vectors."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reference import semantic_graph_hash, sign_receipt


VALID = ROOT / "vectors" / "valid"
INVALID = ROOT / "vectors" / "invalid"
SPEC_URI = "https://github.com/terryncew/olp-wire-canon"
ALGORITHM_ID = "olp-wire-conformance-0.1"
CANONICALIZATION_ID = "olp-canonical-json-int-v1"
TEST_PRIVATE_KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def common(kind: str, trace_id: str) -> dict:
    return {
        "kind": kind,
        "receipt_version": "0.1",
        "algorithm_id": ALGORITHM_ID,
        "canonicalization_id": CANONICALIZATION_ID,
        "spec_uri": SPEC_URI,
        "trace_id": trace_id,
        "attestation": "self",
        "capture_status": "provisional",
    }


def write(path: Path, value: dict) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="ascii",
    )


def generate() -> list[dict]:
    VALID.mkdir(parents=True, exist_ok=True)
    INVALID.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.from_private_bytes(TEST_PRIVATE_KEY)

    trace_id = "11111111111111111111111111111111"
    trace = sign_receipt(
        {
            **common("trace_receipt", trace_id),
            "capture_loss": False,
            "dropped_span_count": 0,
            "observed_span_count": 2,
            "trace_root": digest("trace-records"),
            "tree_algorithm": "rfc6962-mth-sha256-promote-odd-v1",
            "completion_policy": {
                "type": "root_close_plus_grace",
                "grace_millis": 30000,
                "semconv_schema_id": "otel-genai-development-2026-06",
            },
            "seal_reason": "grace_elapsed",
            "semantic_claims": False,
        },
        key,
    )

    semantic_graph = {
        "claims": [
            {
                "id": "claim_1",
                "content_hash": digest("material claim"),
                "material": True,
            }
        ],
        "evidence": [
            {
                "id": "evidence_1",
                "content_hash": digest("observed evidence bytes"),
                "observed": True,
            }
        ],
        "relations": [
            {
                "src": "evidence_1",
                "dst": "claim_1",
                "relation_type": "supports",
            }
        ],
    }
    signals = [
        {"sequence": 0, "value_micros": 250000},
        {"sequence": 1, "value_micros": 500000},
        {"sequence": 2, "value_micros": 750000},
    ]

    coherence = sign_receipt(
        {
            **common(
                "coherence_input_receipt",
                "22222222222222222222222222222222",
            ),
            "capture_loss": False,
            "dropped_span_count": 0,
            "observed_span_count": 4,
            "trace_root": digest("coherence-trace-records"),
            "tree_algorithm": "rfc6962-mth-sha256-promote-odd-v1",
            "completion_policy": {
                "type": "root_close_plus_grace",
                "grace_millis": 30000,
                "semconv_schema_id": "otel-genai-development-2026-06",
            },
            "seal_reason": "grace_elapsed",
            "semantic_claims": True,
            "typed_event_status": "valid",
            "semantic_graph_hash": semantic_graph_hash(semantic_graph),
            "signal_schema_id": "conformance.normalized-signal.v1",
            "signal_points_micros": [250000, 500000, 750000],
            "state_cap": "white",
        },
        key,
    )

    amendment = sign_receipt(
        {
            **common("amendment_receipt", trace_id),
            "amendment_sequence": 1,
            "previous_receipt_hash": trace["payload_hash"],
            "late_span_hash": digest("late-span-record"),
            "reason": "span_arrived_after_provisional_seal",
        },
        key,
    )

    loss = sign_receipt(
        {
            **common("capture_loss_amendment", trace_id),
            "amendment_sequence": 2,
            "previous_receipt_hash": amendment["payload_hash"],
            "new_dropped_span_count": 3,
            "cumulative_dropped_span_count": 3,
            "reason": "processor_queue_overflow_after_provisional_seal",
        },
        key,
    )

    vectors = [trace, coherence, amendment, loss]
    names = [
        "trace-receipt.json",
        "coherence-input-receipt.json",
        "amendment-receipt.json",
        "capture-loss-amendment.json",
    ]
    for name, vector in zip(names, vectors):
        write(VALID / name, vector)

    write(
        VALID / "coherence-input-disclosure.json",
        {
            "kind": "coherence_input_disclosure",
            "disclosure_version": "0.1",
            "trace_id": coherence["trace_id"],
            "semantic_graph": semantic_graph,
            "signal_schema_id": coherence["signal_schema_id"],
            "signals": signals,
        },
    )

    tampered = copy.deepcopy(coherence)
    tampered["signal_points_micros"][1] = 500001
    write(INVALID / "tampered-coherence-input-receipt.json", tampered)

    broken_chain_body = copy.deepcopy(loss)
    broken_chain_body.pop("payload_hash")
    broken_chain_body.pop("signature")
    broken_chain_body["previous_receipt_hash"] = digest("wrong-parent")
    broken_chain = sign_receipt(broken_chain_body, key)
    write(INVALID / "broken-chain-loss-amendment.json", broken_chain)

    altered_disclosure = {
        "kind": "coherence_input_disclosure",
        "disclosure_version": "0.1",
        "trace_id": coherence["trace_id"],
        "semantic_graph": copy.deepcopy(semantic_graph),
        "signal_schema_id": coherence["signal_schema_id"],
        "signals": copy.deepcopy(signals),
    }
    altered_disclosure["semantic_graph"]["claims"][0]["content_hash"] = digest("altered claim")
    write(INVALID / "altered-coherence-input-disclosure.json", altered_disclosure)
    return vectors


if __name__ == "__main__":
    generated = generate()
    print(f"generated {len(generated)} signed OLP Wire Canon vectors")
