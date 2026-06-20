"""Reference canonicalizer and envelope verifier for OLP Wire Canon 0.1."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


MAX_SAFE_INTEGER = (1 << 53) - 1
CANONICALIZATION_ID = "olp-canonical-json-int-v1"
HASH256 = re.compile(r"^[0-9a-f]{64}$")
SIGNATURE_HEX = re.compile(r"^[0-9a-f]{128}$")
TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]+$")

COMMON_FIELDS = {
    "kind",
    "receipt_version",
    "algorithm_id",
    "canonicalization_id",
    "spec_uri",
    "attestation",
    "capture_status",
    "payload_hash",
    "signature",
}
TRACE_FIELDS = {
    "trace_id",
    "capture_loss",
    "dropped_span_count",
    "observed_span_count",
    "trace_root",
    "tree_algorithm",
    "completion_policy",
    "seal_reason",
}
TRACE_OPTIONAL_FIELDS = {"semantic_claims", "typed_event_status", "typed_event_error"}
COHERENCE_FIELDS = TRACE_FIELDS | {
    "semantic_claims",
    "typed_event_status",
    "semantic_graph_hash",
    "signal_schema_id",
    "signal_points_micros",
    "state_cap",
}
AMENDMENT_FIELDS = {
    "trace_id",
    "amendment_sequence",
    "previous_receipt_hash",
    "late_span_hash",
    "reason",
}
LOSS_FIELDS = {
    "trace_id",
    "amendment_sequence",
    "previous_receipt_hash",
    "new_dropped_span_count",
    "cumulative_dropped_span_count",
    "reason",
}


def validate_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if isinstance(value, bool) or abs(value) > MAX_SAFE_INTEGER:
            raise ValueError(f"{path}: integer outside interoperable range")
        return
    if isinstance(value, float):
        raise ValueError(f"{path}: floats are forbidden")
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            validate_value(item, f"{path}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise ValueError(f"{path}: keys must be ASCII strings")
            validate_value(item, f"{path}.{key}")
        return
    raise ValueError(f"{path}: unsupported value type {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    validate_value(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def sign_receipt(body: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    if "payload_hash" in body or "signature" in body:
        raise ValueError("body must not contain envelope fields")
    payload = canonical_json(body)
    public_key = key.public_key().public_bytes_raw().hex()
    return {
        **body,
        "payload_hash": hashlib.sha256(payload).hexdigest(),
        "signature": {
            "algorithm": "Ed25519",
            "public_key": public_key,
            "value": key.sign(payload).hex(),
        },
    }


def _require_exact_fields(value: Mapping[str, Any], required: set[str], allowed: set[str] | None = None) -> None:
    actual = set(value)
    admitted = required if allowed is None else allowed
    missing = required - actual
    unknown = actual - admitted
    if missing or unknown:
        raise ValueError(f"field mismatch: missing={sorted(missing)} unknown={sorted(unknown)}")


def _nonnegative_integer(value: Any, field: str, *, positive: bool = False) -> None:
    minimum = 1 if positive else 0
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"{field} must be an integer >= {minimum}")


def _hash(value: Any, field: str) -> None:
    if not isinstance(value, str) or not HASH256.fullmatch(value):
        raise ValueError(f"{field} must be lowercase SHA-256 hex")


def _completion_policy(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise ValueError("completion_policy must be an object")
    _require_exact_fields(value, {"type", "grace_millis", "semconv_schema_id"})
    if value["type"] != "root_close_plus_grace":
        raise ValueError("unsupported completion policy")
    _nonnegative_integer(value["grace_millis"], "grace_millis")
    if value["grace_millis"] > MAX_SAFE_INTEGER:
        raise ValueError("grace_millis outside interoperable range")
    if not isinstance(value["semconv_schema_id"], str) or not value["semconv_schema_id"]:
        raise ValueError("semconv_schema_id is required")


def validate_profile(receipt: Mapping[str, Any]) -> None:
    """Validate a strict Wire Canon 0.1 receipt-kind profile."""
    validate_value(receipt)
    if not COMMON_FIELDS <= set(receipt):
        raise ValueError("missing signed envelope field")
    if receipt["receipt_version"] != "0.1":
        raise ValueError("unsupported receipt version")
    if receipt["canonicalization_id"] != CANONICALIZATION_ID:
        raise ValueError("unsupported canonicalization profile")
    if receipt["attestation"] != "self" or receipt["capture_status"] != "provisional":
        raise ValueError("unsupported trust profile")
    if not isinstance(receipt["algorithm_id"], str) or not receipt["algorithm_id"] or not receipt["algorithm_id"].isascii():
        raise ValueError("algorithm_id must be non-empty ASCII")
    if not isinstance(receipt["spec_uri"], str) or not receipt["spec_uri"].startswith(("https://", "urn:")):
        raise ValueError("spec_uri must be an HTTPS URI or URN")
    _hash(receipt["payload_hash"], "payload_hash")

    signature = receipt["signature"]
    if not isinstance(signature, Mapping):
        raise ValueError("signature must be an object")
    _require_exact_fields(signature, {"algorithm", "public_key", "value"})
    if signature["algorithm"] != "Ed25519":
        raise ValueError("unsupported signature algorithm")
    if not isinstance(signature["public_key"], str) or not HASH256.fullmatch(signature["public_key"]):
        raise ValueError("public_key must be 32-byte lowercase hex")
    if not isinstance(signature["value"], str) or not SIGNATURE_HEX.fullmatch(signature["value"]):
        raise ValueError("signature value must be 64-byte lowercase hex")

    kind = receipt["kind"]
    if kind == "trace_receipt":
        _require_exact_fields(receipt, COMMON_FIELDS | TRACE_FIELDS, COMMON_FIELDS | TRACE_FIELDS | TRACE_OPTIONAL_FIELDS)
        if "semantic_claims" in receipt and receipt["semantic_claims"] is not False:
            raise ValueError("trace receipts cannot assert semantics")
        if "typed_event_status" in receipt or "typed_event_error" in receipt:
            if receipt["typed_event_status"] != "invalid" or not receipt.get("typed_event_error"):
                raise ValueError("invalid typed events require a signed error")
    elif kind == "coherence_input_receipt":
        _require_exact_fields(receipt, COMMON_FIELDS | COHERENCE_FIELDS)
        if receipt["semantic_claims"] is not True or receipt["typed_event_status"] != "valid":
            raise ValueError("coherence input requires valid explicit semantics")
        _hash(receipt["semantic_graph_hash"], "semantic_graph_hash")
        points = receipt["signal_points_micros"]
        if not isinstance(points, list):
            raise ValueError("signal_points_micros must be an array")
        for point in points:
            if not isinstance(point, int) or isinstance(point, bool) or abs(point) > MAX_SAFE_INTEGER:
                raise ValueError("signal point must be an interoperable integer")
        schema_id = receipt["signal_schema_id"]
        if points and (not isinstance(schema_id, str) or not schema_id):
            raise ValueError("signal schema is required when signal points exist")
        if not points and schema_id is not None:
            raise ValueError("signal schema must be null when no signal points exist")
        if receipt["state_cap"] != "white":
            raise ValueError("wire input state cap must remain white")
    elif kind == "amendment_receipt":
        _require_exact_fields(receipt, COMMON_FIELDS | AMENDMENT_FIELDS)
        _nonnegative_integer(receipt["amendment_sequence"], "amendment_sequence", positive=True)
        _hash(receipt["previous_receipt_hash"], "previous_receipt_hash")
        _hash(receipt["late_span_hash"], "late_span_hash")
        if receipt["reason"] != "span_arrived_after_provisional_seal":
            raise ValueError("unsupported amendment reason")
    elif kind == "capture_loss_amendment":
        _require_exact_fields(receipt, COMMON_FIELDS | LOSS_FIELDS)
        _nonnegative_integer(receipt["amendment_sequence"], "amendment_sequence", positive=True)
        _hash(receipt["previous_receipt_hash"], "previous_receipt_hash")
        _nonnegative_integer(receipt["new_dropped_span_count"], "new_dropped_span_count", positive=True)
        _nonnegative_integer(receipt["cumulative_dropped_span_count"], "cumulative_dropped_span_count", positive=True)
        if receipt["cumulative_dropped_span_count"] < receipt["new_dropped_span_count"]:
            raise ValueError("cumulative loss cannot be smaller than new loss")
        if receipt["reason"] != "processor_queue_overflow_after_provisional_seal":
            raise ValueError("unsupported loss reason")
    else:
        raise ValueError("unknown receipt kind")

    if kind in {"trace_receipt", "coherence_input_receipt"}:
        if not isinstance(receipt["trace_id"], str) or not TRACE_ID.fullmatch(receipt["trace_id"]):
            raise ValueError("trace_id must be 16-byte lowercase hex")
        _nonnegative_integer(receipt["dropped_span_count"], "dropped_span_count")
        _nonnegative_integer(receipt["observed_span_count"], "observed_span_count")
        if not isinstance(receipt["capture_loss"], bool):
            raise ValueError("capture_loss must be boolean")
        if receipt["capture_loss"] is not (receipt["dropped_span_count"] > 0):
            raise ValueError("capture_loss must agree with dropped_span_count")
        _hash(receipt["trace_root"], "trace_root")
        if receipt["tree_algorithm"] != "rfc6962-mth-sha256-promote-odd-v1":
            raise ValueError("unsupported trace tree algorithm")
        _completion_policy(receipt["completion_policy"])
        if receipt["seal_reason"] not in {"grace_elapsed", "shutdown_before_grace_elapsed"}:
            raise ValueError("unsupported seal reason")
    else:
        if not isinstance(receipt["trace_id"], str) or not TRACE_ID.fullmatch(receipt["trace_id"]):
            raise ValueError("trace_id must be 16-byte lowercase hex")


def semantic_graph_hash(graph: Mapping[str, Any]) -> str:
    validate_semantic_graph(graph)
    return hashlib.sha256(canonical_json(graph)).hexdigest()


def validate_semantic_graph(graph: Mapping[str, Any]) -> None:
    if not isinstance(graph, Mapping):
        raise ValueError("semantic_graph must be an object")
    _require_exact_fields(graph, {"claims", "evidence", "relations"})
    if not all(isinstance(graph[field], list) for field in ("claims", "evidence", "relations")):
        raise ValueError("semantic graph groups must be arrays")

    node_types: dict[str, str] = {}
    claim_ids: list[str] = []
    evidence_ids: list[str] = []
    for claim in graph["claims"]:
        if not isinstance(claim, Mapping):
            raise ValueError("claim must be an object")
        _require_exact_fields(claim, {"id", "content_hash", "material"})
        node_id = claim["id"]
        if not isinstance(node_id, str) or not SAFE_ID.fullmatch(node_id) or node_id in node_types:
            raise ValueError("claim id must be safe and globally unique")
        _hash(claim["content_hash"], "claim content_hash")
        if not isinstance(claim["material"], bool):
            raise ValueError("claim material must be boolean")
        node_types[node_id] = "Claim"
        claim_ids.append(node_id)

    for evidence in graph["evidence"]:
        if not isinstance(evidence, Mapping):
            raise ValueError("evidence must be an object")
        _require_exact_fields(evidence, {"id", "content_hash", "observed"})
        node_id = evidence["id"]
        if not isinstance(node_id, str) or not SAFE_ID.fullmatch(node_id) or node_id in node_types:
            raise ValueError("evidence id must be safe and globally unique")
        _hash(evidence["content_hash"], "evidence content_hash")
        if evidence["observed"] is not True:
            raise ValueError("evidence must be directly observed")
        node_types[node_id] = "Evidence"
        evidence_ids.append(node_id)

    if claim_ids != sorted(claim_ids) or evidence_ids != sorted(evidence_ids):
        raise ValueError("semantic graph nodes must be sorted by id")

    relation_keys: list[tuple[str, str, str]] = []
    for relation in graph["relations"]:
        if not isinstance(relation, Mapping):
            raise ValueError("relation must be an object")
        _require_exact_fields(relation, {"src", "dst", "relation_type"})
        src, dst, relation_type = relation["src"], relation["dst"], relation["relation_type"]
        if src not in node_types or dst not in node_types:
            raise ValueError("relation references a missing node")
        if relation_type == "supports":
            if node_types[src] != "Evidence" or node_types[dst] != "Claim":
                raise ValueError("supports must point from Evidence to Claim")
        elif relation_type == "contradicts":
            if node_types[src] != "Claim" or node_types[dst] != "Claim":
                raise ValueError("contradicts must point between Claims")
        elif relation_type == "depends_on":
            if node_types[dst] != "Claim":
                raise ValueError("depends_on must target a Claim")
        else:
            raise ValueError("unsupported relation type")
        relation_keys.append((src, dst, relation_type))

    if len(set(relation_keys)) != len(relation_keys):
        raise ValueError("duplicate relation")
    if relation_keys != sorted(relation_keys):
        raise ValueError("relations must be sorted by src, dst, and relation_type")


def validate_disclosure(disclosure: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    validate_profile(receipt)
    if receipt["kind"] != "coherence_input_receipt" or not verify_receipt(receipt):
        raise ValueError("disclosure requires a valid coherence_input_receipt")
    if not isinstance(disclosure, Mapping):
        raise ValueError("disclosure must be an object")
    _require_exact_fields(
        disclosure,
        {"kind", "disclosure_version", "trace_id", "semantic_graph", "signal_schema_id", "signals"},
    )
    if disclosure["kind"] != "coherence_input_disclosure" or disclosure["disclosure_version"] != "0.1":
        raise ValueError("unsupported disclosure profile")
    if disclosure["trace_id"] != receipt["trace_id"]:
        raise ValueError("disclosure trace mismatch")
    if semantic_graph_hash(disclosure["semantic_graph"]) != receipt["semantic_graph_hash"]:
        raise ValueError("semantic graph commitment mismatch")
    if disclosure["signal_schema_id"] != receipt["signal_schema_id"]:
        raise ValueError("signal schema mismatch")

    signals = disclosure["signals"]
    if not isinstance(signals, list):
        raise ValueError("signals must be an array")
    values: list[int] = []
    for expected_sequence, signal in enumerate(signals):
        if not isinstance(signal, Mapping):
            raise ValueError("signal must be an object")
        _require_exact_fields(signal, {"sequence", "value_micros"})
        if signal["sequence"] != expected_sequence:
            raise ValueError("disclosure signals must be normalized and contiguous")
        value = signal["value_micros"]
        if not isinstance(value, int) or isinstance(value, bool) or abs(value) > MAX_SAFE_INTEGER:
            raise ValueError("signal value must be an interoperable integer")
        values.append(value)
    if values != receipt["signal_points_micros"]:
        raise ValueError("signal commitment mismatch")


def verify_receipt(receipt: Mapping[str, Any]) -> bool:
    try:
        validate_profile(receipt)
        body = dict(receipt)
        signature = body.pop("signature")
        payload_hash = body.pop("payload_hash")
        if body.get("canonicalization_id") != CANONICALIZATION_ID:
            return False
        payload = canonical_json(body)
        if hashlib.sha256(payload).hexdigest() != payload_hash:
            return False
        if signature.get("algorithm") != "Ed25519":
            return False
        key_bytes = bytes.fromhex(signature["public_key"])
        signature_bytes = bytes.fromhex(signature["value"])
        if len(key_bytes) != 32 or len(signature_bytes) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(signature_bytes, payload)
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False


def verify_chain(receipts: list[Mapping[str, Any]]) -> bool:
    if not receipts or not verify_receipt(receipts[0]):
        return False
    trace_id = receipts[0].get("trace_id")
    previous_hash = receipts[0].get("payload_hash")
    for sequence, receipt in enumerate(receipts[1:], start=1):
        if not verify_receipt(receipt):
            return False
        if receipt.get("trace_id") != trace_id:
            return False
        if receipt.get("amendment_sequence") != sequence:
            return False
        if receipt.get("previous_receipt_hash") != previous_hash:
            return False
        previous_hash = receipt.get("payload_hash")
    return True
