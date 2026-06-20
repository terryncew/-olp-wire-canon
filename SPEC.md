# OpenLine Protocol Wire Canon 0.1

Status: Draft

Canon ID: `olp-wire-0.1-draft`

Canonicalization ID: `olp-canonical-json-int-v1`

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, NOT RECOMMENDED, MAY, and OPTIONAL are to be interpreted as
described in BCP 14 when, and only when, they appear in all capitals.

## 1. Scope

This document defines how an OpenLine receipt is serialized, hashed, signed,
verified, and linked to earlier receipts. It defines four capture-layer receipt
kinds:

- `trace_receipt`
- `coherence_input_receipt`
- `amendment_receipt`
- `capture_loss_amendment`

It does not define whether an observed claim is true, whether capture was
complete, how COLE computes a measurement, or whether a controller may act.

## 2. Receipt envelope

A receipt is one JSON object. The signed body is the receipt after removing
exactly two top-level members: `payload_hash` and `signature`.

The body MUST contain:

- `kind`
- `receipt_version`
- `algorithm_id`
- `canonicalization_id`
- `spec_uri`
- `attestation`
- `capture_status`

`payload_hash` MUST be lowercase hexadecimal SHA-256 over the canonical JSON
bytes of the body.

`signature` MUST contain:

```json
{
  "algorithm": "Ed25519",
  "public_key": "32-byte-lowercase-hex",
  "value": "64-byte-lowercase-hex"
}
```

The Ed25519 signature MUST be computed directly over the canonical body bytes,
not over `payload_hash` and not over the complete envelope.

## 3. Canonical JSON

`olp-canonical-json-int-v1` accepts only JSON null, booleans, strings, arrays,
objects, and integers in the inclusive range
`[-9007199254740991, 9007199254740991]`.

Floats and non-finite numbers are forbidden. Object keys MUST be ASCII strings.
Duplicate keys MUST be rejected by the parser before canonicalization.

Canonical output MUST:

1. sort object keys by ascending ASCII code point;
2. contain no insignificant whitespace;
3. encode non-ASCII string characters with lowercase JSON `\u` escapes;
4. use the shortest JSON escapes for quote, reverse solidus, and the standard
   control escapes;
5. encode the final byte sequence as ASCII.

Telemetry values outside this domain MUST be normalized before they enter a
committed record. The OTel capture profile uses:

- `{"$int":"<canonical decimal>"}` for integers outside the safe range;
- `{"$f64":"<16 lowercase hex characters>"}` for finite IEEE-754 binary64
  values encoded in network byte order.

Signed receipt bodies themselves MUST remain valid canonical JSON values.

## 4. Hash and identifier encoding

SHA-256 values MUST be 64 lowercase hexadecimal characters. Ed25519 public keys
MUST be 64 lowercase hexadecimal characters. Ed25519 signatures MUST be 128
lowercase hexadecimal characters.

Trace identifiers in the OTel profile MUST be 32 lowercase hexadecimal
characters. Span identifiers MUST be 16 lowercase hexadecimal characters.

### 4.1 OTel trace tree

For `rfc6962-mth-sha256-promote-odd-v1`, the OTel profile orders disclosed span
records by `(start_time_unix_nano, span_id)`. Each leaf is
`SHA-256(0x00 || canonical_json(record))`. Each complete pair is
`SHA-256(0x01 || left || right)`. An unpaired node is promoted unchanged to the
next level. The empty root is `SHA-256` of the empty byte string.

The compact receipt carries only `trace_root`. Span records remain outside the
receipt unless an auditor requests disclosure.

## 5. Trust semantics

Wire Canon 0.1 defines one attestation value: `self`.

`self` means the receipt reports what the signer says it observed. Signature
verification proves possession of the signing key and integrity after signing.
It does not prove that capture was complete, that source events were true, or
that the signer was independent from the system being observed.

Wire Canon 0.1 defines one capture status: `provisional`.

Root closure, a grace interval, process separation, or use of an OpenTelemetry
Collector MUST NOT silently upgrade either trust label. A stronger attestation
profile requires a future canon extension defining key control, routing
enforcement, and verifier requirements.

## 6. Initial capture receipts

### 6.1 `trace_receipt`

A `trace_receipt` commits observed trace structure without assigning semantic
meaning to ordinary telemetry. Its `trace_root` is defined by the declared
`tree_algorithm`. The OTel 0.1 profile uses
`rfc6962-mth-sha256-promote-odd-v1`.

If typed OpenLine events are absent, `semantic_claims`, when present, MUST be
false. If typed events are invalid, the receipt MUST remain a `trace_receipt`
and SHOULD carry a signed validation status and error. A producer MUST NOT infer
missing claims, evidence, relations, or signals from ordinary span text.

### 6.2 `coherence_input_receipt`

A `coherence_input_receipt` is an admission receipt for an explicitly typed
semantic graph. It is not a COLE measurement.

It MUST carry `semantic_claims: true`, `typed_event_status: valid`, a
`semantic_graph_hash`, integer `signal_points_micros`, and `state_cap: white`.
Its typed event profile MUST reject duplicate node identifiers, missing relation
targets, mixed signal schemas, sequence gaps, malformed content hashes, and
floating-point signal values.

The receipt MAY contain no signal points. In that case `signal_schema_id` MUST
be null and downstream measurement remains unavailable.

### 6.3 Coherence input disclosure

The graph itself does not travel inside the compact signed receipt. A producer
MAY provide a `coherence_input_disclosure` sidecar when a verifier or COLE
implementation needs to recompute the admitted input.

The sidecar is not independently trusted. A consumer MUST verify all of the
following against a valid `coherence_input_receipt`:

1. `trace_id` is identical;
2. SHA-256 over canonical JSON of `semantic_graph` equals
   `semantic_graph_hash`;
3. `signal_schema_id` is identical;
4. disclosed signal values, ordered by normalized zero-based `sequence`, equal
   `signal_points_micros`.

Claims, evidence, and relations MUST use the exact typed event fields defined by
the disclosure schema. Node identifiers MUST be globally unique. Relations MUST
reference existing nodes. `supports` MUST point from Evidence to Claim;
`contradicts` MUST point between Claims; `depends_on` MUST target a Claim.
Duplicate relations are forbidden.

Possession of a valid disclosure proves correspondence to the signed
commitment. It does not prove that the disclosed claims or evidence are true.

## 7. Amendments

An initial receipt is immutable. Information observed after provisional sealing
MUST NOT rewrite it.

Every amendment MUST include a positive `amendment_sequence` and
`previous_receipt_hash`. Sequence 1 references the initial receipt's
`payload_hash`. Each later amendment references the immediately preceding
amendment's `payload_hash`. A verifier MUST reject a gap, duplicate sequence, or
hash discontinuity.

`amendment_receipt` commits a late observed span through `late_span_hash`.
`capture_loss_amendment` commits newly reported and cumulative dropped-span
counts. Loss accounting applies only to the identified trace.

An amendment extends the record. It does not retroactively make the initial
capture complete.

## 8. Derived layers

A COLE measurement receipt, controller proposal, governance decision, or other
derived artifact MUST be signed separately from its input receipt. It SHOULD
reference the input `payload_hash` and identify its own algorithm and profile.

Derived layers MUST NOT change the capture receipt's body, trust label, or
capture status. COLE metric equations, calibration profiles, thresholds, and
actuation rules are outside Wire Canon 0.1.

## 9. Versioning and extensions

`receipt_version` versions a receipt-kind profile. `algorithm_id` identifies the
algorithm that produced profile-specific commitments. `canonicalization_id`
identifies the byte serialization contract.

Adding an OPTIONAL body member requires a new receipt-kind profile version when
strict schemas would otherwise reject it. Changing canonicalization, signature
coverage, hash encoding, or amendment linkage is a breaking wire change.

Unknown receipt kinds MUST NOT be treated as verified merely because their
signature is valid. A verifier MAY report envelope integrity while refusing
profile conformance.

## 10. Conformance

A conforming implementation MUST:

1. reproduce canonical body bytes for every valid vector;
2. reproduce each `payload_hash`;
3. verify every valid Ed25519 signature;
4. reject each invalid mutation;
5. validate receipt-kind structure against the applicable schema;
6. verify amendment order and hash continuity.

Cross-language agreement is REQUIRED. Passing only a same-language signer and
verifier is insufficient for a conformance claim.
