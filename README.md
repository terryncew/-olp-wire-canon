# OLP Wire Canon 0.1

OLP Wire Canon defines the portable byte-level contract shared by OpenLine
receipt producers and verifiers. It specifies canonical JSON, hashing, signing,
receipt kinds, amendment chaining, and trust labels.

It deliberately does not define COLE metrics, thresholds, calibration, agent
policy, or automatic control. Those are derived layers that may reference an
OLP receipt by its `payload_hash`.

The first conforming implementation is
[`openline-otel`](https://github.com/terryncew/openline-otel). The older OLR 1.5
schemas in `openline-core` are legacy application profiles, not this wire
contract.

## Contents

- `SPEC.md`: normative protocol text.
- `schemas/`: strict JSON Schema 2020-12 receipt profiles.
- `vectors/`: signed receipts, a bound disclosure, and invalid mutations.
- `reference.py`: canonicalization, signing, and verification reference.
- `verify-node.mjs`: independent Node.js verifier.
- `verify-chain-node.mjs`: independent amendment-chain verifier.
- `verify-disclosure-node.mjs`: independent disclosure commitment verifier.
- `scripts/generate_vectors.py`: deterministic conformance vector generator.
- `tests/test_conformance.py`: schema, signature, chaining, and mutation tests.

## Verify

```bash
python -m pip install -e .
python scripts/generate_vectors.py
python -m unittest tests.test_conformance -v
node verify-node.mjs vectors/valid/trace-receipt.json
node verify-node.mjs vectors/valid/coherence-input-receipt.json
node verify-node.mjs vectors/valid/amendment-receipt.json
node verify-node.mjs vectors/valid/capture-loss-amendment.json
node verify-chain-node.mjs vectors/valid/trace-receipt.json vectors/valid/amendment-receipt.json vectors/valid/capture-loss-amendment.json
node verify-disclosure-node.mjs vectors/valid/coherence-input-receipt.json vectors/valid/coherence-input-disclosure.json
```

## Status

Version `0.1-draft` freezes only behavior already exercised by the
`openline-otel` Python/Node release gate. New receipt kinds may be registered
without changing the signed envelope. Breaking byte-level changes require a new
wire version or canonicalization identifier.

The canonical publication location is
`https://github.com/terryncew/olp-wire-canon`. Existing receipts that reference
the earlier `openline-core` URI remain verifiable because the specification URI
is signed provenance, not a network dependency.

## License

MIT License. Copyright 2026 Terrynce White.
