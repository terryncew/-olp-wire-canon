import fs from "node:fs";
import crypto from "node:crypto";
import { canonical, verify } from "./verify-node.mjs";

const [receiptPath, disclosurePath] = process.argv.slice(2);
if (!receiptPath || !disclosurePath) {
  throw new Error("usage: node verify-disclosure-node.mjs RECEIPT.json DISCLOSURE.json");
}

const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
const disclosure = JSON.parse(fs.readFileSync(disclosurePath, "utf8"));
verify(receipt);
if (receipt.kind !== "coherence_input_receipt") throw new Error("wrong receipt kind");
if (disclosure.kind !== "coherence_input_disclosure") throw new Error("wrong disclosure kind");
if (disclosure.trace_id !== receipt.trace_id) throw new Error("trace mismatch");

const graphHash = crypto.createHash("sha256")
  .update(Buffer.from(canonical(disclosure.semantic_graph), "ascii"))
  .digest("hex");
if (graphHash !== receipt.semantic_graph_hash) throw new Error("semantic graph commitment mismatch");
if (disclosure.signal_schema_id !== receipt.signal_schema_id) throw new Error("signal schema mismatch");

const values = disclosure.signals.map((signal, index) => {
  if (signal.sequence !== index) throw new Error("signal sequence mismatch");
  if (!Number.isSafeInteger(signal.value_micros)) throw new Error("non-interoperable signal value");
  return signal.value_micros;
});
if (JSON.stringify(values) !== JSON.stringify(receipt.signal_points_micros)) {
  throw new Error("signal commitment mismatch");
}
console.log(`verified coherence disclosure ${graphHash}`);
