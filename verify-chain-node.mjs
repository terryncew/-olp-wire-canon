import fs from "node:fs";
import { verify } from "./verify-node.mjs";

const paths = process.argv.slice(2);
if (paths.length < 2) {
  throw new Error("usage: node verify-chain-node.mjs INITIAL.json AMENDMENT.json [...]");
}

const receipts = paths.map((path) => JSON.parse(fs.readFileSync(path, "utf8")));
const traceId = receipts[0].trace_id;
let previousHash = verify(receipts[0]);
for (let index = 1; index < receipts.length; index += 1) {
  const receipt = receipts[index];
  verify(receipt);
  if (receipt.trace_id !== traceId) throw new Error("trace mismatch");
  if (receipt.amendment_sequence !== index) throw new Error("amendment sequence mismatch");
  if (receipt.previous_receipt_hash !== previousHash) throw new Error("amendment hash discontinuity");
  previousHash = receipt.payload_hash;
}
console.log(`verified amendment chain length=${receipts.length}`);
