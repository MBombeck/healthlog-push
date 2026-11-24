// Cross-checks spec/vectors/v1.json:
// 1. The file equals what gen-vectors.mjs produces (no hand edits, deterministic output).
// 2. The reference proof (reference/hpke-proof.mjs) passes, including RFC 9180 A.2.1 and A.2.3, and its alert
//    envelope (SHA-256, AAD, lengths) is byte-identical to the "alert" vector here.
// 3. Every envelope vector opens or fails with its recorded code; every statement signature verifies and every
//    negative statement fails.
// 4. spec/vectors/wallet-v1.json equals what gen-wallet-vectors.mjs produces, every manifest gets its recorded
//    answer, and every walletSign signature verifies over its signed attributes with the pass key.
// Usage: node spec/tools/check-vectors.mjs   (exit code 1 on any failure)
// SPDX-License-Identifier: CC0-1.0
import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { build } from "./gen-vectors.mjs";
import { open, unhex, sha, hex, edVerify, tokenTagOf } from "./envelope.mjs";
import { build as buildWallet } from "./gen-wallet-vectors.mjs";
import { checkManifest, signedAttributes } from "./wallet.mjs";

let failed = 0;
const check = (name, ok) => { if (!ok) { failed++; console.error("FAIL", name); } };

const onDisk = readFileSync(new URL("../vectors/v1.json", import.meta.url), "utf8");
check("file matches generator output", onDisk === JSON.stringify(build(), null, 2) + "\n");
const v = JSON.parse(onDisk);

const proof = execFileSync(process.execPath, [fileURLToPath(new URL("./reference/hpke-proof.mjs", import.meta.url))], { encoding: "utf8" });
check("reference proof passes", proof.trimEnd().endsWith("all checks passed"));
const summary = JSON.parse(proof.slice(proof.lastIndexOf("\n{") + 1, proof.lastIndexOf("}") + 1));
const alert = Buffer.from(v.envelopes.find((e) => e.name === "alert").envelope, "base64url");
check("alert envelope sha256 equals reference", hex(sha(alert)) === summary.envelopeSha256);
check("alert aad equals reference", v.aad.alert === summary.aad);
check("alert length equals reference", alert.length === summary.envelopeLength);
check("no envelope vector uses the reserved live activity class", v.envelopes.every((e) => e.expectedClass !== "liveactivity"));
check("sender public key equals reference", v.keys.senderPublicKey === summary.senderPublicKey);
check("recipient public key equals reference", v.keys.recipientPublicKey === summary.recipientPublicKey);

for (const e of v.envelopes) {
  let got = "ok";
  try {
    open({ recipientKeys: e.recipientKeys.map(unhex), trustedSenders: e.trustedSenders.map(unhex), apnsToken: unhex(e.apnsToken),
      envelope: Buffer.from(e.envelope, "base64url"), expectedClass: e.expectedClass, now: e.now });
  } catch (err) { got = err.code ?? err.message; }
  check(`envelope ${e.name} -> ${e.expect}`, got === e.expect);
}
for (const t of v.tokenTags) check(`tokenTag ${t.token.slice(0, 4)}`, hex(tokenTagOf(unhex(t.token))) === t.tokenTag);
const byName = Object.fromEntries(v.statements.map((s) => [s.name, s]));
for (const s of v.statements) check(`statement ${s.name}`, edVerify(Buffer.from(s.publicKey, "base64url"), s.text, Buffer.from(s.signature, "base64url")));
for (const n of v.negativeStatements) {
  const s = byName[n.of];
  check(`negative statement ${n.name}`, !edVerify(Buffer.from(s.publicKey, "base64url"), n.text, Buffer.from(s.signature, "base64url")));
}

const walletOnDisk = readFileSync(new URL("../vectors/wallet-v1.json", import.meta.url), "utf8");
check("wallet file matches generator output", walletOnDisk === JSON.stringify(buildWallet(), null, 2) + "\n");
const w = JSON.parse(walletOnDisk);
for (const m of w.manifests) check(`wallet manifest ${m.name} -> ${m.expect}`, checkManifest(Buffer.from(m.manifest, "utf8"), w.pins) === m.expect);
const passCert = new crypto.X509Certificate(Buffer.from(w.certificates.pass, "base64url"));
const interCert = new crypto.X509Certificate(Buffer.from(w.certificates.intermediate, "base64url"));
const rootCert = new crypto.X509Certificate(Buffer.from(w.certificates.root, "base64url"));
check("wallet chain verifies", passCert.verify(interCert.publicKey) && interCert.verify(rootCert.publicKey) && rootCert.verify(rootCert.publicKey));
for (const s of w.walletSign) {
  const manifest = Buffer.from(s.manifest, "base64url");
  const attrs = signedAttributes(manifest, new Date(s.signingTime));
  check(`walletSign ${s.name} attributes`, attrs.toString("hex") === s.signedAttributes);
  const der = Buffer.from(s.signature, "base64url");
  const sig = der.subarray(der.length - 256);
  check(`walletSign ${s.name} signature verifies`, crypto.verify("sha256", attrs, passCert.publicKey, sig));
}

if (failed) { console.error(`${failed} check(s) failed`); process.exit(1); }
console.log(`vectors ok: ${v.envelopes.length} envelopes, ${v.statements.length} statements, ${v.negativeStatements.length} negative statements, ${w.manifests.length} wallet manifests, ${w.walletSign.length} wallet signatures`);
