// Generates spec/vectors/wallet-v1.json from the reference implementation in wallet.mjs.
// Usage: node spec/tools/gen-wallet-vectors.mjs [--write]
// Without --write the JSON is printed. The RSA keys are derived from public seeds (repeated bytes) and are
// not secret; the file holds the seeds, never a key.
// SPDX-License-Identifier: CC0-1.0
import crypto from "node:crypto";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { deriveRSAKey, certificate, signManifest, checkManifest, bigToBytes } from "./wallet.mjs";

const PASS_TYPE_ID = "pass.dev.healthlog.vector";
const TEAM_ID = "VECTOR1234";
const NOT_BEFORE = new Date("2026-01-01T00:00:00Z");
const NOT_AFTER = new Date("2036-01-01T00:00:00Z");
const SIGNING_TIME = new Date("2026-12-01T10:00:00Z");
const sha1 = (s) => crypto.createHash("sha1").update(s).digest("hex");
const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");

// Pins of the vectors: SHA-1 of a label, standing in for the brand images.
const PINS = Object.fromEntries(["icon.png", "icon@2x.png", "icon@3x.png", "logo@2x.png", "logo@3x.png",
  "primaryLogo@2x.png", "primaryLogo@3x.png", "artwork@2x.png", "artwork@3x.png"].map((p) => [p, [sha1("vector " + p)]]));
const h = (label) => sha1("vector file " + label);

function manifests() {
  const minimal = { "pass.json": h("pass.json"), "icon.png": PINS["icon.png"][0] };
  const full = { "pass.json": h("pass.json") };
  for (const [p, [v]] of Object.entries(PINS)) full[p] = v;
  for (const l of ["de", "en", "es", "fr", "it", "ko", "nl", "pl", "pt-BR", "ru"]) full[`${l}.lproj/pass.strings`] = h(l);
  const many = {};
  for (let i = 0; i < 41; i++) many[`f${i}`] = h(String(i));
  const j = (o) => JSON.stringify(o);
  return [
    ["minimal", j(minimal), "ok"],
    ["full", j(full), "ok"],
    ["full_pretty", JSON.stringify(full, null, 2), "ok"],
    ["foreign_logo", j({ ...minimal, "logo@2x.png": h("another logo") }), "foreign_asset"],
    ["foreign_icon", j({ "pass.json": h("pass.json"), "icon.png": h("another icon") }), "foreign_asset"],
    ["thumbnail", j({ ...minimal, "thumbnail.png": h("t") }), "unknown_file"],
    ["image_in_lproj", j({ ...minimal, "de.lproj/logo@2x.png": PINS["logo@2x.png"][0] }), "unknown_file"],
    ["unknown_locale", j({ ...minimal, "xx.lproj/pass.strings": h("xx") }), "unknown_file"],
    ["personalization", j({ ...minimal, "personalization.json": h("p") }), "unknown_file"],
    ["dot_dot", j({ ...minimal, "../pass.json": h("x") }), "unknown_file"],
    ["absolute", j({ ...minimal, "/pass.json": h("x") }), "unknown_file"],
    ["case_variant", j({ "pass.json": h("pass.json"), "Icon.png": PINS["icon.png"][0], "icon.png": PINS["icon.png"][0] }), "unknown_file"],
    ["logo_1x", j({ ...minimal, "logo.png": h("l") }), "unknown_file"],
    ["missing_icon", j({ "pass.json": h("pass.json") }), "missing_file"],
    ["missing_pass", j({ "icon.png": PINS["icon.png"][0] }), "missing_file"],
    ["duplicate_key", `{"pass.json":"${h("a")}","pass.json":"${h("b")}","icon.png":"${PINS["icon.png"][0]}"}`, "shape"],
    ["upper_hex", j({ ...minimal, "pass.json": h("pass.json").toUpperCase() }), "shape"],
    ["short_hash", j({ ...minimal, "pass.json": "abc" }), "shape"],
    ["number_value", `{"pass.json":1,"icon.png":"${PINS["icon.png"][0]}"}`, "shape"],
    ["array", `["pass.json"]`, "shape"],
    ["trailing", j(minimal) + "x", "shape"],
    ["too_many", j(many), "too_many"],
  ];
}

export function build() {
  const seeds = { root: "11".repeat(32), intermediate: "22".repeat(32), pass: "33".repeat(32) };
  const keys = Object.fromEntries(Object.entries(seeds).map(([k, s]) => [k, deriveRSAKey(Buffer.from(s, "hex"))]));
  const rootName = [["2.5.4.3", "HealthLog Vector Root"], ["2.5.4.10", "HealthLog Vectors"], ["2.5.4.6", "US", true]];
  const interName = [["2.5.4.3", "HealthLog Vector Intermediate"], ["2.5.4.11", "G4"], ["2.5.4.10", "HealthLog Vectors"], ["2.5.4.6", "US", true]];
  const passName = [["0.9.2342.19200300.100.1.1", PASS_TYPE_ID], ["2.5.4.3", "Pass Type ID: " + PASS_TYPE_ID],
    ["2.5.4.11", TEAM_ID], ["2.5.4.10", "HealthLog Vectors"], ["2.5.4.6", "US", true]];
  const base = { notBefore: NOT_BEFORE, notAfter: NOT_AFTER };
  const root = certificate({ ...base, serial: 1, subject: rootName, issuer: rootName, key: keys.root, issuerKey: keys.root, ca: true });
  const inter = certificate({ ...base, serial: 2, subject: interName, issuer: rootName, key: keys.intermediate, issuerKey: keys.root, ca: true });
  const pass = certificate({ ...base, serial: 3, subject: passName, issuer: interName, key: keys.pass, issuerKey: keys.intermediate, ca: false });
  const list = manifests();
  const walletSign = ["minimal", "full"].map((n) => {
    const m = Buffer.from(list.find(([name]) => name === n)[1], "utf8");
    const { attrs, signature } = signManifest(m, keys.pass.privateKey, pass, inter, SIGNING_TIME);
    return { name: n, manifest: m.toString("base64url"), manifestSha256: sha256(m), signingTime: SIGNING_TIME.toISOString(),
      signedAttributes: attrs.toString("hex"), signature: signature.toString("base64url") };
  });
  return {
    format: "healthlog-push-wallet-vectors-v1",
    keyDerivation: "deriveRSAKey in spec/tools/wallet.mjs: 1024-bit candidates from SHA-256(seed || label || uint32be(i)), labels p and q, top two bits and low bit set, next probable prime with gcd(c-1, 65537) = 1, e = 65537",
    seeds,
    moduli: Object.fromEntries(Object.entries(keys).map(([k, v]) => [k, bigToBytes(v.n).toString("hex")])),
    certificates: { root: root.toString("base64url"), intermediate: inter.toString("base64url"), pass: pass.toString("base64url") },
    passTypeIdentifier: PASS_TYPE_ID,
    teamIdentifier: TEAM_ID,
    signerSubjectO: "HealthLog Vectors",
    pins: PINS,
    manifests: list.map(([name, text, expect]) => {
      const got = checkManifest(Buffer.from(text, "utf8"), PINS);
      if (got !== expect) throw new Error(`manifest ${name}: reference says ${got}, vector expects ${expect}`);
      return { name, manifest: text, expect };
    }),
    walletSign,
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const out = JSON.stringify(build(), null, 2) + "\n";
  if (process.argv.includes("--write")) writeFileSync(new URL("../vectors/wallet-v1.json", import.meta.url), out);
  else process.stdout.write(out);
}
