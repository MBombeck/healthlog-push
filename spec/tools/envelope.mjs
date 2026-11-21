// HealthLog push envelope v1: reference seal and open (spec/envelope.md).
// HPKE (RFC 9180) mode_auth, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, node:crypto only.
// The functions are the same as in reference/hpke-proof.mjs, exported for the vector generator and checker.
// SPDX-License-Identifier: CC0-1.0
import crypto from "node:crypto";

export const hex = (b) => Buffer.from(b).toString("hex");
export const unhex = (s) => Buffer.from(s.replace(/\s+/g, ""), "hex");
const i2osp = (n, len) => { const b = Buffer.alloc(len); b.writeUIntBE(n, 0, len); return b; };
const extract = (salt, ikm) => crypto.createHmac("sha256", salt.length ? salt : Buffer.alloc(32)).update(ikm).digest();
const expand = (prk, info, L) => {
  let t = Buffer.alloc(0), out = Buffer.alloc(0);
  for (let i = 1; out.length < L; i++) {
    t = crypto.createHmac("sha256", prk).update(Buffer.concat([t, info, Buffer.from([i])])).digest();
    out = Buffer.concat([out, t]);
  }
  return out.subarray(0, L);
};
const V1 = Buffer.from("HPKE-v1");
const KEM_SUITE = Buffer.concat([Buffer.from("KEM"), i2osp(0x20, 2)]);
const HPKE_SUITE = Buffer.concat([Buffer.from("HPKE"), i2osp(0x20, 2), i2osp(1, 2), i2osp(3, 2)]);
const lExtract = (suite, salt, label, ikm) => extract(salt, Buffer.concat([V1, suite, Buffer.from(label), ikm]));
const lExpand = (suite, prk, label, info, L) => expand(prk, Buffer.concat([i2osp(L, 2), V1, suite, Buffer.from(label), info]), L);
const NONCE_LABEL = "base_" + "nonce";
export const MODE = { base: 0x00, auth: 0x02 };

const X25519_SPKI = unhex("302a300506032b656e032100");
const X25519_PKCS8 = unhex("302e020100300506032b656e04220420");
const ED25519_PKCS8 = unhex("302e020100300506032b657004220420");
const pub = (raw) => crypto.createPublicKey({ key: Buffer.concat([X25519_SPKI, raw]), format: "der", type: "spki" });
const priv = (raw) => crypto.createPrivateKey({ key: Buffer.concat([X25519_PKCS8, raw]), format: "der", type: "pkcs8" });
export const x25519Public = (raw) => crypto.createPublicKey(priv(raw)).export({ format: "der", type: "spki" }).subarray(12);
const dh = (sk, pk) => crypto.diffieHellman({ privateKey: priv(sk), publicKey: pub(pk) });
const extractAndExpand = (dhBytes, kemContext) =>
  lExpand(KEM_SUITE, lExtract(KEM_SUITE, Buffer.alloc(0), "eae_prk", dhBytes), "shared_secret", kemContext, 32);

export function encap(pkR, skE) {
  const enc = x25519Public(skE);
  return { enc, shared: extractAndExpand(dh(skE, pkR), Buffer.concat([enc, pkR])) };
}
export function authEncap(pkR, skE, skS) {
  const enc = x25519Public(skE);
  const pkS = x25519Public(skS);
  return { enc, shared: extractAndExpand(Buffer.concat([dh(skE, pkR), dh(skS, pkR)]), Buffer.concat([enc, pkR, pkS])) };
}
export function authDecap(enc, skR, pkS) {
  const pkR = x25519Public(skR);
  return extractAndExpand(Buffer.concat([dh(skR, enc), dh(skR, pkS)]), Buffer.concat([enc, pkR, pkS]));
}
export function schedule(mode, shared, info) {
  const pskIdHash = lExtract(HPKE_SUITE, Buffer.alloc(0), "psk_id_hash", Buffer.alloc(0));
  const infoHash = lExtract(HPKE_SUITE, Buffer.alloc(0), "info_hash", info);
  const ctx = Buffer.concat([Buffer.from([mode]), pskIdHash, infoHash]);
  const secret = lExtract(HPKE_SUITE, shared, "secret", Buffer.alloc(0));
  return { key: lExpand(HPKE_SUITE, secret, "key", ctx, 32), nonce: lExpand(HPKE_SUITE, secret, NONCE_LABEL, ctx, 12) };
}
export function aeadSeal(key, nonce, aad, pt) {
  const c = crypto.createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  c.setAAD(aad, { plaintextLength: pt.length });
  return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
}
export function aeadOpen(key, nonce, aad, ct) {
  const d = crypto.createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  d.setAAD(aad, { plaintextLength: ct.length - 16 });
  d.setAuthTag(ct.subarray(ct.length - 16));
  return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
}

export const INFO = Buffer.from("HealthLog push envelope v1");
export const VERSION = 0x01;
export const SUITE = 0x01;
export const CLASS = { alert: 0x01, silent: 0x02 };
// 0x03 is reserved for sealed Live Activity content. Version 1 defines no bucket for it and never seals or
// opens it: Live Activity ends travel as a fixed template without an envelope (spec/envelope.md, "Format").
export const RESERVED_CLASS = { liveactivity: 0x03 };
export const BUCKET = { alert: 1024, silent: 1024 };
export const MAX_TTL = { alert: 6 * 3600, silent: 3600 };
export const CLOCK_SKEW = 300;
export const HEADER_LEN = 3, ENC_LEN = 32, TAG_LEN = 16;
export const envelopeLength = (cls) => HEADER_LEN + ENC_LEN + BUCKET[cls] + TAG_LEN;
export const sha = (...parts) => crypto.createHash("sha256").update(Buffer.concat(parts)).digest();
export const tokenTagOf = (tok) => sha(Buffer.from("hl-push-token"), tok).subarray(0, 16);
export const keyIdOf = (pk) => sha(Buffer.from("hl-push-key"), pk).subarray(0, 8);

export class EnvelopeError extends Error { constructor(code) { super(code); this.code = code; } }

export const LOW_ORDER = [
  "00".repeat(32), "01" + "00".repeat(31),
  "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
  "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
].map(unhex);

export function validateRecipientKey(pk) {
  if (!Buffer.isBuffer(pk) || pk.length !== 32) return false;
  try {
    const probe = crypto.generateKeyPairSync("x25519").privateKey;
    const s = crypto.diffieHellman({ privateKey: probe, publicKey: pub(pk) });
    return !s.every((b) => b === 0);
  } catch { return false; }
}

export function buildPadded(pushClass, json) {
  const body = Buffer.from(JSON.stringify(json), "utf8");
  const size = BUCKET[pushClass];
  if (body.length + 2 > size) throw new Error("payload exceeds bucket");
  const padded = Buffer.alloc(size);
  padded.writeUInt16BE(body.length, 0);
  body.copy(padded, 2);
  return padded;
}

// Test vectors only: the ephemeral key is injected so the output is deterministic. A production sealer must
// generate a fresh ephemeral key for every call and must not accept one from the caller.
export function sealWithInjectedEphemeralForVectors({ pkR, skS, apnsToken, pushClass, json, skE, padded }) {
  if (!validateRecipientKey(pkR)) throw new EnvelopeError("invalidRecipientKey");
  const pt = padded ?? buildPadded(pushClass, json);
  const header = Buffer.from([VERSION, SUITE, CLASS[pushClass]]);
  const aad = Buffer.concat([header, tokenTagOf(apnsToken)]);
  const { enc, shared } = authEncap(pkR, skE, skS);
  const k = schedule(MODE.auth, shared, INFO);
  return { envelope: Buffer.concat([header, enc, aeadSeal(k.key, k.nonce, aad, pt)]), aad, padded: pt };
}

const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });
const ID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;
export function open({ recipientKeys, trustedSenders, apnsToken, envelope, expectedClass, now, replayStore }) {
  if (envelope.length < HEADER_LEN + ENC_LEN + TAG_LEN + 2) throw new EnvelopeError("malformed");
  if (envelope[0] !== VERSION || envelope[1] !== SUITE) throw new EnvelopeError("unsupportedVersion");
  if (envelope[2] !== CLASS[expectedClass]) throw new EnvelopeError("classMismatch");
  if (envelope.length !== envelopeLength(expectedClass)) throw new EnvelopeError("malformed");
  const header = envelope.subarray(0, HEADER_LEN);
  const enc = envelope.subarray(HEADER_LEN, HEADER_LEN + ENC_LEN);
  const ct = envelope.subarray(HEADER_LEN + ENC_LEN);
  const aad = Buffer.concat([header, tokenTagOf(apnsToken)]);
  let pt = null;
  for (const skR of recipientKeys) {
    for (const pkS of trustedSenders) {
      try {
        const k = schedule(MODE.auth, authDecap(enc, skR, pkS), INFO);
        pt = aeadOpen(k.key, k.nonce, aad, ct);
      } catch { /* not this pair */ }
      if (pt) break;
    }
    if (pt) break;
  }
  if (!pt) throw new EnvelopeError("authFailure");
  const len = pt.readUInt16BE(0);
  if (len === 0 || len + 2 > pt.length) throw new EnvelopeError("malformed");
  if (!pt.subarray(2 + len).every((b) => b === 0)) throw new EnvelopeError("malformed");
  let json;
  try { json = JSON.parse(STRICT_UTF8.decode(pt.subarray(2, 2 + len))); } catch { throw new EnvelopeError("malformed"); }
  if (!json || typeof json !== "object" || json.v !== 1 || typeof json.t !== "string" || typeof json.id !== "string"
      || !ID_RE.test(json.id) || !Number.isInteger(json.iat) || !Number.isInteger(json.exp)) throw new EnvelopeError("malformed");
  if (json.exp <= json.iat || json.exp - json.iat > MAX_TTL[expectedClass]) throw new EnvelopeError("lifetimeTooLong");
  if (json.iat > now + CLOCK_SKEW) throw new EnvelopeError("notYetValid");
  if (now > json.exp + CLOCK_SKEW) throw new EnvelopeError("expired");
  if (replayStore) replayStore.checkAndRecord(json.id, json.exp, now);
  return json;
}

// Ed25519 helpers for the statement vectors. Seeds are fixed, repeated bytes; Ed25519 signatures are deterministic.
export const edKeyFromSeed = (seed) => crypto.createPrivateKey({ key: Buffer.concat([ED25519_PKCS8, seed]), format: "der", type: "pkcs8" });
export const edPublicRaw = (sk) => crypto.createPublicKey(sk).export({ format: "der", type: "spki" }).subarray(12);
export const edSign = (sk, text) => crypto.sign(null, Buffer.from(text, "utf8"), sk);
export const edVerify = (pkRaw, text, sig) => {
  try {
    const pk = crypto.createPublicKey({ key: Buffer.concat([unhex("302a300506032b6570032100"), pkRaw]), format: "der", type: "spki" });
    return crypto.verify(null, Buffer.from(text, "utf8"), pk, sig);
  } catch { return false; }
};
