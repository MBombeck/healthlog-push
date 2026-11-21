// Proof of concept for the HealthLog push envelope v1 (reference implementation):
// HPKE (RFC 9180) mode_auth, DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/ChaCha20-Poly1305, node:crypto only.
// 1. Checks RFC 9180 A.2.1 (base) and A.2.3 (auth) byte for byte.
// 2. Seals and opens the v3 envelope: 3-byte header (no key ids), exp in the plaintext, strict parser,
//    replay store sized to the device quota, ephemeral key generated internally.
// 3. Regression cases from the security and red-team probes (low-order points, ephemeral reuse,
//    header linkability, padding, UTF-8, JSON, off-by-one lengths, AAD class binding, replay).
// 4. Protocol checks for the v3 additions: device-signed binding (proof of possession), direct opt-out,
//    activity statement for the Live Activity token, signed relay responses, request signature scope.
// Run: node hpke-proof.mjs   (exit code 1 on any failed check)
import crypto from "node:crypto";

const hex = (b) => Buffer.from(b).toString("hex");
const unhex = (s) => Buffer.from(s.replace(/\s+/g, ""), "hex");
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
const MODE = { base: 0x00, auth: 0x02 };

const X25519_SPKI = unhex("302a300506032b656e032100");
const X25519_PKCS8 = unhex("302e020100300506032b656e04220420");
const pub = (raw) => crypto.createPublicKey({ key: Buffer.concat([X25519_SPKI, raw]), format: "der", type: "spki" });
const priv = (raw) => crypto.createPrivateKey({ key: Buffer.concat([X25519_PKCS8, raw]), format: "der", type: "pkcs8" });
const rawPub = (k) => crypto.createPublicKey(k).export({ format: "der", type: "spki" }).subarray(12);
const rawPriv = (k) => k.export({ format: "der", type: "pkcs8" }).subarray(16);
const dh = (sk, pk) => crypto.diffieHellman({ privateKey: priv(sk), publicKey: pub(pk) });
const extractAndExpand = (dhBytes, kemContext) =>
  lExpand(KEM_SUITE, lExtract(KEM_SUITE, Buffer.alloc(0), "eae_prk", dhBytes), "shared_secret", kemContext, 32);

// RFC 9180 4.1: Encap/Decap (base) and AuthEncap/AuthDecap (auth).
function encap(pkR, skE) {
  const enc = rawPub(priv(skE));
  return { enc, shared: extractAndExpand(dh(skE, pkR), Buffer.concat([enc, pkR])) };
}
function decap(enc, skR) {
  const pkR = rawPub(priv(skR));
  return extractAndExpand(dh(skR, enc), Buffer.concat([enc, pkR]));
}
function authEncap(pkR, skE, skS) {
  const enc = rawPub(priv(skE));
  const pkS = rawPub(priv(skS));
  const dhBytes = Buffer.concat([dh(skE, pkR), dh(skS, pkR)]);
  return { enc, shared: extractAndExpand(dhBytes, Buffer.concat([enc, pkR, pkS])) };
}
function authDecap(enc, skR, pkS) {
  const pkR = rawPub(priv(skR));
  const dhBytes = Buffer.concat([dh(skR, enc), dh(skR, pkS)]);
  return extractAndExpand(dhBytes, Buffer.concat([enc, pkR, pkS]));
}
function schedule(mode, shared, info) {
  const pskIdHash = lExtract(HPKE_SUITE, Buffer.alloc(0), "psk_id_hash", Buffer.alloc(0));
  const infoHash = lExtract(HPKE_SUITE, Buffer.alloc(0), "info_hash", info);
  const ctx = Buffer.concat([Buffer.from([mode]), pskIdHash, infoHash]);
  const secret = lExtract(HPKE_SUITE, shared, "secret", Buffer.alloc(0));
  return { key: lExpand(HPKE_SUITE, secret, "key", ctx, 32), nonce: lExpand(HPKE_SUITE, secret, NONCE_LABEL, ctx, 12) };
}
function aeadSeal(key, nonce, aad, pt) {
  const c = crypto.createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  c.setAAD(aad, { plaintextLength: pt.length });
  return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
}
function aeadOpen(key, nonce, aad, ct) {
  const d = crypto.createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  d.setAAD(aad, { plaintextLength: ct.length - 16 });
  d.setAuthTag(ct.subarray(ct.length - 16));
  return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
}

let allOk = true;
const report = (name, checks) => {
  console.log(name, checks);
  if (!Object.values(checks).every((v) => v === true)) allOk = false;
};
const RFC_INFO = unhex("4f6465206f6e2061204772656369616e2055726e");
const RFC_PT = unhex("4265617574792069732074727574682c20747275746820626561757479");
const RFC_AAD = unhex("436f756e742d30");

// --- RFC 9180 A.2.1 (base), sequence 0 ---
{
  const v = {
    skEm: unhex("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600"),
    pkRm: unhex("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a"),
    skRm: unhex("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb"),
    enc: "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
    shared: "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
    key: "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
    nonce: "5c4d98150661b848853b547f",
    ct: "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
  };
  const e = encap(v.pkRm, v.skEm);
  const ks = schedule(MODE.base, e.shared, RFC_INFO);
  const ct = aeadSeal(ks.key, ks.nonce, RFC_AAD, RFC_PT);
  report("RFC 9180 A.2.1 base:", {
    enc: hex(e.enc) === v.enc, shared: hex(e.shared) === v.shared, decap: hex(decap(e.enc, v.skRm)) === v.shared,
    key: hex(ks.key) === v.key, nonce: hex(ks.nonce) === v.nonce, ct: hex(ct) === v.ct,
    open: hex(aeadOpen(ks.key, ks.nonce, RFC_AAD, ct)) === hex(RFC_PT),
  });
}

// --- RFC 9180 A.2.3 (auth), sequence 0 ---
{
  const v = {
    skEm: unhex("c94619e1af28971c8fa7957192b7e62a71ca2dcdde0a7cc4a8a9e741d600ab13"),
    pkRm: unhex("1a478716d63cb2e16786ee93004486dc151e988b34b475043d3e0175bdb01c44"),
    skRm: unhex("3ca22a6d1cda1bb9480949ec5329d3bf0b080ca4c45879c95eddb55c70b80b82"),
    pkSm: unhex("f0f4f9e96c54aeed3f323de8534fffd7e0577e4ce269896716bcb95643c8712b"),
    skSm: unhex("2def0cb58ffcf83d1062dd085c8aceca7f4c0c3fd05912d847b61f3e54121f05"),
    enc: "f7674cc8cd7baa5872d1f33dbaffe3314239f6197ddf5ded1746760bfc847e0e",
    shared: "d2d67828c8bc9fa661cf15a31b3ebf1febe0cafef7abfaaca580aaf6d471e3eb",
    key: "b071fd1136680600eb447a845a967d35e9db20749cdf9ce098bcc4deef4b1356",
    nonce: "d20577dff16d7cea2c4bf780",
    ct: "ab1a13c9d4f01a87ec3440dbd756e2677bd2ecf9df0ce7ed73869b98e00c09be111cb9fdf077347aeb88e61bdf",
  };
  const e = authEncap(v.pkRm, v.skEm, v.skSm);
  const ks = schedule(MODE.auth, e.shared, RFC_INFO);
  const ct = aeadSeal(ks.key, ks.nonce, RFC_AAD, RFC_PT);
  report("RFC 9180 A.2.3 auth:", {
    pkS: hex(rawPub(priv(v.skSm))) === hex(v.pkSm),
    enc: hex(e.enc) === v.enc, shared: hex(e.shared) === v.shared,
    authDecap: hex(authDecap(e.enc, v.skRm, v.pkSm)) === v.shared,
    key: hex(ks.key) === v.key, nonce: hex(ks.nonce) === v.nonce, ct: hex(ct) === v.ct,
    open: hex(aeadOpen(ks.key, ks.nonce, RFC_AAD, ct)) === hex(RFC_PT),
  });
}

// ===================================================================================================
// HealthLog push envelope v1 (spec/envelope.md)
// Header: version(1) suite(1) class(1) = 3 bytes, then enc(32), then ciphertext+tag. No key ids on the wire:
// the KEM context binds pkR and pkS, the device tries its (at most 2) own keys x (at most 2) pinned senders.
// AAD = header ‖ tokenTag(16) = 19 bytes.
// Plaintext = uint16 length ‖ UTF-8 JSON ‖ zero padding to the class bucket. JSON carries v, t, id, iat, exp.
// ===================================================================================================
const INFO = Buffer.from("HealthLog push envelope v1");
const VERSION = 0x01;
const SUITE_AUTH_X25519_CHACHA = 0x01;
const CLASS = { alert: 0x01, background: 0x02, liveactivity: 0x03 };
const BUCKET = { alert: 1024, background: 1024, liveactivity: 512 };
const MAX_TTL = { alert: 6 * 3600, background: 3600, liveactivity: 4 * 3600 }; // seconds, equals the class deadline
const CLOCK_SKEW = 300; // seconds tolerated for iat in the future and after exp
const HEADER_LEN = 3;
const ENC_LEN = 32;
const TAG_LEN = 16;
const envelopeLength = (cls) => HEADER_LEN + ENC_LEN + BUCKET[cls] + TAG_LEN;
const sha = (...parts) => crypto.createHash("sha256").update(Buffer.concat(parts)).digest();
const tokenTagOf = (tok) => sha(Buffer.from("hl-push-token"), tok).subarray(0, 16);
const keyIdOf = (pk) => sha(Buffer.from("hl-push-key"), pk).subarray(0, 8); // API and UI only, never on the wire

class EnvelopeError extends Error { constructor(code) { super(code); this.code = code; } }

// Known X25519 points of small order (RFC 7748 / libsodium blocklist subset) plus all-zero.
const LOW_ORDER = [
  "00".repeat(32), "01" + "00".repeat(31),
  "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
  "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
].map(unhex);

// Server side, POST /api/devices: reject a device key that is not 32 bytes or fails a probe derivation.
function validateRecipientKey(pk) {
  if (!Buffer.isBuffer(pk) || pk.length !== 32) return false;
  try {
    const probe = crypto.generateKeyPairSync("x25519").privateKey;
    const s = crypto.diffieHellman({ privateKey: probe, publicKey: pub(pk) });
    return !s.every((b) => b === 0);
  } catch { return false; }
}

function buildPadded(pushClass, json) {
  const body = Buffer.from(JSON.stringify(json), "utf8");
  const size = BUCKET[pushClass];
  if (body.length + 2 > size) throw new Error("payload exceeds bucket");
  const padded = Buffer.alloc(size);
  padded.writeUInt16BE(body.length, 0);
  body.copy(padded, 2);
  return padded;
}

// Test-only: deterministic seal with an injected ephemeral key, for golden vectors. In the server this lives
// under __tests__ and a structural test forbids importing it elsewhere (spec/envelope.md).
function __sealWithEphemeralForVectorsOnly({ pkR, skS, apnsToken, pushClass, json, skE, padded }) {
  if (!validateRecipientKey(pkR)) throw new EnvelopeError("invalidRecipientKey");
  const pt = padded ?? buildPadded(pushClass, json);
  const header = Buffer.from([VERSION, SUITE_AUTH_X25519_CHACHA, CLASS[pushClass]]);
  const aad = Buffer.concat([header, tokenTagOf(apnsToken)]);
  const { enc, shared } = authEncap(pkR, skE, skS);
  const k = schedule(MODE.auth, shared, INFO);
  return { envelope: Buffer.concat([header, enc, aeadSeal(k.key, k.nonce, aad, pt)]), aad, padded: pt, header };
}

// Public seal: never accepts an ephemeral key, always generates a fresh one. A retry resends the finished
// envelope, it never re-seals.
function seal(args) {
  if ("skE" in args) throw new Error("ephemeral key injection not allowed");
  const skE = rawPriv(crypto.generateKeyPairSync("x25519").privateKey);
  return __sealWithEphemeralForVectorsOnly({ ...args, skE });
}

// Replay store: holds each id until its exp + skew. Capacity is sized above the device day quota (300), so a
// valid id can never be evicted while it can still be opened. Full or unreadable store => placeholder, no side effects.
class ReplayStore {
  constructor(capacity = 512) { this.capacity = capacity; this.m = new Map(); }
  prune(now) { for (const [id, exp] of this.m) if (exp + CLOCK_SKEW < now) this.m.delete(id); }
  checkAndRecord(id, exp, now) {
    this.prune(now);
    if (this.m.has(id)) throw new EnvelopeError("replayed");
    if (this.m.size >= this.capacity) throw new EnvelopeError("replayStoreFull");
    this.m.set(id, exp);
  }
}

const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });
const ID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/; // ULID
// recipientKeys: the device's current and (during rotation) previous private keys for this account.
// trustedSenders: the pinned sender keys (current and previous) for this account, from the push keychain group.
function open({ recipientKeys, trustedSenders, apnsToken, envelope, expectedClass, now, replayStore }) {
  if (envelope.length < HEADER_LEN + ENC_LEN + TAG_LEN + 2) throw new EnvelopeError("malformed");
  if (envelope[0] !== VERSION || envelope[1] !== SUITE_AUTH_X25519_CHACHA) throw new EnvelopeError("unsupportedVersion");
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
      } catch { /* DH failure (low-order enc) and AEAD failure both mean: not this pair */ }
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
const expectError = (fn) => { try { fn(); return "none"; } catch (e) { return e.code ?? e.message; } };

// Fixed, obviously synthetic test material (repeated bytes, never real keys or tokens).
const skR = unhex("a8".repeat(32)), pkR = rawPub(priv(skR));
const skR2 = unhex("a9".repeat(32)), pkR2 = rawPub(priv(skR2)); // device key of the previous rotation period
const skS = unhex("c3".repeat(32)), pkS = rawPub(priv(skS));
const skSprev = unhex("c4".repeat(32)), pkSprev = rawPub(priv(skSprev));
const skX = unhex("d4".repeat(32)), pkX = rawPub(priv(skX)); // some other instance
const skE = unhex("5e".repeat(32));
const apnsToken = unhex("0f".repeat(32));
const NOW = 1795000000;
const id = (n) => "01JTESTVECT" + String(n).padStart(15, "0");
const alertJson = {
  v: 1, t: "MEDICATION_INTAKE_RECORDED", id: id(1), iat: NOW, exp: NOW + 7200,
  d: { medicationId: "cm_test_med_1", slot: { id: "slot_test_1", scheduledAt: "2026-11-21T07:00:00Z" }, takenAt: "2026-11-21T07:12:00Z", source: "API" },
  n: { title: "Test medication", body: "Recorded at 07:12" },
  ui: { category: "MEDICATION_INTAKE_RECORDED", thread: "med-test", level: "passive" },
};
const silentJson = { v: 1, t: "SYNC", id: id(2), iat: NOW, exp: NOW + 3600, d: { scope: ["medications", "schedule"], syncedAt: "2026-11-21T07:12:00Z" } };
const laJson = { v: 1, t: "LA_UPDATE", id: id(3), iat: NOW, exp: NOW + 7200, d: { status: "pending" } };

const V = (args) => __sealWithEphemeralForVectorsOnly({ pkR, skS, apnsToken, skE, ...args });
const s = V({ pushClass: "alert", json: alertJson });
const sSilent = V({ pushClass: "background", json: silentJson });
const sLa = V({ pushClass: "liveactivity", json: laJson });
const O = (envelope, extra = {}) => expectError(() => open({
  recipientKeys: [skR], trustedSenders: [pkS], apnsToken, envelope, expectedClass: "alert", now: NOW, ...extra,
}));
const openOk = (envelope, extra = {}) => open({ recipientKeys: [skR], trustedSenders: [pkS], apnsToken, envelope, expectedClass: "alert", now: NOW, ...extra });

// Authenticated envelopes with a crafted padded plaintext (for parser cases).
const craft = (padded, cls = "alert") => V({ pushClass: cls, padded }).envelope;
const craftJson = (obj) => craft(buildPadded("alert", obj));
const flip = (buf, i) => { const c = Buffer.from(buf); c[i] ^= 0x01; return c; };
const withEnc = (buf, encBytes) => { const c = Buffer.from(buf); encBytes.copy(c, HEADER_LEN); return c; };

// --- positive cases ---
const maxBody = (() => { // body of exactly bucket-2 bytes, ending with a multibyte character
  const base = { v: 1, t: "X", id: id(9), iat: NOW, exp: NOW + 60, n: { body: "" } };
  const fixed = Buffer.byteLength(JSON.stringify(base), "utf8");
  const room = BUCKET.alert - 2 - fixed - 2; // reserve 2 bytes for the trailing "ü"
  base.n.body = "a".repeat(room) + "ü";
  return base;
})();
report("Envelope v1 positive:", {
  alertRoundtrip: JSON.stringify(openOk(s.envelope)) === JSON.stringify(alertJson),
  silentRoundtrip: JSON.stringify(openOk(sSilent.envelope, { expectedClass: "background" })) === JSON.stringify(silentJson),
  liveActivityRoundtrip: JSON.stringify(openOk(sLa.envelope, { expectedClass: "liveactivity" })) === JSON.stringify(laJson),
  alertLength: s.envelope.length === 1075,
  liveActivityLength: sLa.envelope.length === 563,
  previousSenderAccepted: O(__sealWithEphemeralForVectorsOnly({ pkR, skS: skSprev, apnsToken, skE, pushClass: "alert", json: alertJson }).envelope,
    { trustedSenders: [pkS, pkSprev] }) === "none",
  previousRecipientKeyAccepted: O(__sealWithEphemeralForVectorsOnly({ pkR: pkR2, skS, apnsToken, skE, pushClass: "alert", json: alertJson }).envelope,
    { recipientKeys: [skR, skR2] }) === "none",
  exactBucketWithMultibyteEnd: Buffer.byteLength(JSON.stringify(maxBody)) === BUCKET.alert - 2
    && O(V({ pushClass: "alert", json: maxBody }).envelope) === "none",
  oneByteOverBucketRefused: expectError(() => V({ pushClass: "alert", json: { ...maxBody, n: { body: maxBody.n.body + "a" } } })) === "payload exceeds bucket",
});

// --- negative cases (expected error code per case; these become spec/vectors/v1.json negatives) ---
const ZERO_PADDING_DIRTY = (() => { const p = Buffer.from(s.padded); p[p.length - 1] = 0x41; return p; })();
const LEN_ZERO = Buffer.alloc(BUCKET.alert);
const LEN_OVERFLOW = (() => { const p = Buffer.alloc(BUCKET.alert); p.writeUInt16BE(0xffff, 0); return p; })();
const BAD_JSON = (() => { const p = Buffer.alloc(BUCKET.alert); p.writeUInt16BE(3, 0); p.write("{x:", 2); return p; })();
const BAD_UTF8 = (() => { const p = Buffer.alloc(BUCKET.alert); p.writeUInt16BE(4, 0); Buffer.from([0x22, 0xff, 0xfe, 0x22]).copy(p, 2); return p; })();
const classTampered = (() => { const c = Buffer.from(sSilent.envelope); c[2] = CLASS.alert; return c; })(); // silent envelope relabelled as alert
const negatives = {
  wrongToken: [O(s.envelope, { apnsToken: unhex("10".repeat(32)) }), "authFailure"],
  wrongClassPath: [O(s.envelope, { expectedClass: "background" }), "classMismatch"],
  classByteTamperedOnMatchingPath: [O(classTampered), "authFailure"],
  unknownVersion: [O(flip(s.envelope, 0)), "unsupportedVersion"],
  unknownSuite: [O(flip(s.envelope, 1)), "unsupportedVersion"],
  untrustedSender: [O(s.envelope, { trustedSenders: [pkX] }), "authFailure"],
  forgedSender: [O(__sealWithEphemeralForVectorsOnly({ pkR, skS: skX, apnsToken, skE, pushClass: "alert", json: alertJson }).envelope), "authFailure"],
  sealedToOtherDevice: [O(__sealWithEphemeralForVectorsOnly({ pkR: pkX, skS, apnsToken, skE, pushClass: "alert", json: alertJson }).envelope), "authFailure"],
  tamperedCiphertext: [O(flip(s.envelope, 100)), "authFailure"],
  tamperedTag: [O(flip(s.envelope, s.envelope.length - 1)), "authFailure"],
  tamperedEnc: [O(flip(s.envelope, HEADER_LEN + 5)), "authFailure"],
  lowOrderEncZero: [O(withEnc(s.envelope, LOW_ORDER[0])), "authFailure"],
  lowOrderEncPoint: [O(withEnc(s.envelope, LOW_ORDER[2])), "authFailure"],
  truncated60: [O(s.envelope.subarray(0, 60)), "malformed"],
  oneByteShort: [O(s.envelope.subarray(0, s.envelope.length - 1)), "malformed"],
  oneByteLong: [O(Buffer.concat([s.envelope, Buffer.from([0])])), "malformed"],
  lengthPrefixOverflow: [O(craft(LEN_OVERFLOW)), "malformed"],
  lengthZero: [O(craft(LEN_ZERO)), "malformed"],
  nonZeroPadding: [O(craft(ZERO_PADDING_DIRTY)), "malformed"],
  invalidJson: [O(craft(BAD_JSON)), "malformed"],
  invalidUtf8: [O(craft(BAD_UTF8)), "malformed"],
  missingExp: [O(craftJson({ v: 1, t: "X", id: id(20), iat: NOW })), "malformed"],
  badIdFormat: [O(craftJson({ v: 1, t: "X", id: "a", iat: NOW, exp: NOW + 60 })), "malformed"],
  unknownSchemaVersion: [O(craftJson({ v: 2, t: "X", id: id(21), iat: NOW, exp: NOW + 60 })), "malformed"],
  lifetimeTooLong: [O(craftJson({ v: 1, t: "X", id: id(22), iat: NOW, exp: NOW + MAX_TTL.alert + 1 })), "lifetimeTooLong"],
  expired: [O(s.envelope, { now: alertJson.exp + CLOCK_SKEW + 1 }), "expired"],
  notYetValid: [O(s.envelope, { now: NOW - CLOCK_SKEW - 1 }), "notYetValid"],
};
report("Envelope v1 negatives:", Object.fromEntries(Object.entries(negatives).map(([k, [got, want]]) => [k, got === want])));

// --- replay window sized to volume (security M1, red team B11) ---
{
  const store = new ReplayStore(512);
  const first = openOk(s.envelope, { replayStore: store });
  const replayImmediately = O(s.envelope, { replayStore: store });
  // 300 further pushes in one day (device day quota) do not evict the first id while it is still valid.
  let t = NOW;
  for (let i = 0; i < 300; i++) {
    t = NOW + Math.floor((i * 7000) / 300); // spread over less than the alert lifetime
    store.checkAndRecord(id(1000 + i), t + 3600, t);
  }
  const replayAfter300 = O(s.envelope, { replayStore: store, now: alertJson.exp });
  // Once exp + skew has passed the id is pruned, but the envelope is refused as expired anyway.
  const afterExpiry = O(s.envelope, { replayStore: store, now: alertJson.exp + CLOCK_SKEW + 1 });
  const full = new ReplayStore(2);
  full.checkAndRecord(id(5000), NOW + 60, NOW); full.checkAndRecord(id(5001), NOW + 60, NOW);
  report("Replay store:", {
    firstOpens: first.id === alertJson.id,
    replayImmediately: replayImmediately === "replayed",
    replayAfter300Pushes: replayAfter300 === "replayed",
    afterExpiryRefusedAsExpired: afterExpiry === "expired",
    fullStoreRefusesWithoutSideEffect: O(sSilent.envelope, { expectedClass: "background", replayStore: full }) === "replayStoreFull",
    capacityAboveDeviceQuota: new ReplayStore().capacity > 300,
  });
}

// --- ephemeral key handling (security M3) ---
{
  const a = seal({ pkR, skS, apnsToken, pushClass: "alert", json: alertJson });
  const b = seal({ pkR, skS, apnsToken, pushClass: "alert", json: alertJson });
  // Why injection is banned: same skE for the same recipient => same key and nonce => ct1 ^ ct2 == pt1 ^ pt2.
  const s2 = V({ pushClass: "alert", json: { ...alertJson, id: id(2), n: { title: "Other", body: "Other" } } });
  const x = Buffer.alloc(BUCKET.alert);
  for (let i = 0; i < x.length; i++) x[i] = s.envelope[HEADER_LEN + ENC_LEN + i] ^ s2.envelope[HEADER_LEN + ENC_LEN + i] ^ s.padded[i] ^ s2.padded[i];
  report("Ephemeral key:", {
    publicSealRefusesInjection: expectError(() => seal({ pkR, skS, apnsToken, pushClass: "alert", json: alertJson, skE })) === "ephemeral key injection not allowed",
    freshEncPerSeal: !a.envelope.subarray(HEADER_LEN, HEADER_LEN + ENC_LEN).equals(b.envelope.subarray(HEADER_LEN, HEADER_LEN + ENC_LEN)),
    freshCiphertextPerSeal: !a.envelope.equals(b.envelope),
    publicSealOpens: O(a.envelope) === "none",
    reuseWouldLeakXor_reasonForBan: x.every((v) => v === 0),
  });
}

// --- low-order recipient keys (red team B9, security N2) ---
report("Recipient key validation:", {
  ...Object.fromEntries(LOW_ORDER.map((p, i) => [`lowOrder${i}Rejected`, validateRecipientKey(p) === false])),
  shortKeyRejected: validateRecipientKey(Buffer.alloc(31, 1)) === false,
  validKeyAccepted: validateRecipientKey(pkR) === true,
  sealToLowOrderRefused: expectError(() => seal({ pkR: LOW_ORDER[2], skS, apnsToken, pushClass: "alert", json: alertJson })) === "invalidRecipientKey",
});

// --- header linkability (red team B3, security N4) ---
{
  const devB = rawPub(priv(unhex("b1".repeat(32))));
  const fromA1 = seal({ pkR, skS, apnsToken, pushClass: "alert", json: alertJson });
  const fromA2 = seal({ pkR: devB, skS, apnsToken: unhex("1f".repeat(32)), pushClass: "alert", json: alertJson });
  const fromOther = seal({ pkR, skS: skX, apnsToken, pushClass: "alert", json: alertJson });
  const hdr = (e) => hex(e.envelope.subarray(0, HEADER_LEN));
  report("Header linkability:", {
    headerIsOnlyVersionSuiteClass: hdr(fromA1) === "010101",
    sameHeaderAcrossDevicesOfOneInstance: hdr(fromA1) === hdr(fromA2),
    sameHeaderAcrossInstances: hdr(fromA1) === hdr(fromOther),
    noSenderKeyIdBytesOnWire: !fromA1.envelope.includes(sha(Buffer.from("hl-push-sender"), pkS).subarray(0, 8)),
    noRecipientKeyIdBytesOnWire: !fromA1.envelope.includes(keyIdOf(pkR)),
  });
}

// ===================================================================================================
// Protocol checks (spec/statements.md): Ed25519 statements.
// ===================================================================================================
const ed = () => crypto.generateKeyPairSync("ed25519");
const edRaw = (k) => k.export({ format: "der", type: "spki" }).subarray(12);
const sign = (sk, text) => crypto.sign(null, Buffer.from(text), sk);
const verify = (pk, text, sig) => { try { return crypto.verify(null, Buffer.from(text), pk, sig); } catch { return false; } };
const RELAY_HOST = "push.healthlog.dev";
const bindText = ({ instanceId, tokenTag, kind, seq, iat }) => ["hl-bind-v1", RELAY_HOST, instanceId, hex(tokenTag), kind, seq, iat].join("\n");
const unbindText = ({ instanceId, tokenTag, iat }) => ["hl-unbind-v1", RELAY_HOST, instanceId, hex(tokenTag), iat].join("\n");
const activityText = ({ instanceId, tokenTag, laTokenTag, iat }) => ["hl-activity-v1", RELAY_HOST, instanceId, hex(tokenTag), hex(laTokenTag), iat].join("\n");

// Minimal relay binding model: token_mac -> { instanceId, keyHash, seq }; blocked pairs after a device opt-out.
class RelayBindings {
  constructor() { this.b = new Map(); this.blocked = new Set(); }
  bind({ tokenMac, instanceId, bindingKey, stmt, sig, now }) {
    if (Math.abs(now - stmt.iat) > CLOCK_SKEW) return "stale";
    if (stmt.instanceId !== instanceId) return "forbidden";
    if (!verify(bindingKey, bindText(stmt), sig)) return "forbidden";
    if (this.blocked.has(`${tokenMac}|${instanceId}`)) return "forbidden";
    const keyHash = hex(sha(edRaw(bindingKey)));
    const cur = this.b.get(tokenMac);
    if (cur && cur.keyHash !== keyHash) return "conflict"; // resolved by challenge push, never by "last writer wins"
    if (cur && stmt.seq <= cur.seq) return "forbidden";
    this.b.set(tokenMac, { instanceId, keyHash, seq: stmt.seq });
    return "bound";
  }
  unbindSelf({ tokenMac, bindingKey, stmt, sig, now }) { // direct from the app, no instance involved
    const cur = this.b.get(tokenMac);
    if (!cur || Math.abs(now - stmt.iat) > CLOCK_SKEW) return "forbidden";
    if (cur.keyHash !== hex(sha(edRaw(bindingKey))) || !verify(bindingKey, unbindText(stmt), sig)) return "forbidden";
    this.b.delete(tokenMac);
    this.blocked.add(`${tokenMac}|${stmt.instanceId}`);
    return "unbound";
  }
  activityEnd({ tokenMac, instanceId, bindingKey, stmt, sig, now }) {
    const cur = this.b.get(tokenMac);
    if (!cur || cur.instanceId !== instanceId || stmt.instanceId !== instanceId) return "forbidden";
    if (cur.keyHash !== hex(sha(edRaw(bindingKey))) || !verify(bindingKey, activityText(stmt), sig)) return "forbidden";
    if (now - stmt.iat > MAX_TTL.liveactivity + 8 * 3600) return "forbidden"; // statement older than activity lifetime
    return "accepted";
  }
}
{
  const device = ed();          // binding key of the app installation (push keychain group)
  const oldInstanceKey = ed();  // an attacker who knows the token, but not the device key
  const rb = new RelayBindings();
  const tokenTag = tokenTagOf(apnsToken);
  const tokenMac = hex(crypto.createHmac("sha256", Buffer.alloc(32, 7)).update(apnsToken).digest());
  const st = (instanceId, seq, iat = NOW) => ({ instanceId, tokenTag, kind: "device", seq, iat });
  const r1 = rb.bind({ tokenMac, instanceId: "inst-A", bindingKey: device.publicKey, stmt: st("inst-A", 1), sig: sign(device.privateKey, bindText(st("inst-A", 1))), now: NOW });
  // The old instance replays the device's earlier statement for itself: instance id is signed, so it fails.
  const replayOther = rb.bind({ tokenMac, instanceId: "inst-B", bindingKey: device.publicKey, stmt: st("inst-A", 1), sig: sign(device.privateKey, bindText(st("inst-A", 1))), now: NOW });
  // The old instance signs with its own key: conflict, the existing binding stays.
  const ownKey = rb.bind({ tokenMac, instanceId: "inst-B", bindingKey: oldInstanceKey.publicKey, stmt: st("inst-B", 9), sig: sign(oldInstanceKey.privateKey, bindText(st("inst-B", 9))), now: NOW });
  // Legitimate move by the device to instance C with a higher seq.
  const move = rb.bind({ tokenMac, instanceId: "inst-C", bindingKey: device.publicKey, stmt: st("inst-C", 2), sig: sign(device.privateKey, bindText(st("inst-C", 2))), now: NOW });
  // Replay of the old seq-1 statement for inst-A after the move: refused.
  const replayOld = rb.bind({ tokenMac, instanceId: "inst-A", bindingKey: device.publicKey, stmt: st("inst-A", 1), sig: sign(device.privateKey, bindText(st("inst-A", 1))), now: NOW });
  const staleStmt = rb.bind({ tokenMac, instanceId: "inst-C", bindingKey: device.publicKey, stmt: st("inst-C", 3, NOW - 3600), sig: sign(device.privateKey, bindText(st("inst-C", 3, NOW - 3600))), now: NOW });
  const bindingAfterMove = rb.b.get(tokenMac)?.instanceId;
  // Activity statement: device signs the Live Activity token at activity start, the server keeps it and passes it
  // with the end push. The relay never sees the activity token before the end.
  const laTokenTag = tokenTagOf(unhex("2e".repeat(32)));
  const act = { instanceId: "inst-C", tokenTag, laTokenTag, iat: NOW };
  const actOk = rb.activityEnd({ tokenMac, instanceId: "inst-C", bindingKey: device.publicKey, stmt: act, sig: sign(device.privateKey, activityText(act)), now: NOW + 3600 });
  const actForged = rb.activityEnd({ tokenMac, instanceId: "inst-C", bindingKey: device.publicKey, stmt: { ...act, laTokenTag: tokenTagOf(unhex("3e".repeat(32))) }, sig: sign(device.privateKey, activityText(act)), now: NOW + 3600 });
  const actOtherInstance = rb.activityEnd({ tokenMac, instanceId: "inst-B", bindingKey: device.publicKey, stmt: { ...act, instanceId: "inst-B" }, sig: sign(device.privateKey, activityText({ ...act, instanceId: "inst-B" })), now: NOW + 3600 });
  // Direct opt-out from the device (ex-partner case): only the device key can do it, and the pair stays blocked.
  const un = { instanceId: "inst-C", tokenTag, iat: NOW };
  const unByInstance = rb.unbindSelf({ tokenMac, bindingKey: oldInstanceKey.publicKey, stmt: un, sig: sign(oldInstanceKey.privateKey, unbindText(un)), now: NOW });
  const unByDevice = rb.unbindSelf({ tokenMac, bindingKey: device.publicKey, stmt: un, sig: sign(device.privateKey, unbindText(un)), now: NOW });
  const rebindBlocked = rb.bind({ tokenMac, instanceId: "inst-C", bindingKey: device.publicKey, stmt: st("inst-C", 5), sig: sign(device.privateKey, bindText(st("inst-C", 5))), now: NOW });
  report("Device-signed binding:", {
    firstBindingTofu: r1 === "bound",
    otherInstanceCannotReuseStatement: replayOther === "forbidden",
    otherInstanceOwnKeyIsConflictNotTakeover: ownKey === "conflict",
    deviceCanMove: move === "bound" && bindingAfterMove === "inst-C",
    oldStatementReplayRefused: replayOld === "forbidden",
    staleStatementRefused: staleStmt === "stale",
    activityEndWithDeviceStatement: actOk === "accepted",
    activityTokenSwapRefused: actForged === "forbidden",
    activityEndFromOtherInstanceRefused: actOtherInstance === "forbidden",
    optOutNeedsDeviceKey: unByInstance === "forbidden",
    optOutByDevice: unByDevice === "unbound",
    pairBlockedAfterOptOut: rebindBlocked === "forbidden",
  });
}

// Signed relay responses (red team B5): bound to the request nonce, verified against the pinned relay key.
{
  const relayId = ed();
  // Response signature, version 2: method and path with query are bound as well (spec/statements.md).
  const respText = (nonce, status, body, method = "POST", path = "/v1/push") => ["hl-relay-resp-v2", RELAY_HOST, method, path, nonce, status, hex(sha(Buffer.from(body)))].join("\n");
  const body = JSON.stringify({ results: [{ ref: "r1", status: 410, reason: "unregistered" }] });
  const sig = sign(relayId.privateKey, respText("n-1", 200, body));
  const accept = (pinned, nonce, status, b, s) => (s && verify(pinned, respText(nonce, status, b), s)) ? "trusted" : "transportError";
  const impostor = ed();
  report("Signed relay responses:", {
    genuineTrusted: accept(relayId.publicKey, "n-1", 200, body, sig) === "trusted",
    replayOntoOtherRequest: accept(relayId.publicKey, "n-2", 200, body, sig) === "transportError",
    alteredBody: accept(relayId.publicKey, "n-1", 200, body.replace("410", "200"), sig) === "transportError",
    otherPathRefused: !verify(relayId.publicKey, respText("n-1", 200, body, "POST", "/v1/status"), sig),
    unsignedTreatedAsTransportError: accept(relayId.publicKey, "n-1", 200, body, null) === "transportError",
    impostorWithValidTlsButOtherKey: accept(relayId.publicKey, "n-1", 200, body, sign(impostor.privateKey, respText("n-1", 200, body))) === "transportError",
  });
}

// Request signature scope (security M4): host, instance id, path with query are inside the signed text.
{
  const inst = ed();
  const reqText = (host, instanceId, method, pathQuery, ts, nonce, b) => ["hl-relay-v1", host, instanceId, method, pathQuery, ts, nonce, hex(sha(Buffer.from(b)))].join("\n");
  const sig = sign(inst.privateKey, reqText(RELAY_HOST, "inst-A", "POST", "/v1/push", NOW, "n", "{}"));
  // Registration is self-signed (proof of possession of the instance key).
  const regText = (pk, ts) => ["hl-register-v1", RELAY_HOST, hex(edRaw(pk)), ts].join("\n");
  const regSig = sign(inst.privateKey, regText(inst.publicKey, NOW));
  const stranger = ed();
  report("Request signature scope:", {
    valid: verify(inst.publicKey, reqText(RELAY_HOST, "inst-A", "POST", "/v1/push", NOW, "n", "{}"), sig),
    otherHostRefused: !verify(inst.publicKey, reqText("relay.example.org", "inst-A", "POST", "/v1/push", NOW, "n", "{}"), sig),
    otherInstanceRefused: !verify(inst.publicKey, reqText(RELAY_HOST, "inst-B", "POST", "/v1/push", NOW, "n", "{}"), sig),
    queryIsSigned: !verify(inst.publicKey, reqText(RELAY_HOST, "inst-A", "POST", "/v1/push?x=1", NOW, "n", "{}"), sig),
    registrationProofOfPossession: verify(inst.publicKey, regText(inst.publicKey, NOW), regSig),
    foreignKeyRegistrationRefused: !verify(stranger.publicKey, regText(stranger.publicKey, NOW), regSig),
  });
}

console.log(JSON.stringify({
  recipientPrivateKey: hex(skR), recipientPublicKey: hex(pkR), recipientKeyIdApiOnly: hex(keyIdOf(pkR)),
  senderPrivateKey: hex(skS), senderPublicKey: hex(pkS),
  ephemeralPrivateKey: hex(skE), apnsToken: hex(apnsToken), tokenTag: hex(tokenTagOf(apnsToken)),
  pushClass: "alert", aad: hex(s.aad), envelopeLength: s.envelope.length,
  envelopeBase64urlLength: s.envelope.toString("base64url").length,
  envelopeSha256: hex(sha(s.envelope)),
  silentEnvelopeLength: sSilent.envelope.length,
  liveActivityEnvelopeLength: sLa.envelope.length, liveActivityBase64urlLength: sLa.envelope.toString("base64url").length,
  negativeCases: Object.keys(negatives).length,
}, null, 2));
if (!allOk) { console.error("FAILED"); process.exit(1); }
console.log("all checks passed");
