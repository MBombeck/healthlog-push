// Generates spec/vectors/v1.json from the reference implementation in envelope.mjs.
// Usage: node spec/tools/gen-vectors.mjs [--write]
// Without --write the JSON is printed. All key material is synthetic (repeated bytes) and is not secret.
// SPDX-License-Identifier: CC0-1.0
import crypto from "node:crypto";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  hex, unhex, x25519Public, sealWithInjectedEphemeralForVectors as seal, open, buildPadded, tokenTagOf, keyIdOf,
  BUCKET, MAX_TTL, CLOCK_SKEW, HEADER_LEN, CLASS, RESERVED_CLASS, LOW_ORDER, envelopeLength, sha, edKeyFromSeed, edPublicRaw, edSign,
} from "./envelope.mjs";

const b64u = (b) => Buffer.from(b).toString("base64url");
const HOST = "push.healthlog.dev";
const NOW = 1795000000;
const id = (n) => "01JTESTVECT" + String(n).padStart(15, "0");

export function build() {
  const skR = unhex("a8".repeat(32)), pkR = x25519Public(skR);
  const skR2 = unhex("a9".repeat(32)), pkR2 = x25519Public(skR2);
  const skS = unhex("c3".repeat(32)), pkS = x25519Public(skS);
  const skSprev = unhex("c4".repeat(32)), pkSprev = x25519Public(skSprev);
  const skX = unhex("d4".repeat(32)), pkX = x25519Public(skX);
  const skE = unhex("5e".repeat(32));
  const apnsToken = unhex("0f".repeat(32));
  const otherToken = unhex("10".repeat(32));

  const alertJson = {
    v: 1, t: "MEDICATION_INTAKE_RECORDED", id: id(1), iat: NOW, exp: NOW + 7200,
    d: {
      medicationId: "cm_test_med_1", intakeId: "cm_test_intake_1", slotInstant: "2026-11-21T07:00:00.000Z",
      outcome: "taken", takenAt: "2026-11-21T07:12:00.000Z", takenVia: "IOS",
    },
    n: { title: "Dose recorded", body: "A dose was recorded as taken on another device." },
    ui: { thread: "medication-cm_test_med_1", level: "passive" },
  };
  const silentJson = { v: 1, t: "MEDICATION_INTAKE_SYNC", id: id(2), iat: NOW, exp: NOW + 3600, d: { syncedAt: "2026-11-21T07:12:00.000Z" } };
  const maxBody = (() => {
    const base = { v: 1, t: "X", id: id(9), iat: NOW, exp: NOW + 60, n: { body: "" } };
    const fixed = Buffer.byteLength(JSON.stringify(base), "utf8");
    base.n.body = "a".repeat(BUCKET.alert - 2 - fixed - 2) + "ü";
    return base;
  })();

  const S = (args) => seal({ pkR, skS, apnsToken, skE, ...args });
  const sAlert = S({ pushClass: "alert", json: alertJson });
  const sSilent = S({ pushClass: "silent", json: silentJson });
  const craft = (padded, cls = "alert") => S({ pushClass: cls, padded }).envelope;
  const craftJson = (obj) => craft(buildPadded("alert", obj));
  const flip = (buf, i) => { const c = Buffer.from(buf); c[i] ^= 0x01; return c; };
  const withEnc = (buf, encBytes) => { const c = Buffer.from(buf); encBytes.copy(c, HEADER_LEN); return c; };
  const dirty = (() => { const p = Buffer.from(sAlert.padded); p[p.length - 1] = 0x41; return p; })();
  const lenOverflow = (() => { const p = Buffer.alloc(BUCKET.alert); p.writeUInt16BE(0xffff, 0); return p; })();
  const badJson = (() => { const p = Buffer.alloc(BUCKET.alert); p.writeUInt16BE(3, 0); p.write("{x:", 2); return p; })();
  const badUtf8 = (() => { const p = Buffer.alloc(BUCKET.alert); p.writeUInt16BE(4, 0); Buffer.from([0x22, 0xff, 0xfe, 0x22]).copy(p, 2); return p; })();
  const classTampered = (() => { const c = Buffer.from(sSilent.envelope); c[2] = CLASS.alert; return c; })();
  const reservedClass = (() => { const c = Buffer.from(sAlert.envelope); c[2] = RESERVED_CLASS.liveactivity; return c; })();

  const base = { recipientKeys: [hex(skR)], trustedSenders: [hex(pkS)], apnsToken: hex(apnsToken), expectedClass: "alert", now: NOW };
  const E = (name, envelope, expect, over = {}, plaintext) => ({ name, ...base, ...over, envelope: b64u(envelope), expect, ...(plaintext ? { plaintext } : {}) });
  const envelopes = [
    E("alert", sAlert.envelope, "ok", {}, alertJson),
    E("silent", sSilent.envelope, "ok", { expectedClass: "silent" }, silentJson),
    E("previousSender", seal({ pkR, skS: skSprev, apnsToken, skE, pushClass: "alert", json: alertJson }).envelope, "ok", { trustedSenders: [hex(pkS), hex(pkSprev)] }, alertJson),
    E("previousRecipientKey", seal({ pkR: pkR2, skS, apnsToken, skE, pushClass: "alert", json: alertJson }).envelope, "ok", { recipientKeys: [hex(skR), hex(skR2)] }, alertJson),
    E("exactBucketMultibyteEnd", S({ pushClass: "alert", json: maxBody }).envelope, "ok", {}, maxBody),
    E("wrongToken", sAlert.envelope, "authFailure", { apnsToken: hex(otherToken) }),
    E("wrongClassPath", sAlert.envelope, "classMismatch", { expectedClass: "silent" }),
    E("classByteTamperedOnMatchingPath", classTampered, "authFailure"),
    E("reservedLiveActivityClass", reservedClass, "classMismatch"),
    E("unknownVersion", flip(sAlert.envelope, 0), "unsupportedVersion"),
    E("unknownSuite", flip(sAlert.envelope, 1), "unsupportedVersion"),
    E("untrustedSender", sAlert.envelope, "authFailure", { trustedSenders: [hex(pkX)] }),
    E("forgedSender", seal({ pkR, skS: skX, apnsToken, skE, pushClass: "alert", json: alertJson }).envelope, "authFailure"),
    E("sealedToOtherDevice", seal({ pkR: pkX, skS, apnsToken, skE, pushClass: "alert", json: alertJson }).envelope, "authFailure"),
    E("tamperedCiphertext", flip(sAlert.envelope, 100), "authFailure"),
    E("tamperedTag", flip(sAlert.envelope, sAlert.envelope.length - 1), "authFailure"),
    E("tamperedEnc", flip(sAlert.envelope, HEADER_LEN + 5), "authFailure"),
    E("lowOrderEncZero", withEnc(sAlert.envelope, LOW_ORDER[0]), "authFailure"),
    E("lowOrderEncPoint", withEnc(sAlert.envelope, LOW_ORDER[2]), "authFailure"),
    E("truncated60", sAlert.envelope.subarray(0, 60), "malformed"),
    E("oneByteShort", sAlert.envelope.subarray(0, sAlert.envelope.length - 1), "malformed"),
    E("oneByteLong", Buffer.concat([sAlert.envelope, Buffer.from([0])]), "malformed"),
    E("lengthPrefixOverflow", craft(lenOverflow), "malformed"),
    E("lengthZero", craft(Buffer.alloc(BUCKET.alert)), "malformed"),
    E("nonZeroPadding", craft(dirty), "malformed"),
    E("invalidJson", craft(badJson), "malformed"),
    E("invalidUtf8", craft(badUtf8), "malformed"),
    E("missingExp", craftJson({ v: 1, t: "X", id: id(20), iat: NOW }), "malformed"),
    E("badIdFormat", craftJson({ v: 1, t: "X", id: "a", iat: NOW, exp: NOW + 60 }), "malformed"),
    E("unknownSchemaVersion", craftJson({ v: 2, t: "X", id: id(21), iat: NOW, exp: NOW + 60 }), "malformed"),
    E("lifetimeTooLong", craftJson({ v: 1, t: "X", id: id(22), iat: NOW, exp: NOW + MAX_TTL.alert + 1 }), "lifetimeTooLong"),
    E("expired", sAlert.envelope, "expired", { now: alertJson.exp + CLOCK_SKEW + 1 }),
    E("notYetValid", sAlert.envelope, "notYetValid", { now: NOW - CLOCK_SKEW - 1 }),
  ];
  // The relay only checks the outer frame for the class the push item claims (expectedClass): version, suite,
  // class byte, exact length. Everything inside is opaque to it.
  for (const v of envelopes) {
    const e = Buffer.from(v.envelope, "base64url");
    const okFrame = e.length === envelopeLength(v.expectedClass) && e[0] === 1 && e[1] === 1 && e[2] === CLASS[v.expectedClass];
    v.relay = okFrame ? "accept" : "reject";
  }

  // Ed25519 statements (spec/statements.md). Seeds are synthetic.
  const instKey = edKeyFromSeed(Buffer.alloc(32, 0x11));
  const instKey2 = edKeyFromSeed(Buffer.alloc(32, 0x12));
  const bindKey = edKeyFromSeed(Buffer.alloc(32, 0x21));
  const relayKey = edKeyFromSeed(Buffer.alloc(32, 0x31));
  const instanceId = "6f1c2a4e-1b9d-4c3e-8a7f-0d2b5e9c1a37";
  const tokenTag = hex(tokenTagOf(apnsToken));
  const laToken = unhex("2e".repeat(32));
  const laTokenTag = hex(tokenTagOf(laToken));
  const nonce = b64u(Buffer.alloc(16, 0x4e));
  const body = JSON.stringify({ items: [] });
  const bodyHash = hex(sha(Buffer.from(body)));
  const join = (...f) => f.join("\n");
  const st = (name, key, text, extra = {}) => ({ name, publicKey: b64u(edPublicRaw(key)), text, signature: b64u(edSign(key, text)), ...extra });
  const statements = [
    st("register", instKey, join("hl-register-v1", HOST, hex(edPublicRaw(instKey)), NOW)),
    st("request", instKey, join("hl-relay-v1", HOST, instanceId, "POST", "/v1/push", NOW, nonce, bodyHash), { body }),
    st("requestWithQuery", instKey, join("hl-relay-v1", HOST, instanceId, "GET", "/v1/status?probe=1", NOW, nonce, hex(sha(Buffer.alloc(0)))), { body: "" }),
    st("rotateNewKeyProof", instKey2, join("hl-register-v1", HOST, hex(edPublicRaw(instKey2)), NOW)),
    st("bind", bindKey, join("hl-bind-v1", HOST, instanceId, tokenTag, "device", 7, NOW)),
    st("unbind", bindKey, join("hl-unbind-v1", HOST, instanceId, tokenTag, NOW)),
    st("challenge", bindKey, join("hl-challenge-v1", HOST, b64u(Buffer.alloc(32, 0x63)), tokenTag)),
    st("activity", bindKey, join("hl-activity-v1", HOST, instanceId, tokenTag, laTokenTag, NOW)),
    st("selfRead", bindKey, join("hl-selfread-v1", HOST, tokenTag, NOW)),
    st("response", relayKey, join("hl-relay-resp-v2", HOST, "POST", "/v1/push", nonce, 200, bodyHash), { body }),
    st("responseAppEndpoint", relayKey, join("hl-relay-resp-v2", HOST, "DELETE", "/v1/bindings/self", nonce, 204, hex(sha(Buffer.alloc(0)))), { body: "" }),
    st("responseWithoutNonce", relayKey, join("hl-relay-resp-v2", HOST, "GET", "/healthz", "-", 200, hex(sha(Buffer.from('{"status":"ok"}')))), { body: '{"status":"ok"}' }),
    st("registryExport", relayKey, join("hl-relay-export-v1", HOST, hex(sha(Buffer.from('{"format":"healthlog-push-registry-v2"}')))), { body: '{"format":"healthlog-push-registry-v2"}' }),
    st("statusFile", relayKey, join("hl-relay-status-v1", HOST, hex(sha(Buffer.from('{"notice":null}')))), { body: '{"notice":null}' }),
  ];
  // Mutations that must fail verification against the same public key and signature.
  const negativeStatements = [
    { name: "bindOtherInstance", of: "bind", text: join("hl-bind-v1", HOST, "00000000-0000-4000-8000-000000000000", tokenTag, "device", 7, NOW) },
    { name: "bindLowerSeq", of: "bind", text: join("hl-bind-v1", HOST, instanceId, tokenTag, "device", 6, NOW) },
    { name: "bindOtherHost", of: "bind", text: join("hl-bind-v1", "relay.example.org", instanceId, tokenTag, "device", 7, NOW) },
    { name: "requestQueryAdded", of: "request", text: join("hl-relay-v1", HOST, instanceId, "POST", "/v1/push?x=1", NOW, nonce, bodyHash) },
    { name: "requestOtherMethod", of: "request", text: join("hl-relay-v1", HOST, instanceId, "PUT", "/v1/push", NOW, nonce, bodyHash) },
    { name: "responseOtherNonce", of: "response", text: join("hl-relay-resp-v2", HOST, "POST", "/v1/push", b64u(Buffer.alloc(16, 0x4f)), 200, bodyHash) },
    { name: "responseOtherStatus", of: "response", text: join("hl-relay-resp-v2", HOST, "POST", "/v1/push", nonce, 410, bodyHash) },
    { name: "responseOtherMethod", of: "response", text: join("hl-relay-resp-v2", HOST, "GET", "/v1/push", nonce, 200, bodyHash) },
    { name: "responseOtherPath", of: "response", text: join("hl-relay-resp-v2", HOST, "POST", "/v1/status", nonce, 200, bodyHash) },
    { name: "responseAppReplayedOntoOtherRequest", of: "responseAppEndpoint", text: join("hl-relay-resp-v2", HOST, "DELETE", "/v1/bindings/self", b64u(Buffer.alloc(16, 0x50)), 204, hex(sha(Buffer.alloc(0)))) },
    { name: "activityTokenSwapped", of: "activity", text: join("hl-activity-v1", HOST, instanceId, tokenTag, hex(tokenTagOf(unhex("3e".repeat(32)))), NOW) },
    { name: "unbindOtherInstance", of: "unbind", text: join("hl-unbind-v1", HOST, "00000000-0000-4000-8000-000000000000", tokenTag, NOW) },
  ];

  return {
    spec: "HealthLog push relay v1 test vectors",
    license: "CC0-1.0",
    generator: "spec/tools/gen-vectors.mjs",
    note: "All key material is synthetic (repeated bytes) and must never be used outside tests.",
    constants: {
      host: HOST, now: NOW, info: "HealthLog push envelope v1", version: 1, suite: 1, classes: CLASS,
      reservedClasses: RESERVED_CLASS,
      bucket: BUCKET, envelopeLength: { alert: envelopeLength("alert"), silent: envelopeLength("silent") },
      maxTtlSeconds: MAX_TTL, clockSkewSeconds: CLOCK_SKEW,
    },
    keys: {
      recipientPrivateKey: hex(skR), recipientPublicKey: hex(pkR), recipientKeyIdApiOnly: hex(keyIdOf(pkR)),
      recipientPreviousPrivateKey: hex(skR2), senderPrivateKey: hex(skS), senderPublicKey: hex(pkS),
      senderPreviousPrivateKey: hex(skSprev), senderPreviousPublicKey: hex(pkSprev), otherPrivateKey: hex(skX), otherPublicKey: hex(pkX),
      ephemeralPrivateKey: hex(skE), apnsToken: hex(apnsToken),
      instanceSeed: hex(Buffer.alloc(32, 0x11)), instanceRotatedSeed: hex(Buffer.alloc(32, 0x12)),
      bindingSeed: hex(Buffer.alloc(32, 0x21)), relaySeed: hex(Buffer.alloc(32, 0x31)),
      instanceId, laToken: hex(laToken), nonce,
    },
    tokenTags: [
      { token: hex(apnsToken), tokenTag },
      { token: hex(laToken), tokenTag: laTokenTag },
      { token: hex(otherToken), tokenTag: hex(tokenTagOf(otherToken)) },
    ],
    aad: { alert: hex(sAlert.aad) },
    lowOrderPoints: LOW_ORDER.map(hex),
    envelopes,
    statements,
    negativeStatements,
  };
}

const vectors = build();
// Self-check: every envelope vector opens (or fails) exactly as recorded.
for (const v of vectors.envelopes) {
  let got = "ok";
  try {
    open({
      recipientKeys: v.recipientKeys.map(unhex), trustedSenders: v.trustedSenders.map(unhex), apnsToken: unhex(v.apnsToken),
      envelope: Buffer.from(v.envelope, "base64url"), expectedClass: v.expectedClass, now: v.now,
    });
  } catch (e) { got = e.code ?? e.message; }
  if (got !== v.expect) { console.error(`vector ${v.name}: expected ${v.expect}, got ${got}`); process.exit(1); }
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const out = JSON.stringify(vectors, null, 2) + "\n";
  if (process.argv.includes("--write")) {
    writeFileSync(new URL("../vectors/v1.json", import.meta.url), out);
    console.log("wrote spec/vectors/v1.json, sha256", crypto.createHash("sha256").update(out).digest("hex"));
  } else process.stdout.write(out);
}
