// keyring: named testnet identities in localStorage, shared by the apps.
// Keys are stored in plain text. Testnet only. Import this from any page:
//
//   import { list, add, remove, get, info, parsePrivateKey } from 'https://melvincarvalho.github.io/keyring/keyring.js';
//
// Storage: localStorage['keyring'] = [{ name, priv }], priv as 64 hex chars.
// A 'keyring' CustomEvent fires on window after every change in this tab;
// other tabs get the usual 'storage' event.

import { secp256k1, schnorr } from 'https://esm.sh/@noble/curves@1.4.0/secp256k1';
import { sha256 } from 'https://esm.sh/@noble/hashes@1.4.0/sha256';

export const STORAGE_KEY = 'keyring';

// ---- storage ---------------------------------------------------------------

export function list() {
  try { const v = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]'); return Array.isArray(v) ? v : []; } catch { return []; }
}

function save(keys) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(keys));
  window.dispatchEvent(new CustomEvent(STORAGE_KEY, { detail: keys }));
}

// add(name, keyText): keyText is hex, nsec or WIF. Replaces a key of the same name.
export function add(name, keyText) {
  name = String(name).trim();
  if (!name) throw new Error('name required');
  const priv = bytesToHex(parsePrivateKey(keyText));
  const keys = list().filter(k => k.name !== name);
  keys.push({ name, priv });
  save(keys);
  return info(priv);
}

export function remove(name) {
  save(list().filter(k => k.name !== name));
}

export function rename(from, to) {
  to = String(to).trim();
  if (!to) throw new Error('name required');
  save(list().map(k => k.name === from ? { ...k, name: to } : k));
}

// get(name) -> { name, priv } or undefined
export function get(name) {
  return list().find(k => k.name === name);
}

export function clear() { save([]); }

// ---- derived views -----------------------------------------------------------

export function info(privHex) {
  const xonly = schnorr.getPublicKey(hexToBytes(privHex));
  return {
    xonly: bytesToHex(xonly),
    npub: bech32Encode('npub', convertBits(Array.from(xonly), 8, 5), BECH32),
    nsec: bech32Encode('nsec', convertBits(Array.from(hexToBytes(privHex)), 8, 5), BECH32),
    tb1p: bech32Encode('tb', [1].concat(convertBits(Array.from(xonly), 8, 5)), BECH32M),
    bc1p: bech32Encode('bc', [1].concat(convertBits(Array.from(xonly), 8, 5)), BECH32M),
  };
}

// ---- key parsing (hex, nsec, WIF) ----------------------------------------------

export function parsePrivateKey(input) {
  const s = String(input).trim();
  let key;
  if (/^[0-9a-fA-F]{64}$/.test(s)) key = hexToBytes(s.toLowerCase());
  else if (/^nsec1[a-z0-9]+$/i.test(s)) {
    const d = bech32Decode(s);
    if (!d || d.hrp !== 'nsec' || d.spec !== BECH32) throw new Error('bad nsec');
    key = new Uint8Array(convertBits(d.data, 5, 8, false));
    if (key.length !== 32) throw new Error('bad nsec length');
  } else key = wifToPrivateKey(s);
  if (!secp256k1.utils.isValidPrivateKey(key)) throw new Error('key out of range');
  return key;
}

export function bytesToHex(bytes) { return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(''); }
export function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

const BECH32 = 1, BECH32M = 0x2bc830a3, CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) { const b = chk >> 25; chk = ((chk & 0x1ffffff) << 5) ^ v; for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i]; }
  return chk;
}
function hrpExpand(hrp) { return [...[...hrp].map(c => c.charCodeAt(0) >> 5), 0, ...[...hrp].map(c => c.charCodeAt(0) & 31)]; }
function convertBits(data, from, to, pad = true) {
  let acc = 0, bits = 0; const out = [], maxv = (1 << to) - 1;
  for (const v of data) { acc = (acc << from) | v; bits += from; while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); } }
  if (pad) { if (bits > 0) out.push((acc << (to - bits)) & maxv); }
  else if (bits >= from || ((acc << (to - bits)) & maxv)) throw new Error('bad padding');
  return out;
}
function bech32Encode(hrp, data, spec) {
  const pm = polymod(hrpExpand(hrp).concat(data, [0, 0, 0, 0, 0, 0])) ^ spec;
  const cs = []; for (let i = 0; i < 6; i++) cs.push((pm >> (5 * (5 - i))) & 31);
  return hrp + '1' + data.concat(cs).map(d => CHARSET[d]).join('');
}
function bech32Decode(str) {
  const s = str.toLowerCase(), pos = s.lastIndexOf('1');
  if (pos < 1) return null;
  const hrp = s.slice(0, pos), data = [];
  for (const c of s.slice(pos + 1)) { const i = CHARSET.indexOf(c); if (i === -1) return null; data.push(i); }
  return { hrp, data: data.slice(0, -6), spec: polymod(hrpExpand(hrp).concat(data)) };
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function wifToPrivateKey(wif) {
  let num = 0n;
  for (const c of wif) { const i = B58.indexOf(c); if (i === -1) throw new Error('not hex, nsec or WIF'); num = num * 58n + BigInt(i); }
  let hex = num.toString(16); if (hex.length % 2) hex = '0' + hex;
  const bytes = hexToBytes(hex);
  const payload = bytes.subarray(0, -4), check = sha256(sha256(payload)).subarray(0, 4);
  if (bytesToHex(check) !== bytesToHex(bytes.subarray(-4))) throw new Error('bad WIF checksum');
  if (payload[0] !== 0x80 && payload[0] !== 0xef) throw new Error('bad WIF prefix');
  if (payload.length === 34 && payload[33] === 0x01) return payload.slice(1, 33);
  if (payload.length === 33) return payload.slice(1);
  throw new Error('bad WIF length');
}
