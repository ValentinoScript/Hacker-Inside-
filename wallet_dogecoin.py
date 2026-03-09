#!/usr/bin/env python3
# wallet_dogecoin_complete.py
# Wallet Dogecoin (MAINNET) complet — BIP39 -> BIP32(BIP44) derivation, save AES-GCM, UTXO multi-provider, build/sign legacy tx, OP_RETURN, broadcast.

import os
import sys
import time
import json
import base64
import struct
import hashlib
import requests
import getpass
from typing import List, Tuple

from mnemonic import Mnemonic
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der_canonize
from Crypto.Hash import RIPEMD160
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# --------------------- CONFIG ---------------------
WALLETS_FILE = "wallets_doge.json"
MNEMONIC_LANG = "english"

# Dogecoin parameters
DOGE_COIN_TYPE = 3            # BIP44 coin_type for Dogecoin (m/44'/3'/...)
DOGE_MAINNET_P2PKH_PREFIX = b'\x1e'  # 0x1e -> addresses starting with 'D'
DOGE_WIF_PREFIX = b'\x9e'     # WIF prefix: 0x9e ? (some implementations use 0x9e or 0x9e ) -> We'll compute using private key + 0x9e
# NOTE: Many implementations use 0x9e (158) as WIF prefix for Dogecoin mainnet (compressed) — this is standard-ish.
# Units: we treat 1 DOGE = 1e8 base units (like satoshis). Many APIs report DOGE as decimal floats.

DEFAULT_FEE_DOGE = 1.0  # 1 DOGE default fee (you should adapt)
DEFAULT_DUST = 1.0      # 1 DOGE dust default

# UTXO / broadcast providers (try in order)
# SoChain supports DOGE, Blockchair also, BlockCypher maybe, Trezor blockbook might have DOGE instance
SOCHAIN_BASE = "https://sochain.com/api/v2"
BLOCKCHAIR_BASE = "https://api.blockchair.com/dogecoin"
BLOCKCYPHER_BASE = "https://api.blockcypher.com/v1/doge/main"
TREZOR_BLOCKBOOK = "https://doge1.trezor.io"  # may or may not be available

# --------------------- UTIL: hashing & base58 ---------------------
def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def _dsha256(b: bytes) -> bytes:
    return _sha256(_sha256(b))

def _ripemd160(b: bytes) -> bytes:
    h = RIPEMD160.new()
    h.update(b)
    return h.digest()

def _hash160(b: bytes) -> bytes:
    return _ripemd160(_sha256(b))

B58_ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, 'big')
    s = ""
    while n > 0:
        n, r = divmod(n, 58)
        s = B58_ALPH[r] + s
    pad = 0
    for c in b:
        if c == 0:
            pad += 1
        else:
            break
    return "1" * pad + s

def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        if ch not in B58_ALPH:
            raise ValueError("Base58 caractère invalide: " + ch)
        n = n * 58 + B58_ALPH.index(ch)
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big') or b'\x00'
    pad = 0
    for ch in s:
        if ch == '1':
            pad += 1
        else:
            break
    return b'\x00' * pad + b

def base58_check_encode(payload: bytes) -> str:
    checksum = _dsha256(payload)[:4]
    return b58encode(payload + checksum)

def base58_check_decode(addr: str) -> bytes:
    raw = b58decode(addr)
    if len(raw) < 4:
        raise ValueError("Payload trop court")
    payload, checksum = raw[:-4], raw[-4:]
    if _dsha256(payload)[:4] != checksum:
        raise ValueError("Checksum invalide")
    return payload

# --------------------- AES-GCM wallet storage ---------------------
def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000, backend=default_backend())
    return kdf.derive(password.encode())

def encrypt_data(plaintext: bytes, password: str) -> dict:
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, None)
    return {"salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(), "ct": base64.b64encode(ct).decode()}

def decrypt_data(enc: dict, password: str) -> bytes:
    salt = base64.b64decode(enc["salt"]); nonce = base64.b64decode(enc["nonce"]); ct = base64.b64decode(enc["ct"])
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, None)

def load_wallets_file() -> dict:
    if not os.path.exists(WALLETS_FILE):
        return {}
    try:
        with open(WALLETS_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except Exception:
        return {}

def save_wallets_file(d: dict):
    with open(WALLETS_FILE, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)

def list_saved_wallets() -> List[str]:
    return list(load_wallets_file().keys())

def save_wallet(name: str, wtype: str, secret: str, password: str) -> bool:
    data = load_wallets_file()
    if name in data:
        print(f"❌ Le nom '{name}' existe déjà.")
        return False
    data[name] = {"type": wtype, "enc": encrypt_data(secret.encode(), password)}
    save_wallets_file(data)
    print(f"✅ Wallet '{name}' sauvegardé et chiffré.")
    return True

def load_wallet_secret(name: str, password: str) -> Tuple[str, str]:
    data = load_wallets_file()
    if name not in data:
        raise KeyError(f"Wallet '{name}' introuvable.")
    entry = data[name]
    secret = decrypt_data(entry["enc"], password).decode()
    return entry["type"], secret

# --------------------- BIP39 -> BIP32 (minimal) ---------------------
# We implement BIP32 master key derivation and CKDpriv (no public-only derivation needed).
# Path derivation supports hardened (') and non-hardened indices.

def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha512', data, key, 1, dklen=64) if False else hashlib.new('sha512', data, key)  # fallback: we will use hmac below

import hmac
def hmac_sha512_k(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()

def seed_from_mnemonic(mnemonic_phrase: str, passphrase: str = "") -> bytes:
    # BIP39 seed
    mn = Mnemonic(MNEMONIC_LANG)
    return mn.to_seed(mnemonic_phrase, passphrase=passphrase)

def master_from_seed(seed: bytes) -> Tuple[bytes, bytes]:
    I = hmac_sha512_k(b"Bitcoin seed", seed)
    master_priv = I[:32]
    master_chain = I[32:]
    return master_priv, master_chain

# CKDpriv: returns (k_i, c_i)
def ckd_priv(k_parent: bytes, c_parent: bytes, index: int) -> Tuple[bytes, bytes]:
    if index >= 0x80000000:
        # hardened
        data = b'\x00' + k_parent + struct.pack('>I', index)
    else:
        # non-hardened: need parent public key (compressed)
        sk = SigningKey.from_string(k_parent, curve=SECP256k1)
        vk = sk.get_verifying_key()
        pub = b'\x02' + vk.to_string()[:32] if (vk.to_string()[-1] % 2 == 0) else b'\x03' + vk.to_string()[:32]
        data = pub + struct.pack('>I', index)
    I = hmac_sha512_k(c_parent, data)
    Il, Ir = I[:32], I[32:]
    # new private key = (Il + k_parent) mod n
    Il_int = int.from_bytes(Il, 'big')
    k_parent_int = int.from_bytes(k_parent, 'big')
    curve_n = SECP256k1.order
    k_i_int = (Il_int + k_parent_int) % curve_n
    k_i = k_i_int.to_bytes(32, 'big')
    return k_i, Ir

def derive_path_from_seed(seed: bytes, path: str) -> bytes:
    # path example: "m/44'/3'/0'/0/0"
    master_k, master_c = master_from_seed(seed)
    segments = path.split('/')
    if segments[0] != 'm':
        raise ValueError("Path must start with 'm'")
    k, c = master_k, master_c
    for seg in segments[1:]:
        if seg.endswith("'"):
            idx = int(seg[:-1]) + 0x80000000
        else:
            idx = int(seg)
        k, c = ckd_priv(k, c, idx)
    return k  # return private key (32 bytes) at that path

# --------------------- key/address helpers ---------------------
def privkey_to_wif(privkey_bytes: bytes, compressed: bool = True) -> str:
    # WIF payload: prefix + privbytes + (0x01 if compressed)
    payload = DOGE_WIF_PREFIX + privkey_bytes
    if compressed:
        payload = payload + b'\x01'
    checksum = _dsha256(payload)[:4]
    return b58encode(payload + checksum)

def wif_to_privkey(wif: str) -> Tuple[bytes, bool]:
    raw = b58decode(wif)
    if len(raw) < 5:
        raise ValueError("WIF trop court")
    payload = raw[:-4]
    prefix = payload[0:1]
    if prefix != DOGE_WIF_PREFIX:
        # Some WIFs may use 0x80 (Bitcoin-style) if imported from other libs — we allow it but warn
        pass
    if payload[-1] == 0x01:
        return payload[1:-1], True
    else:
        return payload[1:], False

def privkey_to_pubkey(privkey_bytes: bytes, compressed: bool = True) -> bytes:
    sk = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.to_string()[:32]; y = vk.to_string()[32:]
    y_last = y[-1]
    if compressed:
        prefix = b'\x02' if (y_last % 2 == 0) else b'\x03'
        return prefix + x
    else:
        return b'\x04' + x + y

def pubkey_to_p2pkh_address(pubkey_bytes: bytes, prefix: bytes = DOGE_MAINNET_P2PKH_PREFIX) -> str:
    h160 = _hash160(pubkey_bytes)
    payload = prefix + h160
    checksum = _dsha256(payload)[:4]
    return b58encode(payload + checksum)

# --------------------- varint and TX helpers ---------------------
def _varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)

def _le_txid(txid_hex: str) -> bytes:
    return bytes.fromhex(txid_hex)[::-1]

def _outpoint(txid_hex: str, vout: int) -> bytes:
    return _le_txid(txid_hex) + struct.pack('<I', vout)

# --------------------- UTXO providers (DOGE) ---------------------
def _utxos_sochain(address: str) -> List[dict]:
    url = f"{SOCHAIN_BASE}/get_tx_unspent/DOGE/{address}"
    r = requests.get(url, timeout=12); r.raise_for_status()
    j = r.json()
    txs = j.get("data", {}).get("txs", []) or []
    out = []
    for t in txs:
        v = float(t.get("value", "0"))
        out.append({
            "txid": t.get("txid"),
            "vout": int(t.get("output_no") or 0),
            "value": int(round(v * 1e8)),
            "scriptpubkey": t.get("script_hex"),
            "confirmations": int(t.get("confirmations", 0))
        })
    return out

def _utxos_blockchair(address: str) -> List[dict]:
    # Blockchair endpoint for dogecoin: /dashboards/address/{address}
    url = f"{BLOCKCHAIR_BASE}/dashboards/address/{address}"
    r = requests.get(url, timeout=12); r.raise_for_status()
    j = r.json()
    raw = j.get("data", {}).get(address, {}).get("utxo", []) or []
    out = []
    for t in raw:
        out.append({
            "txid": t.get("transaction_hash"),
            "vout": int(t.get("index") or 0),
            "value": int(t.get("value") or 0),
            "scriptpubkey": t.get("script_hex"),
            "confirmations": True
        })
    return out

def _utxos_blockcypher(address: str) -> List[dict]:
    try:
        url = f"{BLOCKCYPHER_BASE}/addrs/{address}"
        r = requests.get(url, timeout=12); r.raise_for_status()
        j = r.json()
        txrefs = j.get("txrefs") or j.get("unconfirmed_txrefs") or []
        out = []
        for t in txrefs:
            out.append({
                "txid": t.get("tx_hash") or t.get("txid"),
                "vout": int(t.get("tx_output_n") or 0),
                "value": int(t.get("value") or 0),
                "scriptpubkey": t.get("script") or None,
                "confirmations": int(t.get("confirmations", 0))
            })
        return out
    except Exception:
        raise

def _utxos_trezor(address: str) -> List[dict]:
    url = f"{TREZOR_BLOCKBOOK}/api/v2/address/{address}/utxo"
    r = requests.get(url, timeout=12); r.raise_for_status()
    j = r.json()
    raw = j.get("payload") or j.get("utxo") or j
    out = []
    if isinstance(raw, list):
        for t in raw:
            out.append({
                "txid": t.get("txid"),
                "vout": int(t.get("vout") or 0),
                "value": int(t.get("value") or 0),
                "scriptpubkey": t.get("scriptPubKey") or None,
                "confirmations": int(t.get("confirmations") or 0)
            })
    return out

def get_utxos(address: str) -> List[dict]:
    providers = [_utxos_sochain, _utxos_blockchair, _utxos_blockcypher, _utxos_trezor]
    errors = []
    for p in providers:
        try:
            u = p(address)
            if isinstance(u, list):
                return u
        except Exception as e:
            errors.append(f"{p.__name__} failed: {e}")
            time.sleep(0.2)
    raise RuntimeError("Impossible de récupérer UTXO. Logs: " + " | ".join(errors[-6:]))

# --------------------- Broadcast raw tx (fallback) ---------------------
def broadcast_raw_hex(raw_hex: str) -> str:
    errors = []
    # SoChain
    try:
        r = requests.post(f"{SOCHAIN_BASE}/send_tx/DOGE", json={"tx_hex": raw_hex}, timeout=15)
        r.raise_for_status()
        j = r.json()
        return j.get("data", {}).get("txid") or str(j)
    except Exception as e:
        errors.append("SoChain: " + str(e))
    # Blockchair
    try:
        r = requests.post(f"{BLOCKCHAIR_BASE}/push/transaction", json={"data": raw_hex}, timeout=15)
        if r.ok:
            j = r.json()
            return j.get("data", {}).get("transaction_hash") or str(j)
        else:
            errors.append("Blockchair: " + r.text[:200])
    except Exception as e:
        errors.append("Blockchair: " + str(e))
    # BlockCypher
    try:
        r = requests.post(f"{BLOCKCYPHER_BASE}/txs/push", json={"tx": raw_hex}, timeout=15)
        if r.ok:
            j = r.json(); return j.get("tx", {}).get("hash") or str(j)
        else:
            errors.append("BlockCypher: " + r.text[:200])
    except Exception as e:
        errors.append("BlockCypher: " + str(e))
    # Trezor
    try:
        r = requests.post(f"{TREZOR_BLOCKBOOK}/api/v2/sendtx/{raw_hex}", timeout=15)
        if r.ok:
            try: j = r.json(); return j.get("result") or str(j)
            except: return r.text
        else:
            errors.append("Trezor: " + r.text[:200])
    except Exception as e:
        errors.append("Trezor: " + str(e))
    raise RuntimeError("Broadcast failed on all providers. Logs: " + " | ".join(errors[-6:]))

# --------------------- TX builder (legacy P2PKH) ---------------------
def build_p2pkh_tx(privkey_bytes: bytes, utxos: List[dict], dest_address: str, amount_sat: int, fee_sat: int) -> str:
    """
    Build and sign a legacy P2PKH transaction spending provided utxos, returning raw hex.
    privkey_bytes: 32 bytes
    utxos: list of dict with keys txid, vout, value (int in sat-like units), optional scriptpubkey hex
    dest_address: destination address (supports legacy base58 D... or other)
    """
    pub = privkey_to_pubkey(privkey_bytes, compressed=True)
    own_h160 = _hash160(pub)
    own_spk = b'\x76\xa9\x14' + own_h160 + b'\x88\xac'  # P2PKH scriptPubKey

    need = amount_sat + fee_sat
    selected = []
    total = 0
    for u in utxos:
        v = int(u.get("value", 0))
        if v <= 0:
            continue
        selected.append(u)
        total += v
        if total >= need:
            break
    if total < need:
        raise ValueError("Fonds insuffisants")

    # build outputs
    outs = []
    # destination: assume legacy base58 P2PKH OR try to accept other formats via base58 decode
    try:
        payload = base58_check_decode(dest_address)
        ver = payload[0:1]; h160_dest = payload[1:21]
        spk_dest = b'\x76\xa9\x14' + h160_dest + b'\x88\xac'
    except Exception:
        raise ValueError("Adresse destin non reconnue (attendue legacy base58).")
    outs.append((amount_sat, spk_dest))
    change = total - amount_sat - fee_sat
    if change > 0:
        outs.append((change, own_spk))

    # serialize outputs
    outs_ser = b''
    for val, spk in outs:
        outs_ser += struct.pack('<Q', val) + _varint(len(spk)) + spk

    version = struct.pack('<I', 1)
    locktime = struct.pack('<I', 0)

    # prepare signing for each input (legacy SIGHASH_ALL)
    sk = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
    final_inputs = []
    for idx, u in enumerate(selected):
        # create inputs serialization with appropriate script for sighash
        txins_for_hash = b''
        for j, uu in enumerate(selected):
            txid = _le_txid(uu["txid"])
            vout = struct.pack('<I', int(uu["vout"]))
            if j == idx:
                # script pubkey for this utxo: try to use provided scriptpubkey, else assume it's P2PKH to our pub
                spk = None
                spk_hex = uu.get("scriptpubkey") or uu.get("scriptPubKey") or uu.get("script")
                if spk_hex:
                    try:
                        spk = bytes.fromhex(spk_hex)
                    except Exception:
                        spk = None
                if spk is None:
                    # fallback: assume utxo belongs to our own pub (could be wrong if using different address)
                    spk = own_spk
                txins_for_hash += txid + vout + _varint(len(spk)) + spk + struct.pack('<I', 0xffffffff)
            else:
                txins_for_hash += txid + vout + _varint(0) + b'' + struct.pack('<I', 0xffffffff)
        preimage = version + _varint(len(selected)) + txins_for_hash + _varint(len(outs)) + outs_ser + locktime + struct.pack('<I', 1)
        sighash = _dsha256(preimage)
        der_sig = sk.sign_digest(sighash, sigencode=sigencode_der_canonize) + b'\x01'
        scriptSig = _varint(len(der_sig)) + der_sig + _varint(len(pub)) + pub
        final_inputs.append(_le_txid(u["txid"]) + struct.pack('<I', int(u["vout"])) + _varint(len(scriptSig)) + scriptSig + struct.pack('<I', 0xffffffff))

    tx = version + _varint(len(selected)) + b''.join(final_inputs) + _varint(len(outs)) + outs_ser + locktime
    return tx.hex()

# OP_RETURN builder (spends utxos and writes message)
def build_opreturn_tx(privkey_bytes: bytes, utxos: List[dict], message: str, fee_sat: int, dust_sat: int = int(DEFAULT_DUST * 1e8)) -> str:
    pub = privkey_to_pubkey(privkey_bytes, compressed=True)
    own_h160 = _hash160(pub)
    own_spk = b'\x76\xa9\x14' + own_h160 + b'\x88\xac'

    need = fee_sat + dust_sat
    selected = []; total = 0
    for u in utxos:
        v = int(u.get("value", 0))
        if v <= 0: continue
        selected.append(u); total += v
        if total >= need:
            break
    if total < need:
        raise ValueError("Fonds insuffisants")

    msgb = message.encode('utf-8')[:80]
    if len(msgb) <= 75:
        push = bytes([len(msgb)])
    else:
        push = b'\x4c' + bytes([len(msgb)])
    opret = b'\x6a' + push + msgb
    outs = [(0, opret), (dust_sat, own_spk)]
    change = total - fee_sat - dust_sat
    if change > 0:
        outs.append((change, own_spk))

    outs_ser = b''.join(struct.pack('<Q', val) + _varint(len(spk)) + spk for val, spk in outs)
    version = struct.pack('<I', 1); locktime = struct.pack('<I', 0)

    sk = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
    final_inputs = []
    for idx, u in enumerate(selected):
        txins_for_hash = b''
        for j, uu in enumerate(selected):
            txid = _le_txid(uu["txid"]); vout = struct.pack('<I', int(uu["vout"]))
            if j == idx:
                spk_hex = uu.get("scriptpubkey") or uu.get("scriptPubKey") or uu.get("script")
                spk = None
                if spk_hex:
                    try: spk = bytes.fromhex(spk_hex)
                    except: spk = None
                if spk is None: spk = own_spk
                txins_for_hash += txid + vout + _varint(len(spk)) + spk + struct.pack('<I', 0xffffffff)
            else:
                txins_for_hash += txid + vout + _varint(0) + b'' + struct.pack('<I', 0xffffffff)
        preimage = version + _varint(len(selected)) + txins_for_hash + _varint(len(outs)) + outs_ser + locktime + struct.pack('<I', 1)
        sighash = _dsha256(preimage)
        der_sig = sk.sign_digest(sighash, sigencode=sigencode_der_canonize) + b'\x01'
        scriptSig = _varint(len(der_sig)) + der_sig + _varint(len(pub)) + pub
        final_inputs.append(_le_txid(u["txid"]) + struct.pack('<I', int(u["vout"])) + _varint(len(scriptSig)) + scriptSig + struct.pack('<I', 0xffffffff))

    tx = version + _varint(len(selected)) + b''.join(final_inputs) + _varint(len(outs)) + outs_ser + locktime
    return tx.hex()

# --------------------- High level helpers & CLI ---------------------
def derive_privkey_from_mnemonic(phrase: str, account: int = 0, change: int = 0, address_index: int = 0) -> bytes:
    # Derive BIP44 doge first address by default m/44'/3'/0'/0/0
    path = f"m/44'/{DOGE_COIN_TYPE}'/0'/{change}/{address_index}"
    seed = seed_from_mnemonic(phrase, passphrase="")
    priv = derive_path_from_seed(seed, path)
    return priv

def show_addresses_from_priv(priv_bytes: bytes) -> Tuple[str, str]:
    pub = privkey_to_pubkey(priv_bytes, compressed=True)
    addr = pubkey_to_p2pkh_address(pub, prefix=DOGE_MAINNET_P2PKH_PREFIX)
    wif = privkey_to_wif(priv_bytes, compressed=True)
    return addr, wif

def show_utxos_and_balance(addr: str):
    try:
        utxos = get_utxos(addr)
    except Exception as e:
        print("❌ Erreur fetch UTXO :", e)
        return []
    if not utxos:
        print("🚫 Aucun UTXO détecté pour", addr)
        return []
    total = sum(int(u.get("value", 0)) for u in utxos)
    print(f"🔍 {len(utxos)} UTXO(s) pour {addr} — Solde total ~ {total/1e8:.8f} DOGE")
    for u in utxos:
        conf = u.get("confirmations", 0)
        st = "✔" if int(conf) > 0 else "🕓"
        print(f" • {u['txid']}:{u['vout']} — {u['value']/1e8:.8f} DOGE ({st})")
    return utxos

# CLI: create / import / load / send / op_return / save encrypted
def main():
    print("=== Wallet Dogecoin (complete) ===")
    active_priv = None
    active_addr = None

    while True:
        print("""
1) Créer wallet (mnemonic)
2) Importer wallet (mnemonic / WIF)
3) Charger wallet sauvegardé
4) Quitter
""")
        c = input("Choix : ").strip()
        if c == "1":
            name = input("Nom du wallet : ").strip()
            phrase = Mnemonic(MNEMONIC_LANG).generate(strength=128)
            print("🔑 Phrase mnémonique :", phrase)
            priv = derive_privkey_from_mnemonic(phrase)
            addr, wif = show_addresses_from_priv(priv)
            print("📮 Adresse (index 0):", addr)
            print("🔐 WIF (privé) :", wif)
            if input("Sauvegarder chiffré ? (o/n) : ").strip().lower() == 'o':
                pwd = getpass.getpass("Mot de passe AES : ")
                pwd2 = getpass.getpass("Confirme : ")
                if pwd != pwd2:
                    print("❌ Mots de passe différents. Abandon.")
                else:
                    save_wallet(name, "mnemonic", phrase, pwd)
            active_priv = priv; active_addr = addr

        elif c == "2":
            sub = input("a) Par phrase mnémonique\nb) Par WIF\nChoix : ").strip().lower()
            if sub == "a":
                phrase = input("Phrase (12–24 mots) : ").strip()
                priv = derive_privkey_from_mnemonic(phrase)
                addr, wif = show_addresses_from_priv(priv)
                print("📮 Adresse :", addr)
                if input("Sauvegarder chiffré ? (o/n) : ").strip().lower() == 'o':
                    name = input("Nom : ").strip()
                    pwd = getpass.getpass("Pwd AES: "); pwd2 = getpass.getpass("Confirme: ")
                    if pwd != pwd2:
                        print("❌ Mots de passe différents.")
                    else:
                        save_wallet(name, "mnemonic", phrase, pwd)
                active_priv = priv; active_addr = addr
            elif sub == "b":
                wif = input("Clé privée WIF : ").strip()
                try:
                    privbytes, compressed = wif_to_privkey(wif)
                except Exception as e:
                    print("WIF invalide :", e); continue
                addr = pubkey_to_p2pkh_address(privkey_to_pubkey(privbytes), prefix=DOGE_MAINNET_P2PKH_PREFIX)
                print("📮 Adresse :", addr)
                if input("Sauvegarder chiffré ? (o/n) : ").strip().lower() == 'o':
                    name = input("Nom : ").strip()
                    pwd = getpass.getpass("Pwd AES: "); pwd2 = getpass.getpass("Confirme: ")
                    if pwd != pwd2:
                        print("❌ Mots de passe différents.")
                    else:
                        save_wallet(name, "wif", wif, pwd)
                active_priv = privbytes; active_addr = addr
            else:
                continue

        elif c == "3":
            saved = list_saved_wallets()
            if not saved:
                print("🚫 Aucun wallet sauvegardé.")
                continue
            for i, n in enumerate(saved, 1):
                print(f"{i}) {n}")
            try:
                idx = int(input("Choix n° : ").strip()) - 1
                name = saved[idx]
            except Exception:
                print("Entrée invalide."); continue
            pwd = getpass.getpass("Mot de passe AES : ")
            try:
                wtype, secret = load_wallet_secret(name, pwd)
            except Exception as e:
                print("❌ Échec déchiffrement :", e); continue
            if wtype == "mnemonic":
                priv = derive_privkey_from_mnemonic(secret)
                addr, wif = show_addresses_from_priv(priv)
                active_priv = priv; active_addr = addr
            elif wtype == "wif":
                wif = secret
                privbytes, _ = wif_to_privkey(wif)
                addr = pubkey_to_p2pkh_address(privkey_to_pubkey(privbytes), prefix=DOGE_MAINNET_P2PKH_PREFIX)
                active_priv = privbytes; active_addr = addr
            else:
                print("Type de wallet inconnu :", wtype); continue
            print("✅ Wallet chargé :", name)
            print("📮 Adresse actuelle :", active_addr)

        elif c == "4":
            print("Bye."); sys.exit(0)
        else:
            continue

        # Submenu for active wallet
        while True:
            print(f"""
--- Wallet actif [{active_addr}] ---
a) Solde & UTXO
b) Envoyer DOGE
c) Envoyer message (OP_RETURN)
d) Afficher adresse & WIF
e) Retour
""")
            sub = input("Option : ").strip().lower()
            if sub == 'a':
                if not active_addr:
                    print("Aucun wallet actif."); break
                show_utxos_and_balance(active_addr)

            elif sub == 'b':
                if active_priv is None:
                    print("Aucun clef privée active."); break
                dest = input("Adresse destinataire : ").strip()
                amt = float(input("Montant (DOGE) : ").strip())
                fee = input(f"Frais (DOGE) [défaut {DEFAULT_FEE_DOGE}] : ").strip()
                fee = float(fee) if fee else DEFAULT_FEE_DOGE
                # fetch utxos for active_addr
                try:
                    utxos = get_utxos(active_addr)
                except Exception as e:
                    print("Erreur fetch UTXO :", e); continue
                if not utxos:
                    print("Aucun UTXO disponible.")
                    continue
                try:
                    raw = build_p2pkh_tx(active_priv, utxos, dest, int(amt * 1e8), int(fee * 1e8))
                except Exception as e:
                    print("Erreur construction TX :", e); continue
                print("📝 Raw TX hex :", raw)
                try:
                    txid = broadcast_raw_hex(raw)
                    print("✅ TX envoyée ! TXID :", txid)
                except Exception as e:
                    print("❌ Erreur broadcast :", e)

            elif sub == 'c':
                if active_priv is None:
                    print("Aucun clef privée active."); break
                msg = input("Message (<=80 octets) : ").strip()
                fee = input(f"Frais (DOGE) [défaut {DEFAULT_FEE_DOGE}] : ").strip()
                fee = float(fee) if fee else DEFAULT_FEE_DOGE
                try:
                    utxos = get_utxos(active_addr)
                except Exception as e:
                    print("Erreur fetch UTXO :", e); continue
                if not utxos:
                    print("Aucun UTXO disponible.")
                    continue
                try:
                    raw = build_opreturn_tx(active_priv, utxos, msg, int(fee * 1e8))
                except Exception as e:
                    print("Erreur build OP_RETURN:", e); continue
                print("📝 Raw OP_RETURN TX hex:", raw)
                try:
                    txid = broadcast_raw_hex(raw)
                    print("✅ TX envoyée ! TXID :", txid)
                except Exception as e:
                    print("❌ Erreur broadcast :", e)

            elif sub == 'd':
                if active_priv is None:
                    print("Aucun wallet actif."); break
                addr, wif = show_addresses_from_priv(active_priv)
                print("Adresse :", addr)
                print("WIF (privé) :", wif)

            else:
                break

if __name__ == "__main__":
    main()
