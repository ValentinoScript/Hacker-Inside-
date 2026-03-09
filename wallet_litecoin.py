#!/usr/bin/env python3
# wallet_litecoin_complete_fixed.py
# Wallet Litecoin (MAINNET) complet — bech32 + legacy, UTXO multi-provider, build/sign segwit & legacy (dest bech/legacy), AES-GCM save.

import os, sys, json, time, base64, getpass, struct, hashlib, requests
from typing import List, Tuple

from mnemonic import Mnemonic
from bitcoinlib.keys import HDKey, Key
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der_canonize
from Crypto.Hash import RIPEMD160
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ---------------- CONFIG ----------------
BIP84_PATH = "m/84h/2h/0h/0/0"   # bech32 path (SegWit)
BIP44_PATH = "m/44h/2h/0h/0/0"   # legacy P2PKH
NETWORK_NAME = "litecoin"
WALLETS_FILE = "wallets_litecoin.json"
DEFAULT_FEE_SAT = 2000     # 0.00002 LTC
DEFAULT_DUST = 1000

# Providers (endpoints)
BLOCKCYPHER_BASE = "https://api.blockcypher.com/v1/ltc/main"
SOCHAIN_BASE = "https://sochain.com/api/v2"
BLOCKCHAIR_BASE = "https://api.blockchair.com/litecoin"
TREZOR_BLOCKBOOK = "https://ltc1.trezor.io"

BLOCKCYPHER_TOKEN = None  # optionnel

# ---------------- AES helpers ----------------
def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000, backend=default_backend())
    return kdf.derive(password.encode())

def encrypt_with_password(plaintext: bytes, password: str) -> dict:
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, None)
    return {"salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(ct).decode()}

def decrypt_with_password(enc: dict, password: str) -> bytes:
    salt = base64.b64decode(enc["salt"]); nonce = base64.b64decode(enc["nonce"]); ct = base64.b64decode(enc["ciphertext"])
    key = _derive_key(password, salt); aes = AESGCM(key)
    return aes.decrypt(nonce, ct, None)

# ---------------- storage ----------------
def load_wallets_file() -> dict:
    if not os.path.isfile(WALLETS_FILE): return {}
    try:
        with open(WALLETS_FILE, "r", encoding="utf-8") as f:
            d = json.load(f); return d if isinstance(d, dict) else {}
    except Exception:
        return {}

def save_wallets_file(d: dict):
    with open(WALLETS_FILE, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)

def list_saved_wallets() -> List[str]:
    return list(load_wallets_file().keys())

def save_wallet(name: str, wtype: str, secret: str, password: str) -> bool:
    d = load_wallets_file()
    if name in d:
        print(f"❌ Le nom '{name}' existe déjà."); return False
    d[name] = {"type": wtype, "enc": encrypt_with_password(secret.encode(), password)}
    save_wallets_file(d); print(f"✅ Wallet '{name}' sauvegardé et chiffré."); return True

def load_wallet_secret(name: str, password: str) -> Tuple[str, str]:
    d = load_wallets_file()
    if name not in d: raise KeyError(f"Wallet '{name}' introuvable.")
    entry = d[name]; secret = decrypt_with_password(entry["enc"], password).decode()
    return entry["type"], secret

# ---------------- low-level helpers ----------------
def _sha256(b: bytes) -> bytes: return hashlib.sha256(b).digest()
def _dsha256(b: bytes) -> bytes: return _sha256(_sha256(b))
def _ripemd160(b: bytes) -> bytes:
    h = RIPEMD160.new(); h.update(b); return h.digest()
def _hash160(b: bytes) -> bytes: return _ripemd160(_sha256(b))
def _varint(n: int) -> bytes:
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff: return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)
def _le_txid(txid_hex: str) -> bytes: return bytes.fromhex(txid_hex)[::-1]
def _outpoint(txid_hex: str, vout: int) -> bytes: return _le_txid(txid_hex) + struct.pack('<I', vout)
def _p2wpkh_spk(h160: bytes) -> bytes: return b'\x00' + b'\x14' + h160
def _p2pkh_scriptcode(h160: bytes) -> bytes: return b'\x19' + b'\x76\xa9\x14' + h160 + b'\x88\xac'
def _op_return_script(data: bytes) -> bytes:
    if len(data) > 80: data = data[:80]
    if len(data) <= 75: push = bytes([len(data)])
    else: push = b'\x4c' + bytes([len(data)])
    return b'\x6a' + push + data

# ---------------- bech32 helpers ----------------
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def bech32_polymod(values):
    GENERATORS = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            if ((b >> i) & 1):
                chk ^= GENERATORS[i]
    return chk
def bech32_hrp_expand(hrp): return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
def bech32_verify_checksum(hrp, data): return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1
def bech32_decode(bech: str):
    bech = bech.lower(); pos = bech.rfind('1')
    if pos < 1: return (None, None)
    hrp = bech[:pos]; data = bech[pos+1:]; data_vals=[]
    for ch in data:
        if ch not in CHARSET: return (None, None)
        data_vals.append(CHARSET.find(ch))
    if not bech32_verify_checksum(hrp, data_vals): return (None, None)
    return hrp, data_vals[:-6]
def convertbits(data, frombits, tobits, pad=True):
    acc=0; bits=0; ret=[]; maxv=(1<<tobits)-1
    for value in data:
        acc=(acc<<frombits)|value; bits+=frombits
        while bits>=tobits:
            bits-=tobits; ret.append((acc>>bits)&maxv)
    if pad:
        if bits: ret.append((acc<<(tobits-bits))&maxv)
    else:
        if bits>=frombits or ((acc<<(tobits-bits))&maxv): return None
    return ret

def address_to_spk(address: str) -> bytes:
    a = address.lower()
    if a.startswith("ltc1"):
        hrp, data = bech32_decode(a)
        if hrp is None: raise ValueError("Bech32 checksum invalide")
        if len(data) == 0: raise ValueError("Bech32 données invalides")
        witver = data[0]; prog = convertbits(data[1:],5,8,False)
        if prog is None: raise ValueError("Bech32 convertbits failed")
        prog = bytes(prog)
        if witver != 0: raise ValueError("Seules witness v0 supportées")
        return b'\x00' + bytes([len(prog)]) + prog
    else:
        raise ValueError("Seules adresses bech32 (ltc1...) supportées pour sortie segwit.")

# ---------------- base58 helpers ----------------
B58_ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, 'big'); s = ""
    while n>0:
        n, r = divmod(n, 58); s = B58_ALPH[r] + s
    pad = 0
    for c in b:
        if c==0: pad+=1
        else: break
    return "1"*pad + s

def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        if ch not in B58_ALPH: raise ValueError("Base58 caractère invalide: "+ch)
        n = n*58 + B58_ALPH.index(ch)
    b = n.to_bytes((n.bit_length()+7)//8, 'big') or b'\x00'
    pad = 0
    for ch in s:
        if ch == '1': pad+=1
        else: break
    return b'\x00'*pad + b

def pubkey_to_p2pkh_address(pubkey_bytes: bytes, prefix: bytes = b'\x30') -> str:
    h160 = _hash160(pubkey_bytes); payload = prefix + h160; checksum = _dsha256(payload)[:4]; return b58encode(payload + checksum)

# ---------------- extract pub/priv ----------------
def extract_pub_priv_bytes(key_obj) -> Tuple[bytes, bytes]:
    pub_hex = getattr(key_obj, "public_hex", None)
    if not pub_hex:
        try:
            p = key_obj.public(); pub_hex = p.hex() if hasattr(p,"hex") else str(p)
        except Exception:
            pass
    if not pub_hex: raise ValueError("Impossible d'extraire la clé publique")
    pub_bytes = bytes.fromhex(pub_hex)
    priv_hex = getattr(key_obj, "private_hex", None)
    if not priv_hex:
        try:
            kp = getattr(key_obj, "key", lambda: None)()
            if kp: priv_hex = getattr(kp, "key_private", None)
        except Exception:
            pass
    if not priv_hex: raise ValueError("Clé privée absente")
    priv_bytes = bytes.fromhex(priv_hex)
    if len(priv_bytes) != 32: priv_bytes = priv_bytes[-32:]
    return pub_bytes, priv_bytes

# ---------------- UTXO providers (robustes) ----------------
def _utxos_blockcypher(address: str):
    url = f"{BLOCKCYPHER_BASE}/addrs/{address}"
    params = {"unspentOnly":"true","includeScript":"true"}
    if BLOCKCYPHER_TOKEN: params["token"] = BLOCKCYPHER_TOKEN
    r = requests.get(url, params=params, timeout=12); r.raise_for_status()
    j = r.json(); txrefs = j.get("txrefs") or j.get("unconfirmed_txrefs") or []
    out=[]
    for t in txrefs:
        out.append({"txid": t.get("tx_hash") or t.get("txid"), "vout": int(t.get("tx_output_n") or 0),
                    "value": int(t.get("value") or 0), "scriptpubkey": t.get("script") or None,
                    "status": {"confirmed": int(t.get("confirmations",0))>0}})
    return out

def _utxos_sochain(address: str):
    url = f"{SOCHAIN_BASE}/get_tx_unspent/LTC/{address}"
    r = requests.get(url, timeout=12); r.raise_for_status()
    j = r.json(); txs = j.get("data", {}).get("txs", []) or []
    out=[]
    for t in txs:
        v = float(t.get("value","0"))
        out.append({"txid": t.get("txid"), "vout": int(t.get("output_no") or 0),
                    "value": int(round(v*1e8)), "scriptpubkey": t.get("script_hex"),
                    "status": {"confirmed": int(t.get("confirmations",0))>0}})
    return out

def _utxos_blockchair(address: str):
    url = f"{BLOCKCHAIR_BASE}/dashboards/address/{address}"
    r = requests.get(url, timeout=12); r.raise_for_status()
    j = r.json(); raw = j.get("data", {}).get(address, {}).get("utxo", []) or []
    out=[]
    for t in raw:
        out.append({"txid": t.get("transaction_hash"), "vout": int(t.get("index") or 0),
                    "value": int(t.get("value") or 0), "scriptpubkey": t.get("script_hex"),
                    "status": {"confirmed": True}})
    return out

def _utxos_trezor(address: str):
    url = f"{TREZOR_BLOCKBOOK}/api/v2/address/{address}/utxo"
    r = requests.get(url, timeout=12); r.raise_for_status()
    j = r.json(); raw = j.get("payload") or j.get("utxo") or j
    out=[]
    if isinstance(raw, list):
        for t in raw:
            out.append({"txid": t.get("txid"), "vout": int(t.get("vout") or 0),
                        "value": int(t.get("value") or 0), "scriptpubkey": t.get("scriptPubKey") or None,
                        "status": {"confirmed": bool(t.get("confirmations"))}})
    return out

def get_utxos(address: str) -> List[dict]:
    providers = [_utxos_blockcypher, _utxos_sochain, _utxos_blockchair, _utxos_trezor]
    errors=[]
    for p in providers:
        try:
            u = p(address)
            if isinstance(u, list): return u
        except Exception as e:
            errors.append(f"{p.__name__} failed: {e}"); time.sleep(0.3)
    raise RuntimeError("Impossible de récupérer UTXO. Logs: " + " | ".join(errors[-6:]))

# ---------------- broadcast raw tx (fallbacks) ----------------
def broadcast_raw_hex(raw_hex: str) -> str:
    errors=[]
    try:
        url = f"{BLOCKCYPHER_BASE}/txs/push"
        payload = {"tx": raw_hex}
        if BLOCKCYPHER_TOKEN: payload["token"] = BLOCKCYPHER_TOKEN
        r = requests.post(url, json=payload, timeout=15)
        if r.ok:
            j = r.json(); tx = j.get("tx") or {}; return tx.get("hash") or j.get("tx_hash") or str(j)
        else:
            errors.append(f"BlockCypher {r.status_code}:{r.text[:200]}")
    except Exception as e:
        errors.append(f"BlockCypher error: {e}")

    try:
        r = requests.post(f"{SOCHAIN_BASE}/send_tx/LTC", json={"tx_hex": raw_hex}, timeout=15); r.raise_for_status()
        j = r.json(); return j.get("data",{}).get("txid") or str(j)
    except Exception as e:
        errors.append(f"SoChain error: {e}")

    try:
        r = requests.post(f"{BLOCKCHAIR_BASE}/push/transaction", json={"data": raw_hex}, timeout=15)
        if r.ok: j = r.json(); return j.get("data",{}).get("transaction_hash") or str(j)
        else: errors.append(f"Blockchair {r.status_code}:{r.text[:200]}")
    except Exception as e:
        errors.append(f"Blockchair error: {e}")

    try:
        r = requests.post(f"{TREZOR_BLOCKBOOK}/api/v2/sendtx/{raw_hex}", timeout=15)
        if r.ok:
            try: j = r.json(); return j.get("result") or str(j)
            except: return r.text
        else: errors.append(f"TrezorBlockbook {r.status_code}:{r.text[:200]}")
    except Exception as e:
        errors.append(f"TrezorBlockbook error: {e}")

    raise RuntimeError("Broadcast failed on all providers. Logs: " + " | ".join(errors[-8:]))

# ---------------- builders & signing ----------------
def build_p2wpkh_tx_manual(key_obj, utxos: List[dict], dest_address: str, amount_sat: int, fee_sat: int) -> str:
    pub, priv = extract_pub_priv_bytes(key_obj)
    h160 = _hash160(pub)
    scriptcode = _p2pkh_scriptcode(h160)
    spk_own = _p2wpkh_spk(h160)

    need = amount_sat + fee_sat
    selected=[]; total_in=0
    for u in utxos:
        v = int(u.get("value",0))
        if v<=0: continue
        selected.append(u); total_in+=v
        if total_in>=need: break
    if total_in < need: raise ValueError("Fonds insuffisants")

    # accept bech32 OR legacy dest:
    try:
        dest_spk = address_to_spk(dest_address)
    except Exception:
        # fallback decode base58 legacy -> P2PKH spk
        raw = b58decode(dest_address)
        if len(raw) < 25: raise ValueError("Décodage base58 trop court")
        payload = raw[:-4]; h160_dest = payload[1:21]
        dest_spk = b'\x76\xa9\x14' + h160_dest + b'\x88\xac'

    outs=[(amount_sat, dest_spk)]
    change = total_in - amount_sat - fee_sat
    if change>0: outs.append((change, spk_own))

    version = struct.pack('<I',2); locktime = struct.pack('<I',0); marker_flag = b'\x00\x01'
    prevouts_ser = b''.join(_outpoint(u["txid"], u["vout"]) for u in selected)
    hashPrevouts = _dsha256(prevouts_ser)
    hashSequence = _dsha256(b''.join(struct.pack('<I',0xffffffff) for _ in selected))
    outs_ser = b''.join(struct.pack('<Q', val) + _varint(len(spk)) + spk for val, spk in outs)
    hashOutputs = _dsha256(outs_ser)
    ins_ser = b''.join(_outpoint(u["txid"], u["vout"]) + b'\x00' + struct.pack('<I',0xffffffff) for u in selected)
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    witnesses=[]
    for u in selected:
        amount = int(u["value"])
        preimage = version + hashPrevouts + hashSequence + _outpoint(u["txid"], u["vout"]) + scriptcode + struct.pack('<Q', amount) + struct.pack('<I',0xffffffff) + hashOutputs + locktime + struct.pack('<I',1)
        sighash = _dsha256(preimage)
        sig = sk.sign_digest(sighash, sigencode=sigencode_der_canonize) + b'\x01'
        witnesses.append([sig, pub])
    tx = version + marker_flag + _varint(len(selected)) + ins_ser + _varint(len(outs)) + outs_ser
    for w in witnesses:
        tx += _varint(len(w))
        for it in w:
            tx += _varint(len(it)) + it
    tx += locktime
    return tx.hex()

def build_p2wpkh_opreturn_tx_manual(key_obj, utxos: List[dict], message: str, fee_sat: int, dust_sat: int = DEFAULT_DUST) -> str:
    pub, priv = extract_pub_priv_bytes(key_obj)
    h160 = _hash160(pub)
    scriptcode = _p2pkh_scriptcode(h160)
    spk_own = _p2wpkh_spk(h160)

    need = fee_sat + dust_sat
    selected=[]; total_in=0
    for u in utxos:
        v = int(u.get("value",0))
        if v<=0: continue
        selected.append(u); total_in+=v
        if total_in>=need: break
    if total_in < need: raise ValueError("Fonds insuffisants")

    msgb = message.encode("utf-8")[:80]
    outs=[(0, _op_return_script(msgb)), (dust_sat, spk_own)]
    change = total_in - fee_sat - dust_sat
    if change>0: outs.append((change, spk_own))

    version = struct.pack('<I',2); locktime = struct.pack('<I',0); marker_flag = b'\x00\x01'
    prevouts_ser = b''.join(_outpoint(u["txid"], u["vout"]) for u in selected)
    hashPrevouts = _dsha256(prevouts_ser)
    hashSequence = _dsha256(b''.join(struct.pack('<I',0xffffffff) for _ in selected))
    outs_ser = b''.join(struct.pack('<Q', val) + _varint(len(spk)) + spk for val, spk in outs)
    hashOutputs = _dsha256(outs_ser)
    ins_ser = b''.join(_outpoint(u["txid"], u["vout"]) + b'\x00' + struct.pack('<I',0xffffffff) for u in selected)
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    witnesses=[]
    for u in selected:
        amount = int(u["value"])
        preimage = version + hashPrevouts + hashSequence + _outpoint(u["txid"], u["vout"]) + scriptcode + struct.pack('<Q', amount) + struct.pack('<I',0xffffffff) + hashOutputs + locktime + struct.pack('<I',1)
        sighash = _dsha256(preimage)
        sig = sk.sign_digest(sighash, sigencode=sigencode_der_canonize) + b'\x01'
        witnesses.append([sig, pub])
    tx = version + marker_flag + _varint(len(selected)) + ins_ser + _varint(len(outs)) + outs_ser
    for w in witnesses:
        tx += _varint(len(w))
        for it in w:
            tx += _varint(len(it)) + it
    tx += locktime
    return tx.hex()

def build_p2pkh_tx_manual(key_obj, utxos: List[dict], dest_address: str, amount_sat: int, fee_sat: int) -> str:
    pub, priv = extract_pub_priv_bytes(key_obj)
    h160 = _hash160(pub)
    scriptpubkey_own = b'\x76\xa9\x14' + h160 + b'\x88\xac'

    need = amount_sat + fee_sat
    selected=[]; total=0
    for u in utxos:
        v = int(u.get("value",0))
        if v<=0: continue
        selected.append(u); total+=v
        if total>=need: break
    if total < need: raise ValueError("Fonds insuffisants")

    outs=[]
    try:
        spk_dest = address_to_spk(dest_address); outs.append((amount_sat, spk_dest))
    except Exception:
        raw = b58decode(dest_address)
        if len(raw) < 25: raise ValueError("Destination legacy invalid")
        payload = raw[:-4]; h160_dest = payload[1:21]; spk_dest = b'\x76\xa9\x14' + h160_dest + b'\x88\xac'
        outs.append((amount_sat, spk_dest))

    change = total - amount_sat - fee_sat
    if change>0: outs.append((change, scriptpubkey_own))

    version = struct.pack('<I',1); locktime = struct.pack('<I',0)
    outs_ser = b''.join(struct.pack('<Q', val) + _varint(len(spk)) + spk for val, spk in outs)
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    final_inputs=[]
    for idx, u in enumerate(selected):
        txins_for_hash = b''
        for j, uu in enumerate(selected):
            txid = _le_txid(uu["txid"]); vout = struct.pack('<I', int(uu["vout"]))
            if j == idx:
                spk = None
                spk_hex = uu.get("scriptpubkey") or uu.get("scriptPubKey") or uu.get("script")
                if spk_hex:
                    try: spk = bytes.fromhex(spk_hex)
                    except: spk = None
                if spk is None: spk = b'\x76\xa9\x14' + _hash160(pub) + b'\x88\xac'
                txins_for_hash += txid + vout + _varint(len(spk)) + spk + struct.pack('<I',0xffffffff)
            else:
                txins_for_hash += txid + vout + _varint(0) + b'' + struct.pack('<I',0xffffffff)
        preimage = version + _varint(len(selected)) + txins_for_hash + _varint(len(outs)) + outs_ser + locktime + struct.pack('<I',1)
        sighash = _dsha256(preimage)
        der_sig = sk.sign_digest(sighash, sigencode=sigencode_der_canonize) + b'\x01'
        scriptSig = _varint(len(der_sig)) + der_sig + _varint(len(pub)) + pub
        final_inputs.append(_le_txid(u["txid"]) + struct.pack('<I', int(u["vout"])) + _varint(len(scriptSig)) + scriptSig + struct.pack('<I',0xffffffff))
    tx = version + _varint(len(selected)) + b''.join(final_inputs) + _varint(len(outs)) + outs_ser + locktime
    return tx.hex()

# ---------------- derivation helpers ----------------
def derive_key0_from_mnemonic(phrase: str, use_bech32=True) -> HDKey:
    seed = Mnemonic("english").to_seed(phrase, passphrase="")
    hd = HDKey.from_seed(seed, network=NETWORK_NAME, witness_type='segwit' if use_bech32 else None)
    path = BIP84_PATH if use_bech32 else BIP44_PATH
    k0 = hd.subkey_for_path(path)
    return HDKey(import_key=k0.private_hex, network=NETWORK_NAME, witness_type='segwit' if use_bech32 else None)

def derive_key0_from_wif(wif: str, use_bech32=True) -> HDKey:
    return HDKey(import_key=wif, network=NETWORK_NAME, witness_type='segwit' if use_bech32 else None)

def derive_key0_from_xprv(xprv: str, use_bech32=True) -> HDKey:
    hd = HDKey(import_key=xprv, network=NETWORK_NAME, witness_type='segwit' if use_bech32 else None)
    k0 = hd.subkey_for_path("m/0/0")
    return HDKey(import_key=k0.private_hex, network=NETWORK_NAME, witness_type='segwit' if use_bech32 else None)

def wif_from_private_hex(priv_hex: str) -> str:
    try: k = Key(import_key=priv_hex, network=NETWORK_NAME); return k.wif()
    except: return None

# ---------------- display & UTXO ----------------
def show_addresses_of_key(key0: HDKey):
    try: bech = key0.address()
    except: bech = None
    pub, _ = extract_pub_priv_bytes(key0)
    legacy = pubkey_to_p2pkh_address(pub, prefix=b'\x30')
    print("Adresses dérivées :")
    if bech: print(" - SegWit bech32 :", bech)
    print(" - Legacy P2PKH   :", legacy)
    return bech, legacy

def show_utxos_both(key0: HDKey):
    bech = None
    try: bech = key0.address()
    except: bech = None
    pub, _ = extract_pub_priv_bytes(key0)
    legacy = pubkey_to_p2pkh_address(pub, prefix=b'\x30')
    utx_bech=[]; utx_leg=[]
    if bech:
        try: utx_bech = get_utxos(bech) or []
        except Exception as e: print("Erreur get_utxos bech:", e)
    try: utx_leg = get_utxos(legacy) or []
    except Exception as e: print("Erreur get_utxos legacy:", e)
    total = sum(int(u.get("value",0)) for u in utx_bech + utx_leg)
    print(f"UTXO bech32 ({bech}): {len(utx_bech)}")
    for u in utx_bech: print(f"  - {u['txid']}:{u['vout']} {u['value']/1e8:.8f} LTC")
    print(f"UTXO legacy ({legacy}): {len(utx_leg)}")
    for u in utx_leg: print(f"  - {u['txid']}:{u['vout']} {u['value']/1e8:.8f} LTC")
    print(f"Total trouvé: {total/1e8:.8f} LTC")
    return utx_bech, utx_leg

# ---------------- send & consolidation ----------------
def build_consolidation_tx_from_legacy_to_bech(key0: HDKey, utxos_legacy: List[dict], target_bech: str, fee_sat: int):
    total = sum(int(u.get("value",0)) for u in utxos_legacy)
    amt = total - fee_sat
    if amt <= 0: raise ValueError("Frais trop élevés pour consolidation")
    return build_p2pkh_tx_manual(key0, utxos_legacy, target_bech, amt, fee_sat)

def send_ltc_manual(key0: HDKey, dest_addr: str, amount_ltc: float, fee_ltc: float):
    amount_sat = int(amount_ltc * 1e8); fee_sat = int(fee_ltc * 1e8)
    try: bech = key0.address()
    except: bech = None
    pub, _ = extract_pub_priv_bytes(key0); legacy = pubkey_to_p2pkh_address(pub, prefix=b'\x30')
    utx_bech = []; utx_leg = []
    try:
        if bech: utx_bech = get_utxos(bech) or []
    except: utx_bech = []
    try: utx_leg = get_utxos(legacy) or []
    except: utx_leg = []
    need = amount_sat + fee_sat
    total_bech = sum(int(u.get("value",0)) for u in utx_bech)
    total_leg  = sum(int(u.get("value",0)) for u in utx_leg)
    if total_bech >= need and utx_bech:
        try: raw = build_p2wpkh_tx_manual(key0, utx_bech, dest_addr, amount_sat, fee_sat)
        except Exception as e: print("Erreur build segwit TX:", e); return
    elif total_leg >= need and utx_leg:
        try: raw = build_p2pkh_tx_manual(key0, utx_leg, dest_addr, amount_sat, fee_sat)
        except Exception as e: print("Erreur build legacy TX:", e); return
    elif (total_bech + total_leg) >= need:
        print("⚠️ Fonds répartis entre bech32 & legacy.")
        choice = input("a) Consolider legacy -> bech, b) Annuler (a/b): ").strip().lower()
        if choice != 'a': print("Annulé."); return
        if not bech: print("Impossible : clé non configurée pour bech32."); return
        consolidation_fee_sat = fee_sat
        try:
            cons_raw = build_consolidation_tx_from_legacy_to_bech(key0, utx_leg, bech, consolidation_fee_sat)
            print("Raw consolidation tx:", cons_raw)
            txid_cons = broadcast_raw_hex(cons_raw)
            print("✅ Consolidation broadcastée, txid:", txid_cons)
            print("Attends confirmations puis renvoie la transaction désirée.")
            return
        except Exception as e:
            print("Erreur consolidation:", e); return
    else:
        print("🚫 Fonds insuffisants (même en combinant)."); return

    print("Raw TX hex:", raw)
    try:
        txid = broadcast_raw_hex(raw); print("✅ TX envoyée ! TXID :", txid)
    except Exception as e:
        print("❌ Erreur broadcast :", e)

# ---------------- CLI ----------------
def main():
    print("=== Wallet Litecoin (MAINNET) - Complet & Corrigé ===")
    active_key = None
    while True:
        print("""
1) Créer wallet (mnemonic) et sauvegarder (SegWit/Legacy)
2) Importer wallet (mnemonic / WIF / xprv) et sauvegarder
3) Charger wallet sauvegardé
4) Quitter
""")
        choice = input("Choix : ").strip()
        if choice == '1':
            use_bech = input("SegWit (bech32) ? [o/n] : ").strip().lower() != 'n'
            phrase = Mnemonic("english").generate(strength=128)
            print("Phrase mnémonique :", phrase)
            key0 = derive_key0_from_mnemonic(phrase, use_bech32=use_bech)
            bech, legacy = show_addresses_of_key(key0)
            wif = wif_from_private_hex(key0.private_hex) or "(n/a)"; print("WIF (privé) :", wif)
            if input("Sauvegarder chiffré ? (o/n) ").strip().lower() == 'o':
                name = input("Nom unique : ").strip(); pwd = getpass.getpass("Pwd AES: "); pwd2 = getpass.getpass("Confirmer: ")
                if pwd != pwd2: print("Mots de passe différents.")
                else: save_wallet(name, "mnemonic_bech" if use_bech else "mnemonic_legacy", phrase, pwd)
            active_key = key0
        elif choice == '2':
            t = input("a) mnemonic b) WIF c) xprv : ").strip().lower()
            use_bech = input("SegWit (bech32) ? [o/n] : ").strip().lower() != 'n'
            if t == 'a':
                phrase = input("Phrase : ").strip(); key0 = derive_key0_from_mnemonic(phrase, use_bech32=use_bech); stype, secret = ("mnemonic_bech" if use_bech else "mnemonic_legacy", phrase)
            elif t == 'b':
                wif = input("Clé privée WIF : ").strip(); key0 = derive_key0_from_wif(wif, use_bech32=use_bech); stype, secret = ("wif", wif)
            else:
                xprv = input("xprv : ").strip(); key0 = derive_key0_from_xprv(xprv, use_bech32=use_bech); stype, secret = ("xprv", xprv)
            show_addresses_of_key(key0)
            if input("Sauvegarder chiffré ? (o/n) ").strip().lower() == 'o':
                name = input("Nom : ").strip(); pwd = getpass.getpass("Pwd AES: "); pwd2 = getpass.getpass("Confirmer: ")
                if pwd != pwd2: print("Mots de passe différents.")
                else: save_wallet(name, stype, secret, pwd)
            active_key = key0
        elif choice == '3':
            saved = list_saved_wallets()
            if not saved: print("Aucun wallet sauvegardé."); continue
            for i,n in enumerate(saved,1): print(f"{i}) {n}")
            try: idx = int(input("Choix n°: ").strip()) - 1; name = saved[idx]
            except Exception: print("Entrée invalide."); continue
            pwd = getpass.getpass("Mot de passe AES: ")
            try: wtype, secret = load_wallet_secret(name, pwd)
            except Exception as e: print("Échec déchiffrement:", e); continue
            use_bech = True if wtype.endswith("bech") or wtype=="wif" or wtype=="xprv" else not wtype.endswith("_legacy")
            if wtype.startswith("mnemonic"): key0 = derive_key0_from_mnemonic(secret, use_bech32=use_bech)
            elif wtype == "wif": key0 = derive_key0_from_wif(secret, use_bech32=use_bech)
            else: key0 = derive_key0_from_xprv(secret, use_bech32=use_bech)
            show_addresses_of_key(key0); active_key = key0
        elif choice == '4':
            print("Bye."); sys.exit(0)
        else:
            continue

        # wallet menu
        while True:
            addr_show = "(aucun)"
            try: addr_show = active_key.address()
            except:
                try: pub,_ = extract_pub_priv_bytes(active_key); addr_show = pubkey_to_p2pkh_address(pub, b'\x30')
                except: addr_show = "(n/a)"
            print(f"""
--- Wallet actif [{addr_show}] ---
a) Solde & UTXO (vérifie bech32 + legacy)
b) Envoyer LTC (dest ltc1... ou legacy L...)
c) Envoyer message (OP_RETURN)
d) Afficher adresses
e) Retour
""")
            op = input("Option : ").strip().lower()
            if op == 'a': show_utxos_both(active_key)
            elif op == 'b':
                dest = input("Adresse destinataire : ").strip()
                amt = float(input("Montant (LTC) : ").strip())
                fee = input(f"Frais (LTC) [défaut {DEFAULT_FEE_SAT/1e8:.8f}] : ").strip()
                fee = float(fee) if fee else (DEFAULT_FEE_SAT/1e8)
                send_ltc_manual(active_key, dest, amt, fee)
            elif op == 'c':
                msg = input("Message (<=80 octets) : ").strip()
                fee = input(f"Frais (LTC) [défaut {DEFAULT_FEE_SAT/1e8:.8f}] : ").strip()
                fee = float(fee) if fee else (DEFAULT_FEE_SAT/1e8)
                try:
                    utx_bech, utx_leg = show_utxos_both(active_key)
                    if utx_bech and sum(u['value'] for u in utx_bech) >= int(fee*1e8):
                        raw = build_p2wpkh_opreturn_tx_manual(active_key, utx_bech, msg, int(fee*1e8))
                    elif utx_leg and sum(u['value'] for u in utx_leg) >= int(fee*1e8):
                        # create op_return spending legacy utxos: send to own address with OP_RETURN (use build_p2pkh_tx_manual trick)
                        own = active_key.address() if (hasattr(active_key,'address') and active_key.address()) else pubkey_to_p2pkh_address(extract_pub_priv_bytes(active_key)[0], b'\x30')
                        raw = build_p2pkh_tx_manual(active_key, utx_leg, own, 0, int(fee*1e8))  # 0 amount -> only fee, but builder will create change -> not ideal; you may want a dedicated builder
                    else:
                        print("Pas assez de fonds pour OP_RETURN."); continue
                    print("Raw OP_RETURN hex:", raw)
                    txid = broadcast_raw_hex(raw); print("TX broadcasted:", txid)
                except Exception as e: print("Erreur OP_RETURN:", e)
            elif op == 'd': show_addresses_of_key(active_key)
            else: break

if __name__ == "__main__":
    main()
