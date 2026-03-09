#!/usr/bin/env python3
"""
Wallet Testnet complet (CLI)
- Création / Import (mnemonic, WIF, xprv) / Sauvegarde chiffrée AES-GCM
- Affichage UTXO & solde (mempool.space)
- Envoi BTC (P2WPKH -> bech32 dest) construit & signé manuellement (BIP143)
- Envoi message OP_RETURN (<=80 bytes) construit & signé manuellement (BIP143)
- Diffusion via mempool.space POST (raw hex text/plain)
"""
import os
import sys
import json
import time
import base64
import getpass
import struct
import hashlib
import requests
from typing import List, Tuple

# crypto
from mnemonic import Mnemonic
from bitcoinlib.keys import HDKey, Key
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der_canonize
from Crypto.Hash import RIPEMD160
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# ------------------ CONFIG Testnet ------------------
BIP84_PATH = "m/84h/1h/0h/0/0"   # BIP84 Testnet index 0
UTXO_API = "https://mempool.space/testnet/api/address/{addr}/utxo"
BROADCAST_API = "https://mempool.space/testnet/api/tx"
WALLETS_FILE = "wallets_testnet.json"
# Default fees / dust
DEFAULT_FEE_SAT = 5000
DEFAULT_DUST = 1000

# ------------------ AES-GCM helpers (PBKDF2) ------------------
def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000, backend=default_backend())
    return kdf.derive(password.encode())

def encrypt_with_password(plaintext: bytes, password: str) -> dict:
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, None)
    return {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode()
    }

def decrypt_with_password(enc: dict, password: str) -> bytes:
    salt = base64.b64decode(enc["salt"])
    nonce = base64.b64decode(enc["nonce"])
    ct = base64.b64decode(enc["ciphertext"])
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, None)

# ------------------ Wallet storage ------------------
def load_wallets_file() -> dict:
    if not os.path.isfile(WALLETS_FILE):
        return {}
    try:
        with open(WALLETS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def save_wallets_file(data: dict):
    with open(WALLETS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def list_saved_wallets() -> List[str]:
    return list(load_wallets_file().keys())

def save_wallet(name: str, wtype: str, secret: str, password: str) -> bool:
    data = load_wallets_file()
    if name in data:
        print(f"❌ Le nom '{name}' existe déjà.")
        return False
    enc = encrypt_with_password(secret.encode(), password)
    data[name] = {"type": wtype, "enc": enc}
    save_wallets_file(data)
    print(f"✅ Wallet '{name}' sauvegardé et chiffré.")
    return True

def load_wallet_secret(name: str, password: str) -> Tuple[str, str]:
    data = load_wallets_file()
    if name not in data:
        raise KeyError(f"Wallet '{name}' introuvable.")
    entry = data[name]
    secret = decrypt_with_password(entry["enc"], password).decode()
    return entry["type"], secret

# ------------------ Utils: UTXO & broadcast ------------------
def get_utxos(address: str, retries: int = 3, wait: int = 2) -> List[dict]:
    url = UTXO_API.format(addr=address)
    for attempt in range(1, retries+1):
        try:
            r = requests.get(url, timeout=12)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            print(f"⚠️ UTXO fetch attempt {attempt}/{retries} failed: {e}")
            if attempt < retries:
                time.sleep(wait)
    raise RuntimeError("❌ Impossible de récupérer les UTXO (mempool.space).")

def broadcast_raw_hex(raw_hex: str, retries: int = 3, wait: int = 2) -> str:
    for attempt in range(1, retries+1):
        try:
            r = requests.post(BROADCAST_API, data=raw_hex, headers={"Content-Type":"text/plain"}, timeout=20)
            if r.ok:
                return r.text.strip()
            else:
                raise RuntimeError(f"{r.status_code} {r.text}")
        except Exception as e:
            print(f"⚠️ Broadcast attempt {attempt}/{retries} failed: {e}")
            if attempt < retries:
                time.sleep(wait)
    raise RuntimeError("❌ Broadcast échoué sur tous les fournisseurs.")

# ------------------ Low-level helpers for tx building ------------------
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

def _p2wpkh_spk(h160: bytes) -> bytes:
    # OP_0 <20>
    return b'\x00' + b'\x14' + h160

def _p2pkh_scriptcode(h160: bytes) -> bytes:
    # scriptCode for P2WPKH per BIP143: 0x19 0x76 0xa9 0x14 {20} 0x88 0xac
    return b'\x19' + b'\x76\xa9\x14' + h160 + b'\x88\xac'

def _op_return_script(data: bytes) -> bytes:
    if len(data) > 80:
        data = data[:80]
    if len(data) <= 75:
        push = bytes([len(data)])
    else:
        push = b'\x4c' + bytes([len(data)])  # OP_PUSHDATA1 for simplicity
    return b'\x6a' + push + data

# ------------------ Extract pub/priv bytes from bitcoinlib key objects ------------------
def extract_pub_priv_bytes(key_obj) -> Tuple[bytes, bytes]:
    """
    Retourne (pub_bytes, priv_bytes) à partir d'un objet HDKey ou Key.
    Lève ValueError si la clé privée est absente.
    """
    # try public
    pub_hex = getattr(key_obj, "public_hex", None)
    if not pub_hex:
        try:
            p = key_obj.public()
            pub_hex = p.hex() if hasattr(p, "hex") else str(p)
        except Exception:
            pass
    if not pub_hex:
        raise ValueError("Impossible d'extraire la clé publique.")
    pub_bytes = bytes.fromhex(pub_hex)

    # try private
    priv_hex = getattr(key_obj, "private_hex", None)
    if not priv_hex:
        # try nested attributes
        try:
            kp = getattr(key_obj, "key", lambda: None)()
            if kp:
                priv_hex = getattr(kp, "key_private", None)
        except Exception:
            pass
    if not priv_hex:
        raise ValueError("Clé privée absente (wallet en lecture seule ?).")
    priv_bytes = bytes.fromhex(priv_hex)
    if len(priv_bytes) != 32:
        # try trimming/padding (rare)
        priv_bytes = priv_bytes[-32:]
    return pub_bytes, priv_bytes

# ------------------ Bech32 decode minimal (only for v0 P2WPKH) ------------------
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            if ((b >> i) & 1):
                chk ^= GENERATORS[i]
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_verify_checksum(hrp, data):
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1

def bech32_decode(bech: str):
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1:
        return (None, None)
    hrp = bech[:pos]
    data = bech[pos+1:]
    data_vals = []
    for ch in data:
        if ch not in CHARSET:
            return (None, None)
        data_vals.append(CHARSET.find(ch))
    if not bech32_verify_checksum(hrp, data_vals):
        return (None, None)
    # remove checksum (last 6)
    return hrp, data_vals[:-6]

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    else:
        if bits >= frombits or ((acc << (tobits - bits)) & maxv):
            return None
    return ret

def address_to_spk(address: str) -> bytes:
    """
    Retourne le scriptPubKey bytes pour une adresse bech32 v0 (tb1 / bc1 v0).
    Pour l'instant on supporte seulement witness version 0 (P2WPKH / P2WSH).
    """
    addr = address.lower()
    if addr.startswith("tb1") or addr.startswith("bc1"):
        hrp, data = bech32_decode(addr)
        if hrp is None:
            raise ValueError("Bech32 decode failed (checksum?).")
        if len(data) == 0:
            raise ValueError("Bech32 invalid data.")
        witver = data[0]
        prog = convertbits(data[1:], 5, 8, False)
        if prog is None:
            raise ValueError("Bech32 convertbits failed.")
        prog = bytes(prog)
        if witver != 0:
            raise ValueError("Only bech32 v0 addresses supported by this script.")
        # scriptPubKey = OP_0 <push len> <prog>
        return b'\x00' + bytes([len(prog)]) + prog
    else:
        # Do not support legacy/P2PKH/P2SH here (keep it simple)
        raise ValueError("Seules les adresses bech32 (tb1...) sont supportées pour l'envoi actuellement.")

# ------------------ Manual transaction builders & signer (BIP143) ------------------

def build_p2wpkh_tx_manual(key_obj, utxos: List[dict], dest_address: str, amount_sat: int, fee_sat: int, dust_sat: int = DEFAULT_DUST) -> str:
    """
    Construit et signe une tx P2WPKH simple:
    - inputs: utxos selected until amount+fee covered
    - outputs: dest (bech32 only) + change (to self)
    Retourne raw hex signed.
    """
    pub, priv = extract_pub_priv_bytes(key_obj)
    h160 = _hash160(pub)
    scriptcode = _p2pkh_scriptcode(h160)
    spk_own = _p2wpkh_spk(h160)

    need = amount_sat + fee_sat
    selected = []
    total_in = 0
    for u in utxos:
        if not isinstance(u, dict):
            continue
        v = int(u.get("value", 0))
        if v <= 0:
            continue
        selected.append(u)
        total_in += v
        if total_in >= need:
            break
    if total_in < need:
        raise ValueError("Fonds insuffisants pour couvrir montant + frais.")

    # outputs
    outs = []
    # dest scriptPubKey from address
    dest_spk = address_to_spk(dest_address)
    outs.append((amount_sat, dest_spk))
    # change
    change = total_in - amount_sat - fee_sat
    if change > 0:
        outs.append((change, spk_own))

    # prepare BIP143 hashes
    version = struct.pack('<I', 2)
    locktime = struct.pack('<I', 0)
    marker_flag = b'\x00\x01'

    prevouts_ser = b''.join(_outpoint(u["txid"], u["vout"]) for u in selected)
    hashPrevouts = _dsha256(prevouts_ser)
    hashSequence = _dsha256(b''.join(struct.pack('<I', 0xffffffff) for _ in selected))
    outs_ser = b''.join(struct.pack('<Q', val) + _varint(len(spk)) + spk for val, spk in outs)
    hashOutputs = _dsha256(outs_ser)

    ins_ser = b''.join(_outpoint(u["txid"], u["vout"]) + b'\x00' + struct.pack('<I', 0xffffffff) for u in selected)

    sk = SigningKey.from_string(priv, curve=SECP256k1)

    witnesses = []
    for u in selected:
        amount = int(u["value"])
        preimage = (version + hashPrevouts + hashSequence +
                    _outpoint(u["txid"], u["vout"]) + scriptcode +
                    struct.pack('<Q', amount) + struct.pack('<I', 0xffffffff) +
                    hashOutputs + locktime + struct.pack('<I', 1))
        sighash = _dsha256(preimage)
        sig = sk.sign_digest(sighash, sigencode=sigencode_der_canonize) + b'\x01'
        witnesses.append([sig, pub])

    tx = version + marker_flag + _varint(len(selected)) + ins_ser + _varint(len(outs)) + outs_ser
    for w in witnesses:
        tx += _varint(len(w))
        for item in w:
            tx += _varint(len(item)) + item
    tx += locktime
    return tx.hex()

def build_p2wpkh_opreturn_tx_manual(key_obj, utxos: List[dict], message: str, fee_sat: int, dust_sat: int = DEFAULT_DUST) -> str:
    """
    Construire & signer une tx avec OP_RETURN message.
    - OP_RETURN (<=80 bytes)
    - dust output to self
    - change back to self
    """
    pub, priv = extract_pub_priv_bytes(key_obj)
    h160 = _hash160(pub)
    scriptcode = _p2pkh_scriptcode(h160)
    spk_own = _p2wpkh_spk(h160)

    # select utxos to cover (fee + dust)
    need = fee_sat + dust_sat
    selected = []
    total_in = 0
    for u in utxos:
        if not isinstance(u, dict):
            continue
        v = int(u.get("value", 0))
        if v <= 0:
            continue
        selected.append(u)
        total_in += v
        if total_in >= need:
            break
    if total_in < need:
        raise ValueError("Fonds insuffisants pour couvrir frais + dust.")

    # prepare outputs: OP_RETURN, dust, change
    msgb = message.encode("utf-8")[:80]
    outs = []
    outs.append((0, _op_return_script(msgb)))
    outs.append((dust_sat, spk_own))
    change = total_in - fee_sat - dust_sat
    if change > 0:
        outs.append((change, spk_own))

    # BIP143 precomputation
    version = struct.pack('<I', 2)
    locktime = struct.pack('<I', 0)
    marker_flag = b'\x00\x01'
    prevouts_ser = b''.join(_outpoint(u["txid"], u["vout"]) for u in selected)
    hashPrevouts = _dsha256(prevouts_ser)
    hashSequence = _dsha256(b''.join(struct.pack('<I', 0xffffffff) for _ in selected))
    outs_ser = b''.join(struct.pack('<Q', val) + _varint(len(spk)) + spk for val, spk in outs)
    hashOutputs = _dsha256(outs_ser)
    ins_ser = b''.join(_outpoint(u["txid"], u["vout"]) + b'\x00' + struct.pack('<I', 0xffffffff) for u in selected)

    sk = SigningKey.from_string(priv, curve=SECP256k1)
    witnesses = []
    for u in selected:
        amount = int(u["value"])
        preimage = (version + hashPrevouts + hashSequence + _outpoint(u["txid"], u["vout"]) + scriptcode +
                    struct.pack('<Q', amount) + struct.pack('<I', 0xffffffff) + hashOutputs + locktime + struct.pack('<I', 1))
        sighash = _dsha256(preimage)
        sig = sk.sign_digest(sighash, sigencode=sigencode_der_canonize) + b'\x01'
        witnesses.append([sig, pub])

    tx = version + marker_flag + _varint(len(selected)) + ins_ser + _varint(len(outs)) + outs_ser
    for w in witnesses:
        tx += _varint(len(w))
        for item in w:
            tx += _varint(len(item)) + item
    tx += locktime
    return tx.hex()

# ------------------ High-level wallet actions ------------------

def derive_key0_from_mnemonic(phrase: str) -> HDKey:
    seed = Mnemonic.to_seed(phrase, passphrase="")
    hd = HDKey.from_seed(seed, network='testnet', witness_type='segwit')
    k0 = hd.subkey_for_path(BIP84_PATH)
    return HDKey(import_key=k0.private_hex, network='testnet', witness_type='segwit')

def derive_key0_from_wif(wif: str) -> HDKey:
    return HDKey(import_key=wif, network='testnet', witness_type='segwit')

def derive_key0_from_xprv(xprv: str) -> HDKey:
    hd = HDKey(import_key=xprv, network='testnet', witness_type='segwit')
    k0 = hd.subkey_for_path("m/0/0")
    return HDKey(import_key=k0.private_hex, network='testnet', witness_type='segwit')

def wif_from_private_hex(priv_hex: str) -> str:
    try:
        k = Key(import_key=priv_hex, network='testnet')
        return k.wif()
    except Exception:
        return None

def show_utxos_and_balance_for_key(key0: HDKey):
    addr = key0.address()
    print(f"\n📮 Adresse index 0 : {addr}")
    try:
        utxos = get_utxos(addr)
    except Exception as e:
        print("❌ Erreur fetch UTXO :", e)
        return []
    if not utxos:
        print("🚫 Aucun UTXO (confirmé/mempool).")
        return []
    total = sum(int(u.get("value", 0)) for u in utxos)
    print(f"💰 Solde (incl. mempool) : {total/1e8:.8f} tBTC — {len(utxos)} UTXO(s)")
    for u in utxos:
        st = "✔" if u.get("status", {}).get("confirmed") else "🕓"
        print(f" • {u['value']/1e8:.8f} tBTC — {u['txid']}:{u['vout']} ({st})")
    return utxos

# ------------------ CLI: send BTC / send OP_RETURN wrappers ------------------
def send_btc_manual(key0: HDKey, dest_addr: str, amount_btc: float, fee_btc: float):
    amount_sat = int(amount_btc * 1e8)
    fee_sat = int(fee_btc * 1e8)
    addr = key0.address()
    utxos = get_utxos(addr)
    if not utxos:
        print("🚫 Aucun UTXO.")
        return
    # dest must be bech32 tb1...
    try:
        raw = build_p2wpkh_tx_manual(key0, utxos, dest_addr, amount_sat, fee_sat)
    except Exception as e:
        print("❌ Erreur construction TX :", e)
        return
    print("📝 Raw TX hex :", raw)
    try:
        txid = broadcast_raw_hex(raw)
        print("✅ TX envoyée ! TXID :", txid)
    except Exception as e:
        print("❌ Erreur broadcast :", e)

def send_message_opreturn_manual(key0: HDKey, message: str, fee_btc: float):
    fee_sat = int(fee_btc * 1e8)
    addr = key0.address()
    utxos = get_utxos(addr)
    if not utxos:
        print("🚫 Aucun UTXO.")
        return
    try:
        raw = build_p2wpkh_opreturn_tx_manual(key0, utxos, message, fee_sat)
    except Exception as e:
        print("❌ Erreur construction OP_RETURN :", e)
        return
    print("📝 Raw TX hex :", raw)
    try:
        txid = broadcast_raw_hex(raw)
        print("✅ TX envoyée ! TXID :", txid)
    except Exception as e:
        print("❌ Erreur broadcast :", e)

# ------------------ Main CLI ------------------
def main():
    print("=== Wallet Testnet (SegWit) — CLI complet ===")
    active_key = None

    while True:
        print("""
1) Créer un wallet (mnemonic) et sauvegarder
2) Importer un wallet (mnemonic / WIF / xprv) et sauvegarder (optionnel)
3) Charger un wallet sauvegardé
4) Quitter
""")
        choice = input("Choix : ").strip()
        if choice == '1':
            phrase = Mnemonic("english").generate(strength=128)
            print("🔑 Phrase mnémonique :", phrase)
            key0 = derive_key0_from_mnemonic(phrase)
            wif = wif_from_private_hex(key0.private_hex) or "(impossible de générer WIF)"
            print("📮 Adresse index 0 :", key0.address())
            print("🔑 WIF (privé) :", wif)
            if input("Sauvegarder ce wallet chiffré ? (o/n) : ").strip().lower() == 'o':
                name = input("Nom unique : ").strip()
                pwd = getpass.getpass("Mot de passe AES : ")
                pwd2 = getpass.getpass("Confirmez : ")
                if pwd != pwd2:
                    print("❌ Mots de passe différents. Abandon.")
                else:
                    save_wallet(name, "mnemonic", phrase, pwd)
            active_key = key0

        elif choice == '2':
            sub = input("a) Par phrase mnémonique\nb) Par WIF\nc) Par xprv\nChoix : ").strip().lower()
            if sub == 'a':
                phrase = input("Phrase (12/24 mots) : ").strip()
                key0 = derive_key0_from_mnemonic(phrase)
                secret_type, secret = "mnemonic", phrase
            elif sub == 'b':
                wif = input("Clé privée WIF (testnet) : ").strip()
                key0 = derive_key0_from_wif(wif)
                secret_type, secret = "wif", wif
            else:
                xprv = input("Clé étendue xprv (testnet) : ").strip()
                key0 = derive_key0_from_xprv(xprv)
                secret_type, secret = "xprv", xprv
            wif = wif_from_private_hex(key0.private_hex) or "(impossible de générer WIF)"
            print("📮 Adresse index 0 :", key0.address())
            print("🔑 WIF :", wif)
            if input("Sauvegarder chiffré ? (o/n) : ").strip().lower() == 'o':
                name = input("Nom unique : ").strip()
                pwd = getpass.getpass("Mot de passe AES : ")
                pwd2 = getpass.getpass("Confirmez : ")
                if pwd != pwd2:
                    print("❌ Mots de passe différents. Abandon.")
                else:
                    save_wallet(name, secret_type, secret, pwd)
            active_key = key0

        elif choice == '3':
            saved = list_saved_wallets()
            if not saved:
                print("🚫 Aucun wallet sauvegardé.")
                continue
            for i, n in enumerate(saved, 1):
                print(f"{i}) {n}")
            try:
                idx = int(input("Choisissez un wallet (numéro) : ").strip()) - 1
                if idx < 0 or idx >= len(saved):
                    print("❌ Index invalide."); continue
                name = saved[idx]
            except Exception:
                print("❌ Entrée invalide."); continue
            pwd = getpass.getpass("Mot de passe AES : ")
            try:
                wtype, secret = load_wallet_secret(name, pwd)
            except Exception as e:
                print("❌ Échec déchiffrement :", e); continue
            if wtype == 'mnemonic':
                key0 = derive_key0_from_mnemonic(secret)
            elif wtype == 'wif':
                key0 = derive_key0_from_wif(secret)
            else:
                key0 = derive_key0_from_xprv(secret)
            wif = wif_from_private_hex(key0.private_hex) or "(impossible de générer WIF)"
            print("📮 Adresse index 0 :", key0.address())
            print("🔑 WIF :", wif)
            active_key = key0

        elif choice == '4':
            print("Bye.")
            sys.exit(0)
        else:
            continue

        # === menu wallet actif (ne change rien à tes anciennes options) ===
        while True:
            addr = active_key.address() if active_key else "(aucun)"
            print(f"""
--- Wallet actif [{addr}] ---
a) Solde & UTXO
b) Envoyer tBTC (bech32 dest uniquement)
c) Envoyer message (OP_RETURN)
d) Retour au menu principal
""")
            op = input("Option : ").strip().lower()
            if op == 'a':
                show_utxos_and_balance_for_key(active_key)
            elif op == 'b':
                dest = input("Adresse destinataire (tb1...) : ").strip()
                amt = float(input("Montant (tBTC) : ").strip())
                fee = input(f"Frais (tBTC) [défaut {DEFAULT_FEE_SAT/1e8:.8f}] : ").strip()
                fee = float(fee) if fee else (DEFAULT_FEE_SAT/1e8)
                send_btc_manual(active_key, dest, amt, fee)
            elif op == 'c':
                msg = input("Message à écrire (<=80 octets) : ").strip()
                fee = input(f"Frais (tBTC) [défaut {DEFAULT_FEE_SAT/1e8:.8f}] : ").strip()
                fee = float(fee) if fee else (DEFAULT_FEE_SAT/1e8)
                send_message_opreturn_manual(active_key, msg, fee)
            else:
                break

if __name__ == "__main__":
    main()
