#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import getpass
import hmac
import hashlib
import struct
from typing import Dict, List, Tuple

from mnemonic import Mnemonic
from ecdsa import SigningKey, SECP256k1

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import RIPEMD160
from Crypto.Hash import keccak

WALLETS_FILE = "wallets_multi_pure.json"
PBKDF2_ROUNDS = 200_000

# ---------------------------------------------------------------------------
# COINS SUPPORTÉS (SANS bip-utils)
# ---------------------------------------------------------------------------

COINS = {
    # code : (nom lisible, type d'adresse, coin_type BIP44)
    "xec":   ("eCash",              "cashaddr_ecash",       899),
    "bch":   ("Bitcoin Cash",       "cashaddr_bch",         145),
    "eth":   ("Ethereum",           "evm",                  60),
    "bnb":   ("Binance SmartChain", "evm",                  60),
    "matic": ("Polygon",            "evm",                  60),
}

# ---------------------------------------------------------------------------
# STORE JSON : on stocke une LISTE de wallets pour pouvoir les sélectionner par N°
# ---------------------------------------------------------------------------

def load_store() -> List[Dict]:
    if not os.path.exists(WALLETS_FILE):
        return []
    try:
        with open(WALLETS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict) and "wallets" in data:
                return data["wallets"]
            else:
                return []
    except Exception:
        return []


def save_store(wallets: List[Dict]) -> None:
    with open(WALLETS_FILE, "w", encoding="utf-8") as f:
        json.dump({"wallets": wallets}, f, indent=2, ensure_ascii=False)

# ---------------------------------------------------------------------------
# AES-GCM (chiffrement mnémonique ou clé privée)
# ---------------------------------------------------------------------------

def _derive_aes_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password.encode("utf-8"), salt, dkLen=32, count=PBKDF2_ROUNDS)


def aes_encrypt_str(plaintext: str, password: str) -> Dict[str, str]:
    salt = get_random_bytes(16)
    key = _derive_aes_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return {
        "salt": salt.hex(),
        "nonce": cipher.nonce.hex(),
        "tag": tag.hex(),
        "ct": ct.hex(),
    }


def aes_decrypt_str(enc: Dict[str, str], password: str) -> str:
    salt = bytes.fromhex(enc["salt"])
    nonce = bytes.fromhex(enc["nonce"])
    tag = bytes.fromhex(enc["tag"])
    ct = bytes.fromhex(enc["ct"])
    key = _derive_aes_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)
    return pt.decode("utf-8")

# ---------------------------------------------------------------------------
# BIP39 / BIP32 MAISON
# ---------------------------------------------------------------------------

def generate_mnemonic(words: int = 12) -> str:
    mn = Mnemonic("english")
    if words == 24:
        return mn.generate(strength=256)
    return mn.generate(strength=128)


def seed_from_mnemonic(mnemonic: str, passphrase: str = "") -> bytes:
    mn = Mnemonic("english")
    return mn.to_seed(mnemonic, passphrase=passphrase)


def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()


def master_from_seed(seed: bytes) -> Tuple[bytes, bytes]:
    I = hmac_sha512(b"Bitcoin seed", seed)
    return I[:32], I[32:]


def ckd_priv(k_parent: bytes, c_parent: bytes, index: int) -> Tuple[bytes, bytes]:
    if index >= 0x80000000:
        data = b"\x00" + k_parent + struct.pack(">I", index)
    else:
        sk = SigningKey.from_string(k_parent, curve=SECP256k1)
        vk = sk.get_verifying_key()
        x = vk.to_string()[:32]
        y = vk.to_string()[32:]
        pub = (b"\x02" if (y[-1] % 2 == 0) else b"\x03") + x
        data = pub + struct.pack(">I", index)
    I = hmac_sha512(c_parent, data)
    Il, Ir = I[:32], I[32:]
    Il_int = int.from_bytes(Il, "big")
    k_parent_int = int.from_bytes(k_parent, "big")
    n = SECP256k1.order
    k_i = (Il_int + k_parent_int) % n
    return k_i.to_bytes(32, "big"), Ir


def derive_path(seed: bytes, path: str) -> bytes:
    if not path.startswith("m/"):
        raise ValueError("Le chemin doit commencer par m/")
    k, c = master_from_seed(seed)
    for seg in path[2:].split("/"):
        if seg.endswith("'"):
            idx = int(seg[:-1]) + 0x80000000
        else:
            idx = int(seg)
        k, c = ckd_priv(k, c, idx)
    return k

# ---------------------------------------------------------------------------
# KEYS & ADRESSES
# ---------------------------------------------------------------------------

def priv_to_pub(priv_bytes: bytes, compressed: bool = True) -> bytes:
    sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.to_string()[:32]
    y = vk.to_string()[32:]
    if not compressed:
        return b"\x04" + x + y
    return (b"\x02" if (y[-1] % 2 == 0) else b"\x03") + x


def hash160(b: bytes) -> bytes:
    h = hashlib.sha256(b).digest()
    r = RIPEMD160.new()
    r.update(h)
    return r.digest()

# base58 (WIF)
B58_ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
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
            raise ValueError("Caractère base58 invalide: " + ch)
        n = n * 58 + B58_ALPH.index(ch)
    h = n.to_bytes((n.bit_length() + 7) // 8, "big") or b"\x00"
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + h

def base58check_encode(version: bytes, payload: bytes) -> str:
    raw = version + payload
    chk = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    return b58encode(raw + chk)

def base58check_decode(s: str) -> bytes:
    raw = b58decode(s)
    if len(raw) < 4:
        raise ValueError("Trop court pour base58check")
    payload, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != chk:
        raise ValueError("Checksum base58check invalide")
    return payload

def priv_to_wif(priv_bytes: bytes, compressed: bool = True) -> str:
    payload = priv_bytes + (b"\x01" if compressed else b"")
    return base58check_encode(b"\x80", payload)

def wif_to_priv(wif: str) -> Tuple[bytes, bool]:
    payload = base58check_decode(wif)
    if payload[0] != 0x80:
        raise ValueError("WIF version différente de 0x80")
    if len(payload) == 34 and payload[-1] == 0x01:
        return payload[1:-1], True
    elif len(payload) == 33:
        return payload[1:], False
    else:
        raise ValueError("Longueur WIF inattendue")

# ---------------------------------------------------------------------------
# CASHADDR (eCash / Bitcoin Cash) ENCODE
# ---------------------------------------------------------------------------

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
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

def _bech32_polymod(values):
    GENERATORS = [0x98f2bc8e61,0x79b76d99e2,0xf33e5fb3c4,0xae2eabe2a8,0x1e4f43e470]
    chk = 1
    for v in values:
        top = chk >> 35
        chk = ((chk & 0x07ffffffff) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= GENERATORS[i]
    return chk

def _expand_hrp(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def _create_checksum(hrp, values):
    polymod = _bech32_polymod(_expand_hrp(hrp) + values + [0]*8) ^ 1
    return [(polymod >> (5*(7-i))) & 31 for i in range(8)]

def _encode_cashaddr(hrp, payload5):
    chk = _create_checksum(hrp, payload5)
    combined = payload5 + chk
    return hrp + ':' + ''.join(CHARSET[d] for d in combined)

def pub_to_cashaddr(pub_bytes: bytes, prefix: str) -> str:
    h160 = hash160(pub_bytes)      # 20 bytes
    version = 0                    # P2PKH 160-bit
    payload5 = [version] + _convertbits(h160, 8, 5)
    return _encode_cashaddr(prefix, payload5)

# ---------------------------------------------------------------------------
# EVM ADDRESS (ETH / BSC / POLYGON)
# ---------------------------------------------------------------------------

def priv_to_evm_address(priv_bytes: bytes) -> str:
    sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.to_string()[:32]
    y = vk.to_string()[32:]
    uncompressed = b"\x04" + x + y
    k = keccak.new(digest_bits=256)
    k.update(uncompressed[1:])
    addr_bytes = k.digest()[-20:]
    return "0x" + addr_bytes.hex()

# ---------------------------------------------------------------------------
# DÉRIVATION PAR COIN (HD, mnémonique)
# ---------------------------------------------------------------------------

def derive_priv_for_coin(mnemonic: str, coin_code: str) -> bytes:
    if coin_code not in COINS:
        raise ValueError(f"Coin non supporté: {coin_code}")
    _, _, coin_type = COINS[coin_code]
    seed = seed_from_mnemonic(mnemonic)
    path = f"m/44'/{coin_type}'/0'/0/0"
    return derive_path(seed, path)


def derive_addr_priv_for_coin(mnemonic: str, coin_code: str) -> Tuple[str, str, str]:
    if coin_code not in COINS:
        raise ValueError(f"Coin non supporté: {coin_code}")
    name, addr_type, _ = COINS[coin_code]
    priv = derive_priv_for_coin(mnemonic, coin_code)
    priv_hex = priv.hex()

    if addr_type.startswith("cashaddr"):
        pub = priv_to_pub(priv, compressed=True)
        if addr_type == "cashaddr_ecash":
            addr = pub_to_cashaddr(pub, "ecash")
        elif addr_type == "cashaddr_bch":
            addr = pub_to_cashaddr(pub, "bitcoincash")
        else:
            raise ValueError("Type cashaddr inconnu")
        wif = priv_to_wif(priv, compressed=True)
        return addr, priv_hex, wif

    elif addr_type == "evm":
        addr = priv_to_evm_address(priv)
        return addr, priv_hex, ""

    else:
        raise ValueError("Type d'adresse interne inconnu")

# ---------------------------------------------------------------------------
# DÉRIVATION PAR COIN (clé privée brute)
# ---------------------------------------------------------------------------

def addr_priv_from_raw_priv(coin_code: str, priv_hex: str) -> Tuple[str, str, str]:
    if coin_code not in COINS:
        raise ValueError(f"Coin non supporté: {coin_code}")
    name, addr_type, _ = COINS[coin_code]
    priv = bytes.fromhex(priv_hex)

    if addr_type.startswith("cashaddr"):
        pub = priv_to_pub(priv, compressed=True)
        if addr_type == "cashaddr_ecash":
            addr = pub_to_cashaddr(pub, "ecash")
        elif addr_type == "cashaddr_bch":
            addr = pub_to_cashaddr(pub, "bitcoincash")
        else:
            raise ValueError("Type cashaddr inconnu")
        wif = priv_to_wif(priv, compressed=True)
        return addr, priv_hex, wif

    elif addr_type == "evm":
        addr = priv_to_evm_address(priv)
        return addr, priv_hex, ""

    else:
        raise ValueError("Type d'adresse interne inconnu")

# ---------------------------------------------------------------------------
# CRÉATION / IMPORT (MNEMONIC + PRIVKEY) — STOCKAGE LISTE + ID NUMÉRIQUE
# ---------------------------------------------------------------------------

def create_wallet(wallets: List[Dict]) -> None:
    print("=== Création d’un nouveau wallet HD (sans bip-utils) ===")
    print("Coins disponibles :")
    for code, (name, _, _) in COINS.items():
        print(f"  - {code} -> {name}")
    coin_code = input("Code coin (xec, bch, eth, bnb, matic) : ").strip().lower()
    if coin_code not in COINS:
        print("❌ Coin inconnu")
        return

    label = input("Label (nom affiché) : ").strip()
    if not label:
        label = f"wallet_{len(wallets)+1}"

    words = input("Nombre de mots (12 ou 24, défaut 12) : ").strip()
    if words == "24":
        mnemonic = generate_mnemonic(24)
    else:
        mnemonic = generate_mnemonic(12)

    print("\n🔑 Mnémonique (BIP-39, à sauvegarder OFFLINE) :")
    print(mnemonic)
    print("--------------------------------------------------------")

    password = getpass.getpass("Mot de passe pour chiffrer ce wallet : ")
    if not password:
        print("❌ Mot de passe vide, annulation.")
        return

    try:
        addr, priv_hex, wif = derive_addr_priv_for_coin(mnemonic, coin_code)
    except Exception as e:
        print("❌ Erreur dérivation HD :", e)
        return

    print(f"\n✅ Wallet créé pour {COINS[coin_code][0]} (index 0)")
    print(f"📮 Adresse : {addr}")
    print(f"🔐 Clé privée (hex) : {priv_hex}")
    if wif:
        print(f"🔐 Clé privée WIF   : {wif}")
    print("")

    enc = aes_encrypt_str(mnemonic, password)
    wallet_entry = {
        "label": label,
        "coin": coin_code,
        "kind": "mnemonic",
        "mnemonic_enc": enc,
    }
    wallets.append(wallet_entry)
    save_store(wallets)
    print(f"💾 Wallet sauvegardé dans {WALLETS_FILE} sous le numéro {len(wallets)}\n")


def import_wallet_mnemonic(wallets: List[Dict]) -> None:
    print("=== Import d’un wallet HD (mnémonique) ===")
    print("Coins disponibles :")
    for code, (name, _, _) in COINS.items():
        print(f"  - {code} -> {name}")
    coin_code = input("Code coin (xec, bch, eth, bnb, matic) : ").strip().lower()
    if coin_code not in COINS:
        print("❌ Coin inconnu")
        return

    label = input("Label (nom affiché) : ").strip()
    if not label:
        label = f"wallet_{len(wallets)+1}"

    mnemonic = input("Mnémonique BIP-39 (12 ou 24 mots) : ").strip()
    if len(mnemonic.split()) < 12:
        print("⚠️ Ça ressemble à moins de 12 mots, vérifie bien.")

    password = getpass.getpass("Mot de passe pour chiffrer ce wallet : ")
    if not password:
        print("❌ Mot de passe vide, annulation.")
        return

    try:
        addr, priv_hex, wif = derive_addr_priv_for_coin(mnemonic, coin_code)
    except Exception as e:
        print("❌ Erreur dérivation HD :", e)
        return

    print(f"\n✅ Wallet importé (mnémonique) pour {COINS[coin_code][0]}")
    print(f"📮 Adresse index 0 : {addr}")
    print(f"🔐 Clé privée (hex) : {priv_hex}")
    if wif:
        print(f"🔐 Clé privée WIF   : {wif}")
    print("")

    enc = aes_encrypt_str(mnemonic, password)
    wallet_entry = {
        "label": label,
        "coin": coin_code,
        "kind": "mnemonic",
        "mnemonic_enc": enc,
    }
    wallets.append(wallet_entry)
    save_store(wallets)
    print(f"💾 Wallet sauvegardé dans {WALLETS_FILE} sous le numéro {len(wallets)}\n")


def import_wallet_privkey(wallets: List[Dict]) -> None:
    print("=== Import d’un wallet par CLÉ PRIVÉE ===")
    print("Coins disponibles :")
    for code, (name, _, _) in COINS.items():
        print(f"  - {code} -> {name}")
    coin_code = input("Code coin (xec, bch, eth, bnb, matic) : ").strip().lower()
    if coin_code not in COINS:
        print("❌ Coin inconnu")
        return

    label = input("Label (nom affiché) : ").strip()
    if not label:
        label = f"wallet_{len(wallets)+1}"

    key_str = input("Clé privée (HEX 64chars ou WIF) : ").strip()

    priv_bytes = None
    if key_str.startswith("0x") and len(key_str) == 66:
        priv_bytes = bytes.fromhex(key_str[2:])
    else:
        is_hex = len(key_str) == 64 and all(c in "0123456789abcdefABCDEF" for c in key_str)
        if is_hex:
            priv_bytes = bytes.fromhex(key_str)
        else:
            try:
                priv_bytes, _ = wif_to_priv(key_str)
            except Exception as e:
                print("❌ Ni HEX 32 bytes, ni WIF valide :", e)
                return

    priv_hex = priv_bytes.hex()
    password = getpass.getpass("Mot de passe pour chiffrer ce wallet : ")
    if not password:
        print("❌ Mot de passe vide, annulation.")
        return

    try:
        addr, priv_hex_check, wif = addr_priv_from_raw_priv(coin_code, priv_hex)
    except Exception as e:
        print("❌ Erreur création adresse depuis cette clé :", e)
        return

    print(f"\n✅ Wallet importé (clé privée) pour {COINS[coin_code][0]}")
    print(f"📮 Adresse : {addr}")
    print(f"🔐 Clé privée (hex) : {priv_hex_check}")
    if wif:
        print(f"🔐 Clé privée WIF   : {wif}")
    print("")

    enc = aes_encrypt_str(priv_hex, password)
    wallet_entry = {
        "label": label,
        "coin": coin_code,
        "kind": "priv",
        "priv_enc": enc,
    }
    wallets.append(wallet_entry)
    save_store(wallets)
    print(f"💾 Wallet sauvegardé dans {WALLETS_FILE} sous le numéro {len(wallets)}\n")

# ---------------------------------------------------------------------------
# LISTER / CHOISIR PAR NUMÉRO / CHARGER
# ---------------------------------------------------------------------------

def list_wallets(wallets: List[Dict]) -> None:
    if not wallets:
        print("Aucun wallet enregistré.")
        return
    print("=== Wallets enregistrés ===")
    for idx, w in enumerate(wallets, start=1):
        code = w.get("coin", "?")
        coin_name = COINS.get(code, ("???", "", 0))[0]
        kind = w.get("kind", "?")
        label = w.get("label", f"wallet_{idx}")
        print(f"{idx}) {label}  [{code} -> {coin_name}, {kind}]")
    print("")


def select_wallet(wallets: List[Dict]) -> Tuple[int, Dict]:
    if not wallets:
        print("Aucun wallet.")
        return -1, {}
    list_wallets(wallets)
    choice = input("Numéro du wallet : ").strip()
    try:
        n = int(choice)
    except Exception:
        print("❌ Entrée invalide")
        return -1, {}
    if not (1 <= n <= len(wallets)):
        print("❌ Numéro hors plage")
        return -1, {}
    return n - 1, wallets[n - 1]


def load_and_show(wallets: List[Dict]) -> None:
    idx, meta = select_wallet(wallets)
    if idx < 0:
        return

    coin_code = meta["coin"]
    coin_name = COINS.get(coin_code, ("???", "", 0))[0]
    kind = meta.get("kind", "mnemonic")
    label = meta.get("label", f"wallet_{idx+1}")

    print(f"Wallet #{idx+1} — {label} — coin {coin_code} ({coin_name}), type={kind}")

    password = getpass.getpass("Mot de passe pour déchiffrer : ")
    try:
        if kind == "mnemonic":
            mnemonic = aes_decrypt_str(meta["mnemonic_enc"], password)
            addr, priv_hex, wif = derive_addr_priv_for_coin(mnemonic, coin_code)
        elif kind == "priv":
            priv_hex = aes_decrypt_str(meta["priv_enc"], password)
            addr, priv_hex, wif = addr_priv_from_raw_priv(coin_code, priv_hex)
        else:
            print("❌ Type de wallet inconnu dans le JSON")
            return
    except Exception as e:
        print("❌ Erreur déchiffrement / dérivation :", e)
        return

    print("\n=== DÉTAILS WALLET ===")
    print(f"Label      : {label}")
    print(f"Coin       : {coin_code} ({coin_name})")
    print(f"Type       : {kind}")
    if kind == "mnemonic":
        print(f"🧠 Mnémonique : {mnemonic}")
    print(f"📮 Adresse      : {addr}")
    print(f"🔐 Clé privée hex : {priv_hex}")
    if wif:
        print(f"🔐 Clé privée WIF : {wif}")
    print("=======================\n")

# ---------------------------------------------------------------------------
# MAIN CLI
# ---------------------------------------------------------------------------

def main():
    wallets = load_store()
    while True:
        print("""
=== Multi-wallet (sans bip-utils, avec sélection NUMÉRO) ===
1. Créer un nouveau wallet (mnémonique)
2. Importer un wallet (mnémonique)
3. Importer un wallet (clé privée WIF / HEX)
4. Lister les wallets
5. Charger un wallet et afficher adresse + clé privée
6. Quitter
""")
        choice = input("Choix : ").strip()

        if choice == "1":
            create_wallet(wallets)
            wallets = load_store()
        elif choice == "2":
            import_wallet_mnemonic(wallets)
            wallets = load_store()
        elif choice == "3":
            import_wallet_privkey(wallets)
            wallets = load_store()
        elif choice == "4":
            list_wallets(wallets)
        elif choice == "5":
            load_and_show(wallets)
        elif choice == "6":
            sys.exit(0)
        else:
            print("Choix invalide.\n")


if __name__ == "__main__":
    main()
