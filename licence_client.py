import json
import time
import base64
import hashlib
import hmac
import platform
import subprocess
import uuid
from pathlib import Path
from typing import Optional

import requests
from cryptography.fernet import Fernet, InvalidToken


# ==========================
#  CONFIG GÉNÉRALE
# ==========================

# URL de base de l'API License Manager
BASE_URL = "https://valentinoscript.com/wp-json/lmfwc/v2"

# Tes clés REST API du plugin License Manager for WooCommerce
API_KEY = "ck_975227fc8b38b1fed6496a5cac8ec517de45ed05"      # consumer key
API_SECRET = "cs_7a6cd09895f984b0ffc8a194727ba5e80c8d49da"   # consumer secret

# Secret interne de l'application (à changer par une valeur bien random)
# Garde ça privé, ne le partage pas.
APP_SECRET = b"change-this-to-a-very-random-secret-key-32bytes-min"
# APP_SECRET = b"9498888KjfkUH2nsospsocRZRAZ"
# Dossier / fichier de stockage local
CONFIG_DIR = Path.home() / ".valentinoscript_app"
CONFIG_FILE = CONFIG_DIR / "license.dat"

# Délai de grâce hors-ligne (en secondes) après la DERNIÈRE validation OK
OFFLINE_GRACE = 2 * 24 * 3600  # 2 jours


class LicenseError(Exception):
    """Erreur côté licence (clé invalide, expirée, crack, etc.)."""
    pass


# ==========================
#  DEVICE ID (BINDING MACHINE)
# ==========================

def get_device_id() -> str:
    """
    Retourne un identifiant de machine stable (mais pas trivial à falsifier).
    On combine plusieurs infos (UUID carte mère, hostname, MAC).
    """
    parts = []

    # UUID matériel (Windows)
    try:
        if platform.system().lower() == "windows":
            output = subprocess.check_output(
                ["wmic", "csproduct", "get", "uuid"],
                stderr=subprocess.DEVNULL,
                text=True
            )
            lines = [l.strip() for l in output.splitlines() if l.strip() and "UUID" not in l.upper()]
            if lines:
                parts.append(lines[0])
    except Exception:
        pass

    # Hostname
    try:
        parts.append(platform.node())
    except Exception:
        pass

    # MAC address
    try:
        parts.append(hex(uuid.getnode()))
    except Exception:
        pass

    raw = "|".join(p for p in parts if p)
    if not raw:
        raw = "fallback-device-id"

    # On hash pour normaliser
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ==========================
#  CHIFFREMENT LOCAL
# ==========================

def _derive_key(license_key: str, token: str, device_id: str) -> bytes:
    """
    Dérive une clé Fernet à partir de:
      - license_key
      - token d'activation
      - device_id
      - APP_SECRET (clé interne)
    Ça fait que:
      - un autre PC (device_id différent) ne pourra pas déchiffrer
      - un changement de licence ou de token invalide le fichier
    """
    material = f"{license_key}|{token}|{device_id}".encode("utf-8")
    digest = hmac.new(APP_SECRET, material, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest)


def _save_encrypted(payload: dict) -> None:
    """
    Sauvegarde la licence chiffrée dans CONFIG_FILE.
    On garde un header clair (license_key + token) + données chiffrées.
    """
    device_id = payload["device_id"]
    license_key = payload["license_key"]
    token = payload["token"]

    key = _derive_key(license_key, token, device_id)
    f = Fernet(key)

    inner = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ciphertext = f.encrypt(inner).decode("utf-8")

    file_obj = {
        "header": {
            "license_key": license_key,
            "token": token,
        },
        "data": ciphertext,
    }

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f_out:
        json.dump(file_obj, f_out, separators=(",", ":"))


def _load_encrypted() -> Optional[dict]:
    """
    Charge et déchiffre le fichier de licence.
    Retourne None si :
      - fichier manquant
      - signature cryptographique invalide
      - device_id différentv
    """
    if not CONFIG_FILE.exists():
        return None

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f_in:
            obj = json.load(f_in)
        header = obj.get("header") or {}
        license_key = header.get("license_key")
        token = header.get("token")
        ciphertext = obj.get("data")
        if not (license_key and token and ciphertext):
            return None

        device_id = get_device_id()
        key = _derive_key(license_key, token, device_id)
        f = Fernet(key)
        plaintext = f.decrypt(ciphertext.encode("utf-8"))
        payload = json.loads(plaintext.decode("utf-8"))

        # Cohérence interne
        if (
            payload.get("license_key") != license_key
            or payload.get("token") != token
            or payload.get("device_id") != device_id
        ):
            return None

        return payload

    except (InvalidToken, json.JSONDecodeError, OSError, KeyError):
        return None
    return None



# ==========================
#  APPELS API LMFWC
# ==========================

def _api_get(path: str) -> dict:
    """
    Appel générique GET vers l'API License Manager (LMFWC).
    Auth: Basic (API_KEY / API_SECRET).
    """
    url = f"{BASE_URL}{path}"

    try:
        resp = requests.get(url, auth=(API_KEY, API_SECRET), timeout=8)
    except requests.RequestException as e:
        raise LicenseError(f"Impossible de contacter le serveur de licence: {e}")

    if resp.status_code == 401:
        # Essayons de remonter le message brut pour debug
        try:
            err = resp.json()
        except ValueError:
            err = {"raw": resp.text[:200]}
        raise LicenseError(f"401 Unauthorized depuis l'API LMFWC. Réponse: {err}")

    if resp.status_code == 403:
        raise LicenseError("403 Forbidden depuis l'API LMFWC (droits insuffisants ou blocage serveur).")

    if resp.status_code >= 500:
        raise LicenseError(f"Erreur serveur LMFWC ({resp.status_code}). Réessaie plus tard.")

    try:
        data = resp.json()
    except ValueError:
        raise LicenseError(f"Réponse non JSON de l'API LMFWC: {resp.text[:200]}")

    if not data.get("success", False):
        raise LicenseError(f"Erreur LMFWC: {data}")

    return data["data"]


def activate_license_remote(license_key: str) -> dict:
    """
    Active une licence côté serveur.
    Retourne les données 'data' du plugin, qui doivent contenir au moins:
      - status
      - token
      - expiresAt (éventuel)
    """
    data = _api_get(f"/licenses/activate/{license_key}")
    return data


def validate_license_remote(license_key: str) -> dict:
    """
    Vérifie l'état actuel de la licence côté serveur.
    """
    data = _api_get(f"/licenses/validate/{license_key}")
    return data


def deactivate_license_remote(token: str) -> None:
    """
    Désactive une activation côté serveur (slot libéré).
    """
    _api_get(f"/licenses/deactivate/{token}")


def is_license_still_valid(server_data: dict) -> bool:
    """
    Vérifie si la licence est encore valide en fonction des infos serveur.

    Version "fail-open" :
      - Si le serveur renvoie un statut clairement mauvais -> False
      - Sinon -> True (on considère la licence comme valide)
    """

    # Petit debug si tu veux voir ce que renvoie vraiment l'API :
    # print("DEBUG validate server_data:", server_data)

    status = server_data.get("status")
    code = (server_data.get("code") or "").strip().lower()

    # Si l'API renvoie un code d'erreur explicite
    if code in ("lmfwc_license_inactive", "lmfwc_license_expired", "lmfwc_license_disabled"):
        return False

    if status is None:
        # Pas de status -> si pas de code d'erreur évident, on considère valide
        return True

    s = str(status).strip().lower()

    # Tous les statuts clairement mauvais
    if s in ("0", "inactive", "expired", "blocked", "disabled", "revoked"):
        return False

    # Sinon, on arrête de faire notre fragile : on considère que c'est bon.
    return True


# ==========================
#  API HAUT NIVEAU POUR TON APP
# ==========================

def first_time_activation(prompt_func=input) -> dict:
    """
    Première exécution :
      - demande une clé à l'utilisateur
      - active côté serveur
      - bind à la machine (device_id)
      - sauvegarde chiffrée
    """
    print("Cette application nécessite une clé de licence.")
    license_key = prompt_func("Entre ta clé (copier/coller) : ").strip()

    if not license_key:
        raise LicenseError("Aucune clé entrée.")

    device_id = get_device_id()

    print("Activation de la licence sur ce PC…")
    data = activate_license_remote(license_key)

    # --- NOUVEAU : récupérer le token à l'intérieur de activationData ---
    token = data.get("token")

    if not token:
        activation = data.get("activationData")
        if isinstance(activation, dict):
            token = activation.get("token")
        elif isinstance(activation, list) and activation:
            # au cas où le plugin renverrait une liste d'activations
            token = activation[0].get("token")

    if not token:
        # ici on arrive seulement si l'API ne fournit vraiment aucun token
        raise LicenseError(
            f"La réponse du serveur ne contient pas de token d'activation exploitable: {data}"
        )

    if not is_license_still_valid(data):
        raise LicenseError("Licence invalide ou expirée (d'après la réponse serveur).")

    now = int(time.time())
    payload = {
        "license_key": license_key,
        "token": token,
        "device_id": device_id,
        "server_data": data,
        "activated_at": now,
        "last_validation": now,
    }
    _save_encrypted(payload)

    print("Licence activée et liée à cette machine ✅")
    return payload


def ensure_license_valid() -> dict:
    """
    À appeler au lancement de l'app :
      - charge et déchiffre la licence locale
      - vérifie que le device_id est le même
      - vérifie *obligatoirement* auprès du serveur
      - autorise un petit mode hors-ligne si le serveur est injoignable
    """
    local = _load_encrypted()

    if local is None:
        # Pas de licence valable en local -> activation obligatoire
        return first_time_activation()

    device_id = get_device_id()
    if device_id != local.get("device_id"):
        raise LicenseError("Cette licence est liée à une autre machine. (device_id différent)")

    license_key = local["license_key"]
    token = local["token"]
    last_validation = local.get("last_validation", 0)
    now = int(time.time())

    # On tente systématiquement une validation côté serveur
    try:
        server_data = validate_license_remote(license_key)
    except LicenseError as e:
        # Serveur HS / pas d'Internet -> mode hors-ligne limité
        print("⚠ Impossible de joindre le serveur de licence :", e)
        if not last_validation:
            raise LicenseError("Aucune validation précédente, démarrage impossible en mode hors-ligne.")

        if now - last_validation > OFFLINE_GRACE:
            raise LicenseError("Période hors-ligne dépassée. Reconnecte-toi pour revérifier la licence.")

        if not is_license_still_valid(local.get("server_data", {})):
            raise LicenseError("Les données locales indiquent une licence expirée ou invalide.")

        print("Licence acceptée en mode hors-ligne (délai de grâce).")
        return local

    # Serveur répondu -> on vérifie vraiment
    if not is_license_still_valid(server_data):
        raise LicenseError("Licence invalide ou expirée lors de la validation serveur.")

    # Mise à jour des infos locales
    local["server_data"] = server_data
    local["last_validation"] = now
    _save_encrypted(local)

    return local


def deactivate_local_and_remote() -> None:
    """
    Désactive la licence sur CETTE machine :
      - appelle /deactivate/{token} côté serveur
      - supprime le fichier local
    À utiliser par ex. si l'utilisateur veut déplacer sa licence.
    """
    local = _load_encrypted()
    if not local:
        return

    token = local.get("token")
    if token:
        try:
            deactivate_license_remote(token)
        except LicenseError as e:
            # On loggue, mais on continue quand même la suppression locale
            print("Erreur pendant la désactivation côté serveur:", e)

    try:
        CONFIG_FILE.unlink()
    except FileNotFoundError:
        pass