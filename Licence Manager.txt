import json
import time
from pathlib import Path

import requests


# ==========================
#  CONFIG GÉNÉRALE
# ==========================

# URL de base de l'API License Manager
BASE_URL = "https://valentinoscript.com/wp-json/lmfwc/v2"

# Tes clés REST API du plugin License Manager for WooCommerce
# (WooCommerce > Settings > License Manager > REST API keys)
# API_KEY = "ck_88adaa4f6128fbe307e09a22a9436569b9b37de9"      # consumer key
# API_SECRET = "cs_b26e696a254ab693a05d73fc013a1c1279e47167"   # consumer secret

API_KEY = "ck_975227fc8b38b1fed6496a5cac8ec517de45ed05"      # consumer key
API_SECRET = "cs_7a6cd09895f984b0ffc8a194727ba5e80c8d49da"   # consumer secret
# Où on stocke la licence sur le PC de l'utilisateur
CONFIG_DIR = Path.home() / ".valentinoscript_app"
CONFIG_FILE = CONFIG_DIR / "license.json"

# Fréquence de re-vérification en secondes (ici toutes les 24 h)
VALIDATION_INTERVAL = 24 * 3600

# Délai offline maximum (par ex. 7 jours) si le serveur est injoignable
OFFLINE_GRACE = 7 * 24 * 3600


class LicenseError(Exception):
    """Erreur côté licence (clé invalide, expirée, etc.)."""
    pass


def _api_get(path: str):
    """
    Appel générique GET vers l'API License Manager.
    Utilise l'auth Basic (API_KEY / API_SECRET).
    """
    url = f"{BASE_URL}{path}"
    params = {
        "consumer_key": API_KEY,
        "consumer_secret": API_SECRET,
    }
    try:
        resp = requests.get(url, params=params, timeout=8)
    except requests.RequestException as e:
        raise LicenseError(f"Impossible de contacter le serveur de licence: {e}")

    # Erreurs HTTP "brutes"
    if resp.status_code == 401:
        # Essaie d'afficher le message JSON renvoyé par LMFWC
        try:
            err = resp.json()
        except ValueError:
            err = {"raw": resp.text[:200]}
        raise LicenseError(
            f"401 Unauthorized depuis l'API LMFWC. Réponse: {err}"
        )

    if resp.status_code == 403:
        raise LicenseError("Accès refusé (403). SSL ou droits API peut-être mal configurés.")
    if resp.status_code >= 500:
        raise LicenseError(f"Erreur serveur ({resp.status_code}). Réessaie plus tard.")

    # Parsing JSON
    try:
        data = resp.json()
    except ValueError:
        raise LicenseError(f"Réponse JSON invalide: {resp.text[:200]}")

    # Format du plugin : {"success": true/false, "data": {...} }
    if not data.get("success", False):
        raise LicenseError(f"Erreur License Manager: {data}")

    return data["data"]


# ==========================
#  APPELS LICENCE MANAGER
# ==========================

def activate_license(license_key: str) -> dict:
    """
    Active une licence auprès du serveur.
    Incrémente timesActivated côté WP si tout va bien.
    Retourne l'objet "data" de l'API.
    """
    path = f"/licenses/activate/{license_key}"
    data = _api_get(path)
    return data


def validate_license(license_key: str) -> dict:
    """
    Demande l'état actuel de la licence (status, expiration, activations…).
    """
    path = f"/licenses/validate/{license_key}"
    data = _api_get(path)
    return data


def is_license_still_valid(license_data: dict) -> bool:
    """
    Applique tes règles métier sur la réponse de l'API.
    Exemple basique :
      - status == 2 (active)
      - expiresAt est vide ou dans le futur
    """
    status = license_data.get("status")
    expires_at = license_data.get("expiresAt")  # "YYYY-MM-DD HH:MM:SS" ou null

    # Tous les exemples de la doc montrent status=2 pour "active"
    if status != 2:
        return False

    # Si pas de date d'expiration => OK
    if not expires_at:
        return True

    # Vérif expiration
    # Format "2023-12-28 00:00:00"
    try:
        from datetime import datetime
        exp_dt = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S")
        if exp_dt.timestamp() < time.time():
            return False
    except Exception:
        # Si on n'arrive pas à parser, on joue la sécurité : on considère invalide
        return False

    return True


# ==========================
#  STOCKAGE LOCAL
# ==========================

def _load_local_license() -> dict | None:
    if not CONFIG_FILE.exists():
        return None
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _save_local_license(payload: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


# ==========================
#  API HAUT NIVEAU POUR TON APP
# ==========================

def first_time_activation(prompt_func=input) -> dict:
    """
    Pour la première exécution : demande une clé à l'utilisateur,
    tente de l'activer, sauvegarde en local et renvoie les données.
    """
    print("Cette application nécessite une clé de licence.")
    license_key = prompt_func("Entre ta clé (copier/coller) : ").strip()

    if not license_key:
        raise LicenseError("Aucune clé entrée.")

    print("Activation de la licence…")
    data = activate_license(license_key)

    if not is_license_still_valid(data):
        raise LicenseError("Licence invalide ou expirée (status ou date).")

    now = int(time.time())
    to_store = {
        "license_key": license_key,
        "server_data": data,
        "activated_at": now,
        "last_validation": now,
    }
    _save_local_license(to_store)
    print("Licence activée avec succès ✅")

    return to_store


def ensure_license_valid() -> dict:
    """
    À appeler au lancement de ton app.
    - Charge la licence locale si elle existe
    - Sinon demande la clé et l'active
    - Si déjà activée :
        - si dernière validation < 24h => OK
        - sinon demande une validation au serveur
        - gère un petit mode offline avec OFFLINE_GRACE
    Retourne les données de licence (local + dernières données serveur).
    """
    local = _load_local_license()

    # Pas encore de licence : on lance la première activation
    if local is None:
        return first_time_activation()

    license_key = local.get("license_key")
    last_validation = local.get("last_validation", 0)
    now = int(time.time())

    # Si pas besoin de recontacter le serveur (moins de 24h) : on fait confiance au cache
    if now - last_validation < VALIDATION_INTERVAL:
        # Optionnel : vérifier que les données locales semblent toujours ok
        if is_license_still_valid(local.get("server_data", {})):
            return local
        # Sinon on force une validation serveur (au cas où)

    # On tente une validation serveur
    try:
        server_data = validate_license(license_key)
        if not is_license_still_valid(server_data):
            raise LicenseError("Licence invalide ou expirée lors de la validation.")

        local["server_data"] = server_data
        local["last_validation"] = now
        _save_local_license(local)
        return local

    except LicenseError as e:
        # Serveur injoignable / erreur : on regarde la fenêtre offline
        print(f"Attention: {e}")
        print("Tentative de fonctionnement en mode hors-ligne…")

        # Si jamais on n'a JAMAIS validé, on bloque
        if not last_validation:
            raise LicenseError("Impossible de valider la licence et aucune validation précédente enregistrée.")

        # Si dernière validation trop ancienne => on refuse de démarrer
        if now - last_validation > OFFLINE_GRACE:
            raise LicenseError("Période hors-ligne dépassée. Reconnecte-toi à Internet pour revérifier la licence.")

        # Sinon on autorise, en mode dégradé
        print("Licence acceptée en mode hors-ligne (délai de grâce).")
        return local
