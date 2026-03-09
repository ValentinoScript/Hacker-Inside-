from licence_client import ensure_license_valid, LicenseError

def main():
    try:
        lic = ensure_license_valid()
        # Ici tu peux lire des infos :
        #   lic["license_key"]
        #   lic["server_data"]["timesActivated"]
        #   lic["server_data"]["timesActivatedMax"]
        #print("Licence OK, lancement de l'application…")
    except LicenseError as e:
        print("ERREUR LICENCE :", e)
        input("Appuie sur Entrée pour quitter…")
        main()


    # --- ICI TU LANCES TON VRAI PROGRAMME ---
    #print("Hello, utilisateur licencié 😈")
    # ...

if __name__ == "__main__":
    main()