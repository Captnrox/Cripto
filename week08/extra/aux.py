import hmac
from hashlib import sha256
from Crypto.Cipher import AES
import os



def read_keys(file="pw"):
    with open(file, "rb") as f:
        f.seek(0)
        lines = f.readlines()
        encp_key = lines[0].strip()
        auth_key = lines[1].strip()
        
    return encp_key, auth_key

def inc(counter):
    counter['initial_value'] += 1
    return counter
    
def encrypt_message(encp_key,message):
    nonce = os.urandom(8)
    cipher = AES.new(encp_key, AES.MODE_CTR, nonce = nonce)
    ciphertext = cipher.encrypt(message)
    return ciphertext, nonce

def decrypt_ciphertext(encp_key,ciphertext,nonce):
    cipher = AES.new(encp_key, AES.MODE_CTR, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def auth(auth_key,data):
    return hmac.new(auth_key, data, sha256).digest()

def verify_auth(auth_key, data, signature):
    calculated_hmac = auth(auth_key, data)
    return hmac.compare_digest(calculated_hmac, signature)
