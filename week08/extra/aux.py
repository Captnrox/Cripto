import hmac
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util import Counter
import pickle


def read_keys(file="pw"):
    with open(file, "rb") as f:
        f.seek(0)
        lines = f.readlines()
        encp_key = lines[0].strip()
        auth_key = lines[1].strip()
        
    return encp_key, auth_key

def start_counter():
    return Counter.new(128)

def inc(counter):
    counter['initial_value'] += 1
    return counter
    
def encrypt_message(encp_key,message,counter):
    cipher = AES.new(encp_key, AES.MODE_CTR, counter=counter)
    ciphertext = cipher.encrypt(message)
    return ciphertext

def decrypt_ciphertext(encp_key,ciphertext,counter):
    cipher = AES.new(encp_key, AES.MODE_CTR, counter=counter)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def auth(auth_key,data):
    return hmac.new(auth_key, data, sha256).digest()

def verify_auth(auth_key, data, signature):
    calculated_hmac = auth(auth_key, data)
    return hmac.compare_digest(calculated_hmac, signature)

def serialize_counter(counter):
    return pickle.dumps(counter)

def deserialize_counter(serialized_counter):
    return pickle.loads(serialized_counter)