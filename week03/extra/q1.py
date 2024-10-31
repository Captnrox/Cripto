import ciphersuite_aesnotrand as ciphersuite
from binascii import hexlify, unhexlify

offset = 3
key = ciphersuite.gen()
msg = 'Attack at dawn!!'
cph = ciphersuite.enc(key, bytearray(msg,'ascii'))
print(key)

f = open("weak_ciphertext", "wb")
f.write(cph)
f.close()

## 
# Extend me to
# 1 - Read ciphertext
# 2 - Guess the key used
# 3 - Test the decryption
##

with open("weak_ciphertext", "rb") as f:
    cph_txt = f.read()

i = 0
while (i < 2**(offset*8)):
    curr_key = b'\x00' * (16-offset) + i.to_bytes(offset, 'big')
    i += 1 
    try:
        dcph = ciphersuite.dec(curr_key, cph_txt)
        if dcph.decode('ascii') == msg:
            print("Success!")
            print(f"Key found: {curr_key}")
            break
    except Exception as e:
        pass
