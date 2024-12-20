import os


def generate_symetric_keys(file="pw"):
    ecpt_key = os.urandom(16)
    auth_key = os.urandom(32)
    
    print(ecpt_key)
    print(auth_key)
    
    with open(file,"wb") as f:
        f.write(ecpt_key + b"\n")
        f.write(auth_key)
    
generate_symetric_keys()