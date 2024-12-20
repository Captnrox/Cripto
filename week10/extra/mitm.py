from pwn import *
import random
import threading


host_alice = "localhost"
port_alice = 5075
mitm_alice_port = 5085

host_bob = "localhost"
port_bob = 5076
mitm_bob_port = 5086

def handle_alice(gz,z,p):
    r = remote(host_alice,port_alice)
    l = listen(mitm_bob_port)
    l.wait_for_connection()
    
    print("Sending GZ: ", gz)
    r.sendline(gz.to_bytes(8, "little"))
    
    gx = int.from_bytes(l.recvline()[:-1], "little")
    print("Received GX:", gx)
    
    print("Shared secret: ", pow(gx, z, p))

    l.close()
    r.close() 

    return

def handle_bob(gz,z,p):
    l = listen(mitm_alice_port)
    l.wait_for_connection()
    r  = remote(host_bob,port_bob)
    
    gy = int.from_bytes(l.recvline()[:-1], "little")
    print("Received GY:", gy)

    print("Sending GX: ", gz)
    r.sendline(gz.to_bytes(8, "little"))

    print("Shared secret: ", pow(gy, z, p))
        
    l.close()
    r.close() 

    return

def main():    
    g = 2
    p = 7853799659
    z = random.randint(1,p)
    gz = pow(g, z, p) 
    
    alice_thread = Thread(target=handle_alice, args=(gz,z,p))
    bob_thread = Thread(target=handle_bob, args=(gz,z,p))
    
    alice_thread.start()
    bob_thread.start()

    alice_thread.join()
    bob_thread.join()
    
    
    return

if __name__ == "__main__":
    main()


