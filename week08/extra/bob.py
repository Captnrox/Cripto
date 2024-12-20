import socket
import struct
import os
import aux

def handle_client(conn, addr):
    global encp_key,auth_key,counter
    print(f"Connected by {addr}")
    while True:
        signed_packet = conn.recv(2048)
        if not signed_packet:
            print("Connection closed by Alice.")
            break
        
        signature = signed_packet[:32]
        
        packet = signed_packet[32:]
        header = packet[0:8]
        new_counter =  struct.unpack("!I",header[:4])[0]
        header_nonce_size = header[4:]
        nonce_size = struct.unpack("!I", header_nonce_size)[0]

        
        if(aux.verify_auth(auth_key,packet,signature)):
            print("Succesful Auth! Safe message.")
        else:
            print("Failed Auth! Tampered message.")
            print("Ending connection!")
            os._exit(0)
            
        
        if len(packet) < 8 + nonce_size:
            print("Incomplete packet received")
            break
        
        ciphertext = packet[8:-nonce_size]
        nonce = packet[-nonce_size:]
        
        
        if( new_counter < counter +1):
            print("Replayed message")
            os._exit(0)
        else:
            counter = new_counter
        
        message = aux.decrypt_ciphertext(encp_key,ciphertext,nonce).decode('utf-8')
        print(f"Alice: {message}")
        
        counter += 1
        
        if message.lower() == "bye":
            print("Connection closed by Alice.")
            break
        
        reply = input("Bob:")
        ciphertext, nonce = aux.encrypt_message(encp_key, reply.encode('utf-8'))

        header = struct.pack("!I", counter) + struct.pack("!I",len(nonce))
        
        packet = header + ciphertext + nonce
        signature = aux.auth(auth_key,packet)
        signed_packet = signature + packet

        conn.sendall(signed_packet)
        
        if reply.lower() == "bye":
            print("Connection closed by Bob.")
            break

def start_server(host='127.0.0.1', port=65432):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Bob (Server) listening on {host}:{port}...")

        conn, addr = server_socket.accept()
        with conn:
            handle_client(conn, addr)

if __name__ == "__main__":
    counter = 0
    encp_key, auth_key = aux.read_keys()
    start_server()


