import socket
import os
import threading
import struct
import aux

def handle_server_messages(sock):
    global connect,encp_key,auth_key,counter 
    while connect:
        try:
            signed_packet = sock.recv(2048)
            if not signed_packet:
                print("Connection closed by Bob.")
                os._exit(0)
                break
            
            signature = signed_packet[:32]

            packet = signed_packet[32:]
            header = packet[0:8]
            new_counter = struct.unpack("!I",header[:4])[0]
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
            
            
            if(new_counter < counter +1):
                print("Replayed message")
                os._exit(0)
            else:
                counter = new_counter
            
            message = aux.decrypt_ciphertext(encp_key,ciphertext,nonce).decode('utf-8')
            
            counter += 1
            
            print(f"Bob: {message}")
            print("Alice: ", end="", flush=True)  
            
        except ConnectionResetError:
            print("\nConnection closed abruptly.")
            connect = False
            break

def start_client(host='127.0.0.1', port=65432):
    global connect,encp_key,auth_key,counter
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        print(f"Alice (Client) connected to {host}:{port}")

        # Start a thread to receive messages from Bob
        threading.Thread(target=handle_server_messages, args=(client_socket,), daemon=True).start()
        
        message = input("Alice: ")
        ciphertext, nonce = aux.encrypt_message(encp_key, message.encode('utf-8'))
        
        header = struct.pack("!I", counter) + struct.pack("!I",len(nonce))
        
        packet = header + ciphertext + nonce
        signature = aux.auth(auth_key,packet)
        signed_packet = signature + packet

        client_socket.sendall(signed_packet)
        
        if message.lower() == "bye":
            print("Connection closed by Alice.")
            connect = False
        
        while connect:
            try:
                message = input()
                
                if not connect: 
                    break
                
                ciphertext, nonce = aux.encrypt_message(encp_key, message.encode('utf-8'))
                
                header = struct.pack("!I", counter) + struct.pack("!I",len(nonce))
        
                packet = header + ciphertext + nonce
                signature = aux.auth(auth_key,packet)
                signed_packet = signature + packet

                client_socket.sendall(signed_packet)
                
                if message.lower() == "bye":
                    print("Connection closed by Alice.")
                    connect = False
                    break
            except BrokenPipeError:
                print("\nCannot send message. Connection already closed.")
                connect = False
                break

if __name__ == "__main__":
    connect = True 
    encp_key, auth_key = aux.read_keys()
    counter = 1
    start_client()

