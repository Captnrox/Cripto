import socket
import os
import threading
import struct
import aux

def handle_server_messages(sock):
    """ Continuously listen for messages from Bob and print them cleanly. """
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
            header = packet[:4]
            counter_size = struct.unpack("!I", header)[0]

            if(aux.verify_auth(auth_key,packet,signature)):
                print("Succesful Auth! Safe message.")
            else:
                print("Failed Auth! Tampered message.")

            if len(packet) < 4 + counter_size:
                print("Incomplete packet received")
                break
            
            ciphertext = packet[4:-counter_size]
            serialized_counter = packet[-counter_size:]
            
            new_counter = aux.deserialize_counter(serialized_counter)
            
            if(new_counter['initial_value']< counter['initial_value'] +1):
                print("Replayed message")
            else:
                counter = new_counter
            
            message = aux.decrypt_ciphertext(encp_key,ciphertext,counter).decode('utf-8')
            
            counter = aux.inc(counter)
            
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
        ciphertext = aux.encrypt_message(encp_key, message.encode('utf-8'), counter)
        print(counter['initial_value'])
        serialized_counter = aux.serialize_counter(counter)
        
        header = struct.pack("!I",len(serialized_counter))
        
        packet = header + ciphertext + serialized_counter
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
                
                ciphertext = aux.encrypt_message(encp_key, message.encode('utf-8'), counter)
                print(counter['initial_value'])
                serialized_counter = aux.serialize_counter(counter)
                
                header = struct.pack("!I",len(serialized_counter))
        
                packet = header + ciphertext + serialized_counter
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
    counter = aux.start_counter()
    start_client()

