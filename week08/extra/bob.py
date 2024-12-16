import socket
import struct
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
        
        if(new_counter['initial_value']<counter['initial_value'] +1):
            print("Replayed message")
        else:
            counter = new_counter
        
        message = aux.decrypt_ciphertext(encp_key,ciphertext,counter).decode('utf-8')
        print(f"Alice: {message}")
        
        counter = aux.inc(counter)
        
        if message.lower() == "bye":
            print("Connection closed by Alice.")
            break
        
        reply = input("Bob:")
        ciphertext = aux.encrypt_message(encp_key, reply.encode('utf-8'),counter)
        serialized_counter = aux.serialize_counter(counter)
        
        print(counter['initial_value'])
        header = struct.pack("!I",len(serialized_counter))
        
        packet = header + ciphertext + serialized_counter
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
    counter = aux.start_counter()
    counter["initial_value"]=0
    encp_key, auth_key = aux.read_keys()
    start_server()


