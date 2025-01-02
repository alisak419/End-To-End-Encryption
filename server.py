from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json
import socket

#First of all, we will create a dictionary that will act as our database.
#This database will store all the client's data, including public keys, pending messages, connection status.
clients_data_base = {}

#We will define a local IP address. The client and the server will operate on the same computer.
HOST = "127.0.0.1"
PORT = 12345

#Generate a pair of public and private keys for the server with the RSA algorithm.
private_key_of_server = rsa.generate_private_key(public_exponent=65537, key_size=2048)
#The public exponent, 65537, is a prime number and is a standart choice for public exponent.
#The key size 2048 is a large key size and offers a good security.

public_key_of_server = private_key_of_server.public_key()   #Derive the public key from the private key.

#We will save the server's public key into a PEM file.
with open("public_key_of_server.pem", "wb") as public_key_file:
    public_key_file.write(public_key_of_server.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
#and print the name of this file, the server's public key:
print("The public key of the server is saved in this file: 'public_key_of_server.pem'.")

#This will be the main loop of code of the server.
#Starting the server:
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:    #Creating a TCP socket.
    server_socket.bind((HOST, PORT))    #binds the socket to the given IP and port for listening.
    server_socket.listen()  #The server is in listening mode, meaning it's waiting for connections.
    #We will print in what server the port is listening to maintain order:
    print(f"The server is listening on {HOST}:{PORT}.")

    #Now the server needs to accept the client's connections -
    while True:
        #The server will enter an infinite loop where he will listen and wait for incoming connections from the client.
        #client_address contains the client's IP and port number.
        #client_socket is the specific connection to the client.
        client_socket, client_address = server_socket.accept()  #the client connects.
        with client_socket:
            print(f"connected by: {client_address}.")   #A message that indicated that the client is connected + his address.
            #the client socket will be automatically closed when the block ends.
            try:
                received_data = client_socket.recv(4096)    #wait for client's data. 4096 - the number of bytes to read.
                if not received_data:   #if the client disconnects, so end the loop for this client.
                    break

                #analyzing the data:
                message = json.loads(received_data.decode())    #convert the data to a dictionary.
                #creating the structure of the data:
                if message["type"] == "register":   #processing the registration details
                    client_id = message["client_id"]    #the phone number of the client
                    public_key_pem = message["public_key"].encode() #the public key of the client
                    #here we will save the client's data to the dictionary we created at the beginning.
                    #we will store the client's public key and the list of messages sent to this client:
                    clients_data_base[client_id] = {"public_key": public_key_pem, "messages": []}

                    #save the public key to PEM file:
                    with open(f"public_key_of_client_{client_id}.pem", "wb") as client_key_file:
                        client_key_file.write(public_key_pem)

                    print(f"The client that is registered: {client_id}")
                    #confirming that the server processed the registration:
                    client_socket.sendall(b"The registration is successful!")

                #In the case that the received message isn't recognized - the server will print it:
                else:
                    client_socket.sendall(b"The request is unknown!")

            #error handling:
            except Exception as e:
                print(f"Exception occured: {e}")
                client_socket.sendall(b"There is an error...")




