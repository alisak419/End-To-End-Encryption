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
        client_socket, client_address = server_socket.accept()
        with client_socket:
            print(f"connected by: {client_address}.")
