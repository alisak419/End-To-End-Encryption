import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json
import socket

from cryptography.hazmat.primitives.ciphers import Cipher

#First of all, we will create a dictionary that will act as our database.
#This database will store all the client's data, including public keys, pending messages, connection status.
clients_data_base = {}

#We will define a local IP address. The client and the server will operate on the same computer.
HOST = "127.0.0.1"
PORT = 12345

#Generate a pair of public and private keys for the server with the RSA algorithm.
private_key_of_server = rsa.generate_private_key(public_exponent=65537, key_size=2048)
#The public exponent, 65537, is a prime number and is a standard choice for public exponent.
#The key size 2048 is a large key size and offers a good security.

public_key_of_server = private_key_of_server.public_key()   #Derive the public key from the private key.

#We will save the server's public key into a PEM file.
with open("public_key_of_server.pem", "wb") as public_key_file:
    public_key_file.write(public_key_of_server.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
#and print the file name for clarification:
print("The public key of the server is saved in this file: 'public_key_of_server.pem'.")

#Creating AES key for symmetric encryption:
AES_key = os.urandom(32)    #using a key in size 256-bit

#Defining a function that will do symmetric encryption: AES-CBC-256
def encrypt_message(text):
    iv = os.urandom(16) #initialization vector
    cipher = Cipher(algorithms.AES(AES_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    text_with_padding = text + ' ' * (16 - len(text) % 16)  #padding
    cipher_text = encryptor.update(text_with_padding.encode()) + encryptor.finalize()
    return cipher_text + iv     #the final encrypted message

#A function that decrypts the messages using AES-CBC-256:
def decrypt_message(cipher_text):
    iv = cipher_text[:16]
    real_cipher_text = cipher_text[16:]
    cipher = Cipher(algorithms.AES(AES_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    text = decryptor.update(real_cipher_text) + decryptor.finalize()
    return text.decode().strip()

#A function that generates HMAC, we will use a key derived from the AES key.



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
                try:
                    message = json.loads(received_data.decode())    #convert the data to a dictionary.
                #this error appears if the data is malformed or incomplete, or something is missing in JSON syntax.
                except json.JSONDecodeError:
                    client_socket.sendall(b"invalid format of the message.")
                    print("The format that was received is invalid.")

                #Ensure that the "type" field is in the message:
                #critical because it indicates the purpose of the message, if it's registration or just sending message.
                if "type" not in message:
                    client_socket.sendall(b"The 'type' field in the message is missing.")
                    print("The 'type' field is missing.")
                    continue



                #creating the structure of the data:
                if message["type"] == "register":  #the type needs to be a registration request.
                    #The client's phone number and public key also need to be in the message:
                    if "client_id" not in message or "public_key" not in message:
                        #Sending the error responses:
                        client_socket.sendall(b"The 'client_id' and 'public_key' fields are missing.")
                        print("Attention! The 'client_id' and 'public_key' fields are missing.")
                        continue

                    client_id = message["client_id"]    #the phone number of the client
                    public_key_pem = message["public_key"].encode() #the public key of the client

                    #For the simplicity,the MMN16's requirment is that the server
                    #won't contain more than 10 clients.
                    if len(clients_data_base) >= 10:
                        client_socket.sendall(b"Registration failed. Cause: server is full.")
                        print(f"Sorry, client {client_id}. Your registration attempt rejected because the server is full.")
                        continue

                    #here we will save the client's data to the dictionary we created at the beginning.
                    #we will store the client's public key and the list of messages sent to this client:
                    clients_data_base[client_id] = {"public_key": public_key_pem, "messages": []}

                    #save the public key to PEM file:
                    with open(f"public_key_of_client_{client_id}.pem", "wb") as client_key_file:
                        client_key_file.write(public_key_pem)

                    print(f"The client that is registered: {client_id}")
                    #confirming that the server processed the registration:
                    client_socket.sendall(b"The registration is successful!")

                #Checking the message type-"send_message" type is a type of message the client sends to the server.
                elif message["type"] == "send_message":
                    #extracting the details of the message:
                    sender_id = message["sender_id"]
                    receiver_id = message["receiver_id"]
                    text_message = message["message"]

                    #checking if the client exists in the server's data base:
                    if receiver_id in clients_data_base:
                        # the client exists. The message is saved in the receiver's message queue.
                        #The message is added to the receiver's list of pending messages:
                        clients_data_base[receiver_id]["messages"].append({"from":sender_id, "message":text_message})
                        client_socket.sendall(b"The message is sent.")
                        #A confirmation is sent to the client to acknowledge that the delivery was succesful:
                        print(f"The message is sent from {sender_id} to {receiver_id} and is stored!")

                    else:       #the receiver doesn't exist.
                        client_socket.sendall(b"The receiver was not found...")
                        #The sender receives a respond that the receiver was not found:
                        print(f"Failed to send message from {sender_id} to {receiver_id}: receiver not found.")


                #In the case that the received message isn't recognized - the server will print it:
                else:
                    client_socket.sendall(b"The request is unknown!")

            #error handling:
            except Exception as e:
                print(f"Exception occured: {e}")
                client_socket.sendall(b"There is an error...")




