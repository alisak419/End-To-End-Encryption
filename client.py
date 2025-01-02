from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json
import socket

#We will define a local IP address. The client and the server will operate on the same computer.
HOST = "127.0.0.1"
PORT = 12345

#As the MMN16 requested, the phone number will serve as the client's id.
#We get this phone number as an input:
client_id = input("Hey there client! Please enter your phone number right here: ")

#Creating the client's public and private key with RSA:
private_key_of_client = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key_of_client = private_key_of_client.public_key()
#The public exponent, 65537, is a prime number and is a standard choice for public exponent.
#The key size 2048 is a large key size and offers a good security.

#We will save the client's public key to a PEM file:
with open(f"public_key_of_client_{client_id}.pem", "wb") as public_key_file:
    public_key_file.write(public_key_of_client.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

#and print the name of the file for clarification:
print(f"The public key of the client saved as: 'public_key_of_client_{client_id}.pem'.")

#Establishing a connection with the server:
try:
    #create a TCP socket for the client:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:    #specifies IPv4 addressing and a TCP connection.
        client_socket.connect((HOST, PORT)) #establishing connection to the server using the IP address and the port.
        print(f"The client is connected to the server at {HOST}:{PORT}.")

        #The registration message that is sent to the server.
        #This is a dictionary containing: type - the message is for registration, the client's phone number (id),
        #the public key converted to PEM format byte string.
        #The PEM format is base64 encoded.
        registration_message = {"type": "register", "client_id": client_id,
                                "public_key": public_key_of_client.public_bytes(encoding=serialization.Encoding.PEM,
                                                                                format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()}

        #Sending the registration message from the client to the server:
        client_socket.sendall((json.dumps(registration_message)).encode())  #the registration message is converted from Python dictionary
                                                                            #to a JSON formatted string. Then the JSON string is converted
                                                                            #into bytes. Then it all sends to the server using TCP.
        print("Good! The registration message has been sent.")

        #Receiving the server's response after the client's registration request:
        response = client_socket.recv(4096).decode()    #the data from the server is received over the socket connection,
                                                        #the received binary data is in bytes, so it's converted into a string
                                                        #format using UTF-8 encoding.

        #displaying the server's response:
        print(f"The server's response is: {response}.")

        #Here we handle "failed" response from the server.
        res = response.lower()
        if "failed" in res:
            print("Sorry, the registration failed... You can try again later.")

#If the client attempts to connect to the server but the server is unreachble/not running/no ports listening,
#the "connection refused" error will occur:
except ConnectionRefusedError:
    print("Connection failed. Please check if the server is running.")
except Exception as e:
    print(f"Something went wrong. {e}")




