from crypto.SelfTest.Protocol.test_ecdh import private_key
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

#Generate a pair of public and private keys for the client with the RSA algorithm.
private_key_of_client = rsa.generate_private_key(public_exponent=65537, key_size=2048)
#The public exponent, 65537, is a prime number and is a standart choice for public exponent.
#The key size 2048 is a large key size and offers a good security.

public_key_of_client = private_key_of_client.public_key()   #Derive the public key from the private key.