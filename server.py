from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json
import socket

#First of all, we will create a dictionary that will act as our database.
#This database will store all the client's data, including public keys, pending messages, connection status.
clients_data_base = {}

#We will define a local IP address. The client and the server will operate on the same computer.
