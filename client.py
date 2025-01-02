from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json
import socket

#We will define a local IP address. The client and the server will operate on the same computer.
HOST = "127.0.0.1"
PORT = 12345