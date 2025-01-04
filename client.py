from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json
import socket
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import padding


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

#This function derives AES key from OTP with HKDF:
def derive_aes_from_otp(otp):
    otp_bytes = otp.encode()
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"E2EE").derive(otp_bytes)
    return derived_key

# This function creates HMAC for a given message using the provided key
def create_hmac(message, hmac_key):
    hmac_instance = hmac.HMAC(hmac_key, hashes.SHA256())
    hmac_instance.update(message)
    return hmac_instance.finalize()

# This function encrypts messages with AES and sends them along with HMACפט
def send_secure_message(client_socket, AES_key, hmac_key, message):
    # Encrypt the message with AES using the encrypt_message function
    encrypted_message = encrypt_message(message, AES_key)

    # Create an HMAC of the encrypted message
    hmac = create_hmac(encrypted_message, hmac_key)

    # Prepare the data to send: the encrypted message and the HMAC
    data_to_send = {"encrypted_message": encrypted_message, "hmac": hmac}

    # Send the encrypted message and HMAC to the server
    client_socket.sendall(json.dumps(data_to_send).encode())
    print("An encrypted message has been sent.")


#This function encrypts messages with AES:
def encrypt_message(message, AES_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    text_with_padding = message + ' ' * (16-len(message) % 16)
    cipher_text = encryptor.update(text_with_padding.encode()) + encryptor.finalize()
    return base64.b64encode(iv + cipher_text).decode()

#This function signs messages with the private key:
def sign_message(message, private_key):
    signature = private_key.sign(message.encode(), padding.PKCS1v15(), hashes.SHA256(), hashes.SHA256())
    return base64.b64encode(signature).decode()


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

        #Getting OTP from the server:
        otp_answer = client_socket.recv(4096).decode()  #Reading the OTP
        print(f"The OTP we got from the server is this: {otp_answer}")

        #Receiving the server's response after the client's registration request:
        response = client_socket.recv(4096).decode()    #the data from the server is received over the socket connection,
                                                        #the received binary data is in bytes, so it's converted into a string
                                                        #format using UTF-8 encoding.
        print(f"The server's response is: {response}")

        res = response.lower()
        if "successful" in res:
            print("Good, the registration complited.")

            #Derive AES 256 bit key using KDF.
            aes_key = derive_aes_from_otp(otp_answer)
            print("Awesome! the AES key derived successfully with the KDF.")

            #Authentication message to ensute the client is okay to interact securely with the server.
            #The server needs to know that the client is genuinely the one the server itself registered.
            auth = "Authentication data"
            encryped_authentication_message = encrypt_message(auth, aes_key)
            authentication_message = {"type": "authenticate", "client_id": client_id, "auth_data": encryped_authentication_message}

            #after this message is created, it needs to be sent to the server so that he will know the client is legit.
            client_socket.sendall(json.dumps(authentication_message).encode())
            print("Awesome... the client is legit. The authentication message has been sent.")
        else:
            print("ouch... The registration has failed.")



except Exception as e:
    print(f"Something went wrong. {e}")




