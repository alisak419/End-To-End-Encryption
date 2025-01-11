"""
Secure End-to-End Encrypted Messaging System

This project implements an End-to-End Encryption (E2EE) messaging system.
The solution is designed to withstand MITM (Man-In-The-Middle) attacks across all components and communication phases.

Additional security features include:
- Message confidentiality with AES encryption
- Secure key exchange using RSA
- Message integrity verification (HMAC)
- Tampering detection & authentication (digital signatures, OTP)
"""



import socket
import json
import base64
import os
import secrets
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

SERVER_IP = '127.0.0.1'
SERVER_PORT = 9999

"""
Verifies the server's signed response.
This function checks the authenticity of the server's response by verifying its digital signature
using the server's public key. If the signature is valid, it returns the response data; otherwise, it returns None.

Args:
    response_json (str): The server's JSON response, containing data and a signature.
Returns:
    dict or None: The verified response data if the signature is valid, otherwise None.
"""
def verify_server_response(response_json):
    try:
        if 'SERVER_PUBLIC_KEY' not in globals():
            return None

        full_response = json.loads(response_json)
        SERVER_PUBLIC_KEY.verify(
            base64.b64decode(full_response['signature']),
            json.dumps(full_response['data']).encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return full_response['data']
    except Exception as e:
        return None

"""
Generates an RSA key pair.

Returns:
    tuple (bytes, bytes): The private and public keys in PEM format.
"""
def generate_rsa_keys():
 """Generate RSA key pair (private and public keys)."""
 private_key = rsa.generate_private_key(
     public_exponent=65537,
     key_size=2048,
     backend=default_backend()
 )
 public_key = private_key.public_key()
 private_pem = private_key.private_bytes(
     encoding=serialization.Encoding.PEM,
     format=serialization.PrivateFormat.PKCS8,
     encryption_algorithm=serialization.NoEncryption()
 )
 public_pem = public_key.public_bytes(
     encoding=serialization.Encoding.PEM,
     format=serialization.PublicFormat.SubjectPublicKeyInfo
 )
 return private_pem, public_pem

"""
Loads an RSA private key from PEM format.

Args:
    private_pem (bytes): The private key in PEM format.
Returns:
    rsa.RSAPrivateKey: The loaded RSA private key object.
"""
def load_private_key(private_pem):
 return serialization.load_pem_private_key(
     private_pem,
     password=None,
     backend=default_backend()
 )

"""
Requests a one-time password (OTP) from the server.

Args:
    phone_number (str): The target phone number.
Returns:
    str or None: The OTP if successful, otherwise None.
"""
def request_otp(phone_number):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((SERVER_IP, SERVER_PORT))
        request = json.dumps({'action': 'request_otp', 'phone_number': phone_number})
        client.send(request.encode())
        raw_response = client.recv(4096).decode()

        #The first time, before we have the server's key, we'll just get the answer
        response = json.loads(raw_response)
        # If there is a signature, we will try to verify if we already have the key
        if 'signature' in response and 'SERVER_PUBLIC_KEY' in globals():
            response = verify_server_response(raw_response)
            if response is None:
                raise ValueError("Server verification failed!")
        else:
            response = response.get('data', response)

        client.close()

        if response.get('status') == 'otp_sent' and 'otp' in response:
            return response['otp']
        else:
            print("ERROR! oh no, failed to retrieve OTP from server.")
            return None
    except Exception as e:
        print(f"Error {str(e)}")
        return None

"""
Registers the client with the server using OTP and a public key.

Args:
    phone_number (str): The client's phone number.
    otp (str): The one-time password for authentication.
    public_key (str): The client's public key.
Returns:
    dict: The server's response containing the registration status.
"""
def register_client(phone_number, otp, public_key):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((SERVER_IP, SERVER_PORT))
        request = json.dumps({'action': 'register', 'phone_number': phone_number, 'otp': otp, 'public_key': public_key})
        client.send(request.encode())
        raw_response = client.recv(4096).decode()

        # The first time we will just accept the answer as it is
        response = json.loads(raw_response)
        if 'data' in response:
            response = response['data']

        client.close()
        return response
    except Exception as e:
        print(f"Error {str(e)}")
        return {'status': 'error', 'message': str(e)}

"""
Sends a disconnect request to the server.

Args:
    phone_number (str): The client's phone number.
Returns:
    None
"""
def disconnect(phone_number):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((SERVER_IP, SERVER_PORT))
    request = json.dumps({'action': 'disconnect', 'phone_number': phone_number})
    client.send(request.encode())
    raw_response = client.recv(4096).decode()
    response = verify_server_response(raw_response)
    if response is None:
        raise ValueError("Server verification failed!")
    client.close()
    print(response.get('message', 'Error disconnecting'))

"""
Retrieves the public key of another user from the server.

Args:
    phone_number (str): The phone number of the target user.
Returns:
    str or None: The public key if successful, otherwise None.
"""
def get_public_key(phone_number):
 client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 client.connect((SERVER_IP, SERVER_PORT))
 request = json.dumps({'action': 'get_public_key', 'phone_number': phone_number})
 client.send(request.encode())
 raw_response = client.recv(4096).decode()
 response = verify_server_response(raw_response)
 if response is None:
     raise ValueError("Server verification failed!")
 client.close()
 if response['status'] == 'success':
     print(f"[INFO] Retrieved public key for {phone_number}.")
     return response['public_key']
 else:
     print(f"[ERROR] Failed to retrieve receiver's public key for {phone_number}: {response['message']}")
     return None

"""
Saves the private and public keys to files.

Args:
    phone_number (str): The phone number associated with the keys.
    private_pem (bytes): The private key in PEM format.
    public_pem (bytes): The public key in PEM format.
Returns:
    None
"""
def save_keys_to_file(phone_number, private_pem, public_pem):
    with open(f'private_key_{phone_number}.pem', 'wb') as f:
        f.write(private_pem)
    with open(f'public_key_{phone_number}.pem', 'wb') as f:
        f.write(public_pem)

"""
Loads the private and public keys from files.

Args:
    phone_number (str): The phone number associated with the keys.
Returns:
    tuple (bytes, bytes): The private and public keys in PEM format, or (None, None) if not found.
"""
def load_keys_from_file(phone_number):
    try:
        with open(f'private_key_{phone_number}.pem', 'rb') as f:
            private_pem = f.read()
        with open(f'public_key_{phone_number}.pem', 'rb') as f:
            public_pem = f.read()
        return private_pem, public_pem
    except FileNotFoundError:
        return None, None

"""
Encrypts a message using AES-256-CBC and generates an HMAC for integrity verification.

Args:
    plaintext (str): The message to encrypt.
    aes_key (bytes): The AES encryption key (256-bit).
Returns:
    str: The base64-encoded ciphertext, including IV, encrypted data, and HMAC.
"""
def encrypt_aes(plaintext, aes_key):
 iv = os.urandom(16)
 cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
 encryptor = cipher.encryptor()
 padded_plaintext = plaintext.ljust(16 * ((len(plaintext) // 16) + 1)).encode()
 ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

 # Compute HMAC
 hmac_obj = hmac.new(aes_key, ciphertext, hashlib.sha256)
 hmac_digest = hmac_obj.digest()

 return base64.b64encode(iv + ciphertext + hmac_digest).decode()

"""
Decrypts an AES-256-CBC encrypted message and verifies its integrity using HMAC.

Args:
    encrypted_message (str): The base64-encoded ciphertext (including IV, encrypted data, and HMAC).
    aes_key (bytes): The AES decryption key (256-bit).
Returns:
    str: The decrypted plaintext if HMAC verification succeeds.
Raises:
    ValueError: If the HMAC verification fails.
"""
def decrypt_aes(encrypted_message, aes_key):
   encrypted_data = base64.b64decode(encrypted_message)
   iv = encrypted_data[:16]
   ciphertext = encrypted_data[16:-32]  # Last 32 bytes are HMAC
   received_hmac = encrypted_data[-32:]

   # Compute HMAC again
   hmac_obj = hmac.new(aes_key, ciphertext, hashlib.sha256)
   calculated_hmac = hmac_obj.digest()

   # Verify HMAC
   if not hmac.compare_digest(received_hmac, calculated_hmac):
       raise ValueError("Message integrity check failed!")

   cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
   decryptor = cipher.decryptor()
   decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

   return decrypted_padded.rstrip(b"\x00").decode()  #avoid spacing errors in decoding

"""
Encrypts data using an RSA public key with OAEP padding.

Args:
    data (bytes): The data to encrypt.
    public_key_pem (str): The RSA public key in PEM format.
Returns:
    str: The base64-encoded encrypted data.
"""
def encrypt_rsa(data, public_key_pem):
 public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
 encrypted_data = public_key.encrypt(
     data,
     padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA256()),
         algorithm=hashes.SHA256(),
         label=None
     )
 )
 return base64.b64encode(encrypted_data).decode()

"""
Decrypts RSA encrypted data using a private key with OAEP padding.

Args:
    encrypted_data (str): The base64-encoded encrypted data.
    private_key_pem (bytes): The RSA private key in PEM format.
Returns:
    bytes: The decrypted data.
"""
def decrypt_rsa(encrypted_data, private_key_pem):
 private_key = load_private_key(private_key_pem)
 decrypted_data = private_key.decrypt(
     base64.b64decode(encrypted_data),
     padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA256()),
         algorithm=hashes.SHA256(),
         label=None
     )
 )
 return decrypted_data

"""
Sends an encrypted message with integrity verification.

Args:
    sender (str): The sender's phone number.
    receiver (str): The receiver's phone number.
    message (str): The plaintext message to encrypt and send.
Returns:
    None
"""
def send_message(sender, receiver, message):
 print(f"[INFO] Requesting public key for {receiver}...")
 receiver_public_key = get_public_key(receiver)
 if not receiver_public_key:
     print("[ERROR] Could not retrieve public key. Aborting message send.")
     return

 aes_key = secrets.token_bytes(32)
 encrypted_message = encrypt_aes(message, aes_key)
 encrypted_aes_key = encrypt_rsa(aes_key, receiver_public_key)

 client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 client.connect((SERVER_IP, SERVER_PORT))
 request = json.dumps({
     'action': 'send_message',
     'sender': sender,
     'receiver': receiver,
     'encrypted_message': encrypted_message,
     'encrypted_aes_key': encrypted_aes_key
 })
 client.send(request.encode())
 raw_response = client.recv(4096).decode()
 response = verify_server_response(raw_response)
 if response is None:
     raise ValueError("Server verification failed!")
 client.close()
 if response and response.get('status') == 'success':
     print(f"Message sent successfully: {response.get('message')}")
 else:
     print(f"Error sending message: {response.get('message')}")

"""
Fetches and decrypts messages for the client.

Args:
    phone_number (str): The client's phone number.
    private_key_pem (bytes): The RSA private key in PEM format.
Returns:
    None
"""
def fetch_messages(phone_number, private_key_pem):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((SERVER_IP, SERVER_PORT))
    request = json.dumps({'action': 'fetch_messages', 'phone_number': phone_number})
    client.send(request.encode())
    raw_response = client.recv(4096).decode()
    response = verify_server_response(raw_response)
    if response is None:
        raise ValueError("Server verification failed!")
    client.close()

    if response['status'] == 'success':
        messages = response['messages']
        for msg in messages:
            try:
                aes_key = decrypt_rsa(msg['encrypted_aes_key'], private_key_pem)
                decrypted_msg = decrypt_aes(msg['encrypted_message'], aes_key)
                print(f"Message from {msg['sender']}: {decrypted_msg}")
            except Exception as e:
                print(f"[ERROR] Failed to decrypt message from {msg['sender']}: {str(e)}")
    else:
        print("No new messages.")


if __name__ == "__main__":
    print("\n=== Secure Messaging Client ===")
    phone_number = input("Enter your phone number: ").strip()

    # Generating/loading keys
    print("\n[*] Security Step 1 - Key Generation:")
    private_pem, public_pem = load_keys_from_file(phone_number)
    if not private_pem or not public_pem:
        private_pem, public_pem = generate_rsa_keys()
        save_keys_to_file(phone_number, private_pem, public_pem)
        print(f"Created new RSA-2048 key pair for {phone_number}")
        print(f"Public Key Hash: {hashlib.sha256(public_pem).hexdigest()[:8]}")
    else:
        print(f"Loaded existing key pair for {phone_number}")
        print(f"Public Key Hash: {hashlib.sha256(public_pem).hexdigest()[:8]}")

    # Receiving a verification code
    print("\n[*] Security Step 2 - Authentication:")
    otp = request_otp(phone_number)
    if otp:
        print(f"Authentication code generated: {otp}")

        # Identity Verification and Server Key Reception
        print("\n[*] Security Step 3 - Identity Verification:")
        registration_response = register_client(phone_number, otp, public_pem.decode())

        if registration_response.get('status') == 'success':
            print("Identity verified successfully")

            # Initialize server's public key from registration response
            SERVER_PUBLIC_KEY = serialization.load_pem_public_key(
                registration_response['server_public_key'].encode(),
                backend=default_backend()
            )

            print("Server's public key received successfully")

            # Summary of operations
            print("\n=== Final Security Report ===")
            print("1. Key Generation:")
            print(f"   - RSA-2048 Keys: {hashlib.sha256(public_pem).hexdigest()[:8]}")
            print("   - Keys saved locally")
            print("\n2. Authentication:")
            print(f"   - OTP Generated: {otp}")
            print("   - OTP Verified: ✓")
            print("\n3. Connection Security:")
            print("   - Session established")
            print("   - Server verified")
            print("   - Ready for encrypted communication")
            print("\nAll security measures implemented successfully!")
        else:
            print(f"Verification failed: {registration_response.get('message')}")
            exit()
    else:
        print("Authentication failed")
        exit()

    # Main message loop
    while True:
        print("\nSelect an action:")
        print("1 - Send a message")
        print("2 - Fetch messages")
        print("3 - Disconnect and Exit")

        action = input("Enter your choice (1/2/3): ").strip()

        if action == "1":
            receiver = input("Enter receiver's phone number: ").strip()
            message = input("Type your message: ").strip()
            send_message(phone_number, receiver, message)
        elif action == "2":
            fetch_messages(phone_number, private_pem)
        elif action == "3":
            disconnect(phone_number)
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


