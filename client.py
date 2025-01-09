

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

def load_private_key(private_pem):
 """Load RSA private key from PEM format."""
 return serialization.load_pem_private_key(
     private_pem,
     password=None,
     backend=default_backend()
 )


def request_otp(phone_number):
 """Request OTP from the server."""
 try:
     client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
     client.connect((SERVER_IP, SERVER_PORT))
     request = json.dumps({'action': 'request_otp', 'phone_number': phone_number})
     client.send(request.encode())
     response = json.loads(client.recv(4096).decode())
     client.close()

     if response.get('status') == 'otp_sent' and 'otp' in response:
         otp = response['otp']
         print(f"Received OTP: {otp}")
         return otp
     else:
         print("ERROR! oh no, failed to retrieve OTP from server.")
         return None
 except Exception as e:
     print(f"Error {str(e)}")
     return None


def register_client(phone_number, otp, public_key):
 """Register the client with the server using OTP and public key."""
 try:
     client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
     client.connect((SERVER_IP, SERVER_PORT))
     request = json.dumps({'action': 'register', 'phone_number': phone_number, 'otp': otp, 'public_key': public_key})
     client.send(request.encode())
     response = json.loads(client.recv(4096).decode())
     client.close()
     return response
 except Exception as e:
     print(f"Error {str(e)}")
     return {'status': 'error', 'message': str(e)}


def get_public_key(phone_number):
 """Retrieve the public key of another user from the server."""
 client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 client.connect((SERVER_IP, SERVER_PORT))
 request = json.dumps({'action': 'get_public_key', 'phone_number': phone_number})
 client.send(request.encode())
 response = json.loads(client.recv(4096).decode())
 client.close()
 if response['status'] == 'success':
     print(f"[INFO] Retrieved public key for {phone_number}.")
     return response['public_key']
 else:
     print(f"[ERROR] Failed to retrieve receiver's public key for {phone_number}: {response['message']}")
     return None

def save_keys_to_file(phone_number, private_pem, public_pem):
    """Save keys to files."""
    with open(f'private_key_{phone_number}.pem', 'wb') as f:
        f.write(private_pem)
    with open(f'public_key_{phone_number}.pem', 'wb') as f:
        f.write(public_pem)

def load_keys_from_file(phone_number):
    """Load keys from files."""
    try:
        with open(f'private_key_{phone_number}.pem', 'rb') as f:
            private_pem = f.read()
        with open(f'public_key_{phone_number}.pem', 'rb') as f:
            public_pem = f.read()
        return private_pem, public_pem
    except FileNotFoundError:
        return None, None


def encrypt_aes(plaintext, aes_key):
 """Encrypt a message using AES-256-CBC and generate an HMAC."""
 iv = os.urandom(16)
 cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
 encryptor = cipher.encryptor()
 padded_plaintext = plaintext.ljust(16 * ((len(plaintext) // 16) + 1)).encode()
 ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()


 # Compute HMAC
 hmac_obj = hmac.new(aes_key, ciphertext, hashlib.sha256)
 hmac_digest = hmac_obj.digest()

 return base64.b64encode(iv + ciphertext + hmac_digest).decode()

def decrypt_aes(encrypted_message, aes_key):
   """Decrypt AES-256-CBC encrypted message and verify HMAC."""
   encrypted_data = base64.b64decode(encrypted_message)
   iv = encrypted_data[:16]
   ciphertext = encrypted_data[16:-32]  # Last 32 bytes are HMAC
   received_hmac = encrypted_data[-32:]


   # Compute HMAC again
   hmac_obj = hmac.new(aes_key, ciphertext, hashlib.sha256)
   calculated_hmac = hmac_obj.digest()


   # Debug prints for HMAC verification
   print(f"Received HMAC: {received_hmac.hex()}")
   print(f"Calculated HMAC: {calculated_hmac.hex()}")


   # Verify HMAC
   if not hmac.compare_digest(received_hmac, calculated_hmac):
       raise ValueError("Message integrity check failed!")


   cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
   decryptor = cipher.decryptor()
   decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()


   return decrypted_padded.rstrip(b"\x00").decode()  # להימנע משגיאות ריווח בפענוח
def encrypt_rsa(data, public_key_pem):
 """Encrypt data using an RSA public key."""
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

def decrypt_rsa(encrypted_data, private_key_pem):
 """Decrypt RSA encrypted data."""
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
def send_message(sender, receiver, message):
 """Send an encrypted message with integrity check."""
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
 response = json.loads(client.recv(4096).decode())
 client.close()
 print(response)


def fetch_messages(phone_number, private_key_pem):
    """Fetch and decrypt messages for the client."""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((SERVER_IP, SERVER_PORT))
    request = json.dumps({'action': 'fetch_messages', 'phone_number': phone_number})
    client.send(request.encode())
    response = json.loads(client.recv(4096).decode())
    client.close()

    print(f"[DEBUG] Raw response from server: {response}")  # הדפסת דיבאג חדשה

    if response['status'] == 'success':
        messages = response['messages']
        print(f"[DEBUG] Found {len(messages)} messages")  # הדפסת דיבאג חדשה
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
    phone_number = input("Hey! enter your phone number: ").strip()

    # נסה לטעון מפתחות קיימים
    private_pem, public_pem = load_keys_from_file(phone_number)

    # אם אין מפתחות, צור חדשים
    if not private_pem or not public_pem:
        private_pem, public_pem = generate_rsa_keys()
        save_keys_to_file(phone_number, private_pem, public_pem)

    # requesting OTP
    otp = request_otp(phone_number)
    if otp:
        print(f"The otp received is: {otp}")

        # sending registration request
        registration_response = register_client(phone_number, otp, public_pem.decode())
        if registration_response.get('status') == 'success':
            print("Registration successful.")
        else:
            print(f"Registration failed: {registration_response.get('message', 'Unknown error')}")
            exit()
    else:
        print("Failed to get OTP. Exiting...")
        exit()

    while True:
        print("\nSelect an action:")
        print("1 - Send a message")
        print("2 - Fetch messages")
        print("3 - Exit")

        action = input("Enter your choice (1/2/3): ").strip()

        if action == "1":
            receiver = input("Enter receiver's phone number: ").strip()
            message = input("Type your message: ").strip()
            send_message(phone_number, receiver, message)
        elif action == "2":
            fetch_messages(phone_number, private_pem)
        elif action == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


