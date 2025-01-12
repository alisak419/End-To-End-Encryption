
import socket
import threading
import json
import base64
import time
import random

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

clients = {}  # Stores registered users (phone -> public key)
pending_messages = {}  # Stores messages for offline users
otp_storage = {}  # Stores OTPs mapped to phone numbers
failed_attempts = {}  # Tracks failed OTP attempts
OTP_EXPIRY_TIME = 60  # OTP validity in seconds
MAX_ATTEMPTS = 3  # Maximum failed attempts before lockout
active_users = set()

# Generate the server's RSA key pair and store the public key in PEM format.
SERVER_PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
SERVER_PUBLIC_KEY = SERVER_PRIVATE_KEY.public_key()
SERVER_PUBLIC_PEM = SERVER_PUBLIC_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

"""
Signs the server's response using the RSA private key.

Args:
    response_data (dict): The response data to be signed.
Returns:
    dict: The signed response containing the original data and its base64-encoded signature.
"""
def sign_response(response_data):
    signature = SERVER_PRIVATE_KEY.sign(
        json.dumps(response_data).encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return {
        'data': response_data,
        'signature': base64.b64encode(signature).decode()
    }

"""
Generates a 6-digit one-time password (OTP).

Returns:
    str: A randomly generated 6-digit OTP.
"""
def generate_otp():
 return str(random.randint(100000, 999999))

"""
Simulates sending an OTP through a secure channel.

Args:
    phone_number (str): The recipient's phone number.
    otp (str): The OTP to send.
Returns:
    None
"""
def SendBySecureChanel(phone_number, otp):
  print(f"Sending OTP to {phone_number}: {otp}")
  print("The otp send successfully")

"""
Handles client connections and processes requests.

Args:
    client_socket (socket.socket): The socket object representing the client connection.
    address (tuple): The client's address (IP, port).

Processes various client actions, including:
- Requesting and verifying OTP for authentication.
- Registering and reconnecting users securely.
- Retrieving public keys for secure messaging.
- Sending and receiving encrypted messages.
- Handling user disconnection.

Returns:
    None
"""


def handle_client(client_socket, address):
    global pending_messages, clients, otp_storage, failed_attempts, active_users

    try:
        data = client_socket.recv(4096).decode()
        request = json.loads(data)
        response = None

        # Handle OTP request
        if request['action'] == 'request_otp':
            phone_number = request['phone_number']

            # Generate OTP
            otp = generate_otp()
            otp_storage[phone_number] = {'otp': otp, 'timestamp': time.time()}
            failed_attempts[phone_number] = 0

            # Sign the OTP with server's private key
            signature = base64.b64encode(
                SERVER_PRIVATE_KEY.sign(
                    otp.encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            ).decode()

            # Send signed OTP along with server's public key
            response = {
                'status': 'otp_sent',
                'otp': otp,
                'otp_signature': signature,
                'server_public_key': SERVER_PUBLIC_PEM.decode()
            }
            print(f"Signed OTP sent to {phone_number}")

        # Handle user registration
        elif request['action'] == 'register':
            phone_number = request['phone_number']
            encrypted_otp = request['encrypted_otp']
            signature = request['otp_signature']
            public_key = request['public_key']

            if phone_number in active_users:
                response = {'status': 'error', 'message': 'User already connected'}
                return

            # Decrypt the OTP using server's private key
            try:
                decrypted_otp = SERVER_PRIVATE_KEY.decrypt(
                    base64.b64decode(encrypted_otp),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).decode()
            except Exception:
                response = {'status': 'error', 'message': 'Invalid encrypted OTP'}
                return

            # Verify OTP signature
            try:
                SERVER_PUBLIC_KEY.verify(
                    base64.b64decode(signature),
                    decrypted_otp.encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except Exception:
                response = {'status': 'error', 'message': 'Invalid OTP signature'}
                return

            # Standard OTP validations
            if phone_number not in otp_storage:
                response = {'status': 'error', 'message': 'OTP not requested'}
                return

            if time.time() - otp_storage[phone_number]['timestamp'] > OTP_EXPIRY_TIME:
                response = {'status': 'error', 'message': 'OTP expired'}
                del otp_storage[phone_number]
                return

            if failed_attempts[phone_number] >= MAX_ATTEMPTS:
                response = {'status': 'error', 'message': 'Too many failed attempts'}
                return

            # Verify OTP
            if decrypted_otp != otp_storage[phone_number]['otp']:
                failed_attempts[phone_number] += 1
                response = {'status': 'error', 'message': 'Invalid OTP'}
                return

            # Cleanup
            active_users.discard(phone_number)
            del otp_storage[phone_number]

            # Handle existing user
            if phone_number in clients:
                stored_public_key = clients[phone_number]['public_key']
                if phone_number in active_users:
                    print(f"[!] User {phone_number} is already connected. Rejecting new connection attempt.")
                    response = {'status': 'error', 'message': 'User already connected'}
                    return
                if public_key != stored_public_key:
                    print(f"[!] Key mismatch for {phone_number}")
                    response = {'status': 'error', 'message': 'Invalid public key for existing user'}
                    return

                active_users.add(phone_number)
                response = {
                    'status': 'success',
                    'message': 'Reconnection successful',
                    'server_public_key': SERVER_PUBLIC_PEM.decode()
                }
                print(f"[*] User {phone_number} reconnected successfully")
            else:
                # New user registration
                clients[phone_number] = {'public_key': public_key}
                if phone_number not in pending_messages:
                    pending_messages[phone_number] = []
                active_users.add(phone_number)
                response = {
                    'status': 'success',
                    'message': 'Registration successful',
                    'server_public_key': SERVER_PUBLIC_PEM.decode()
                }
                print(f"[*] User {phone_number} registered successfully")

        # Retrieve a user's public key
        elif request['action'] == 'get_public_key':
            phone_number = request['phone_number']

            if phone_number in clients:
                response = {'status': 'success', 'public_key': clients[phone_number]['public_key']}
            else:
                response = {'status': 'error', 'message': 'User not found'}

        # Handle send message
        elif request['action'] == 'send_message':
            sender = request['sender']
            receiver = request['receiver']
            encrypted_message = request.get('encrypted_message')
            encrypted_aes_key = request.get('encrypted_aes_key')

            if not encrypted_message or not encrypted_aes_key:
                response = {'status': 'error', 'message': 'Missing encrypted data'}
            elif receiver not in clients:
                response = {'status': 'error', 'message': 'Receiver not registered'}
            else:
                message_entry = {
                    'sender': sender,
                    'encrypted_message': encrypted_message,
                    'encrypted_aes_key': encrypted_aes_key
                }
                if receiver not in pending_messages:
                    pending_messages[receiver] = []
                pending_messages[receiver].append(message_entry)
                response = {'status': 'success', 'message': 'Message stored'}

        # Handle disconnect
        elif request['action'] == 'disconnect':
            phone_number = request['phone_number']
            if phone_number in active_users:
                active_users.discard(phone_number)
                response = {'status': 'success', 'message': 'User disconnected'}
                print(f"[*] User {phone_number} has disconnected")
            else:
                response = {'status': 'error', 'message': 'User not connected'}

        # Handle fetch messages
        elif request['action'] == 'fetch_messages':
            phone_number = request['phone_number']
            if phone_number not in clients:
                response = {'status': 'error', 'message': 'User not registered'}
            else:
                messages = pending_messages.get(phone_number, [])
                if messages:
                    response = {'status': 'success', 'messages': messages}
                    pending_messages[phone_number] = []  # Clear after sending
                else:
                    response = {'status': 'no_messages'}

        # Handle get server key request
        elif request['action'] == 'get_server_key':
            response = {
                'status': 'success',
                'server_public_key': SERVER_PUBLIC_PEM.decode()
            }
            client_socket.send(json.dumps(response).encode())
            return  # Special case - we return immediately

        # Send signed response for all other cases
        if response:
            signed_response = {
                'data': response,
                'signature': base64.b64encode(
                    SERVER_PRIVATE_KEY.sign(
                        json.dumps(response).encode(),
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                ).decode()
            }
            client_socket.send(json.dumps(signed_response).encode())


    except json.JSONDecodeError:
        print(f"[!] Error with client {address}: Invalid JSON received")
        client_socket.send(json.dumps({'status': 'error', 'message': 'Invalid JSON'}).encode())
    except Exception as e:
        print(f"[!] Error with client {address}: {str(e)}")
        client_socket.send(json.dumps({'status': 'error', 'message': str(e)}).encode())
        if 'request' in locals() and 'phone_number' in request:
            active_users.discard(request['phone_number'])
    finally:
        client_socket.close()


"""
Starts the server and listens for incoming connections.
Creates a socket, binds it to port 9999, and begins listening for clients.

Returns:
    None
"""
def start_server():
 server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 server.bind(('0.0.0.0', 9999))
 server.listen(10)
 print("[*] Server is ready to accept connections...")

 while True:
     client_socket, addr = server.accept()
     client_thread = threading.Thread(target=handle_client, args=(client_socket, addr))
     client_thread.start()

if __name__ == "__main__":
 start_server()
