
import socket
import threading
import json
import base64
import time
import random


from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


# Storage for clients, pending messages, and OTPs
clients = {}  # Stores registered users (phone -> public key)
pending_messages = {}  # Stores messages for offline users
otp_storage = {}  # Stores OTPs mapped to phone numbers
failed_attempts = {}  # Tracks failed OTP attempts
OTP_EXPIRY_TIME = 60  # OTP validity in seconds
MAX_ATTEMPTS = 3  # Maximum failed attempts before lockout
active_users = set()
def generate_otp():
 """Generate a 6-digit OTP."""
 return str(random.randint(100000, 999999))

#As the MMN requests, we will create a function that sends the OTP through a secure chanel.
def SendBySecureChanel(phone_number, otp):
  print(f"Sending OTP to {phone_number}: {otp}")
  print("The otp send successfully")


def handle_client(client_socket, address):
    global pending_messages, clients, otp_storage, failed_attempts, active_users

    print(f"[*] New client connected: {address}")
    try:
        data = client_socket.recv(4096).decode()
        if not data:
            raise ValueError("Received empty data")
        print(f"[INFO] Received data: {data}")
        request = json.loads(data)
        response = None

        # Handle OTP request
        if request['action'] == 'request_otp':
            phone_number = request['phone_number']

            # בדיקה האם המשתמש כבר מחובר
            if phone_number in active_users:
                response = {'status': 'error', 'message': 'User already connected'}
            else:
                otp = generate_otp()
                otp_storage[phone_number] = {'otp': otp, 'timestamp': time.time()}
                failed_attempts[phone_number] = 0
                SendBySecureChanel(phone_number, otp)
                response = {'status': 'otp_sent', 'otp': otp}
                print(f"The OTP for {phone_number} was sent through secure chanel.")

        # Handle user registration with OTP
        elif request['action'] == 'register':
            phone_number = request['phone_number']
            entered_otp = request['otp']
            public_key = request['public_key']

            if phone_number in active_users:
                response = {'status': 'error', 'message': 'User already connected'}
            elif phone_number not in otp_storage:
                response = {'status': 'error', 'message': 'OTP not requested'}
            elif time.time() - otp_storage[phone_number]['timestamp'] > OTP_EXPIRY_TIME:
                response = {'status': 'error', 'message': 'OTP expired'}
                del otp_storage[phone_number]
            elif failed_attempts[phone_number] >= MAX_ATTEMPTS:
                response = {'status': 'error', 'message': 'Too many failed attempts'}
            elif entered_otp != otp_storage[phone_number]['otp']:
                failed_attempts[phone_number] += 1
                response = {'status': 'error', 'message': 'Invalid OTP'}
            else:
                del otp_storage[phone_number]
                clients[phone_number] = {'public_key': public_key}
                if phone_number not in pending_messages:
                    pending_messages[phone_number] = []
                active_users.add(phone_number)
                response = {'status': 'success'}
                print(f"[*] User {phone_number} registered successfully")

        # Retrieve a user's public key
        elif request['action'] == 'get_public_key':
            phone_number = request['phone_number']
            print(f"[DEBUG] Retrieving public key for {phone_number}")

            if phone_number in clients:
                response = {'status': 'success', 'public_key': clients[phone_number]['public_key']}
                print(f"[DEBUG] Found public key for {phone_number}")
            else:
                response = {'status': 'error', 'message': 'User not found'}
                print(f"[DEBUG] User {phone_number} not found")

        # Handle send message
        elif request['action'] == 'send_message':
            sender = request['sender']
            receiver = request['receiver']
            encrypted_message = request.get('encrypted_message')
            encrypted_aes_key = request.get('encrypted_aes_key')

            print(f"[DEBUG] Attempting to send message:")
            print(f"[DEBUG] Sender: {sender}")
            print(f"[DEBUG] Receiver: {receiver}")
            print(f"[DEBUG] Current pending_messages before adding: {pending_messages}")

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
                    print(f"[DEBUG] Creating new message array for receiver {receiver}")
                    pending_messages[receiver] = []

                pending_messages[receiver].append(message_entry)
                print(f"[DEBUG] Added message from {sender} to {receiver}")
                print(f"[DEBUG] Message entry added: {message_entry}")
                print(f"[DEBUG] Current pending messages after adding: {pending_messages}")
                response = {'status': 'success', 'message': 'Message stored'}

        # Handle fetch messages
        elif request['action'] == 'fetch_messages':
            phone_number = request['phone_number']
            print(f"[DEBUG] Fetching messages for {phone_number}")
            print(f"[DEBUG] Current pending messages: {pending_messages}")

            if phone_number not in clients:
                response = {'status': 'error', 'message': 'User not registered'}
            else:
                messages = pending_messages.get(phone_number, [])
                if messages:
                    print(f"[DEBUG] Found {len(messages)} messages for {phone_number}")
                    print(f"[DEBUG] Messages content: {messages}")
                    response = {'status': 'success', 'messages': messages}
                    pending_messages[phone_number] = []  # Clear after sending
                else:
                    print(f"[DEBUG] No messages found for {phone_number}")
                    response = {'status': 'no_messages'}

        if response:
            client_socket.send(json.dumps(response).encode())
        else:
            client_socket.send(json.dumps({'status': 'error', 'message': 'Unknown request'}).encode())

    except json.JSONDecodeError:
        print(f"[!] Error with client {address}: Invalid JSON received")
        client_socket.send(json.dumps({'status': 'error', 'message': 'Invalid JSON'}).encode())
    except Exception as e:
        print(f"[!] Error with client {address}: {str(e)}")
        client_socket.send(json.dumps({'status': 'error', 'message': str(e)}).encode())
        if 'request' in locals() and 'phone_number' in request:
            active_users.discard(request['phone_number'])
    finally:
        if 'request' in locals() and 'phone_number' in request:
            active_users.discard(request['phone_number'])
        client_socket.close()


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
