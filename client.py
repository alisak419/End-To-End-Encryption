import socket
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# server
HOST = "127.0.0.1"
PORT = 12345

# יצירת מפתח פרטי וציבורי ללקוח
client_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
client_public_key = client_private_key.public_key()

# שמירת המפתח הציבורי של הלקוח בקובץ PEM
client_id = "1234567890"  # מספר זיהוי ייחודי ללקוח
client_public_key_file = f"client_{client_id}_public_key.pem"

with open(client_public_key_file, "wb") as f:
    f.write(
        client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print(f"Client public key saved as '{client_public_key_file}'.")

# שליחת בקשה לשרת
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    client_socket.connect((HOST, PORT))
    print(f"Connected to server at {HOST}:{PORT}")

    # שליחת בקשת הרשמה
    registration_data = {
        "type": "register",
        "client_id": client_id,
        "public_key": client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    }
    client_socket.sendall(json.dumps(registration_data).encode())
    print("Registration request sent.")

    # קבלת תגובת השרת
    response = client_socket.recv(4096)
    print("Server response:", response.decode())