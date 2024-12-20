
import socket
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# הגדרות השרת
HOST = "127.0.0.1"
PORT = 12345

# יצירת מילון לשמירת נתוני לקוחות
clients_data = {}

# יצירת מפתח פרטי וציבורי לשרת
server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
server_public_key = server_private_key.public_key()

# שמירת המפתח הציבורי של השרת בקובץ PEM
with open("server_public_key.pem", "wb") as f:
    f.write(
        server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("Server public key saved as 'server_public_key.pem'.")

# הפעלת השרת
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"Server is listening on {HOST}:{PORT}")

    while True:
        conn, addr = server_socket.accept()
        with conn:
            print(f"Connected by {addr}")
            try:
                # קבלת הנתונים מהלקוח
                data = conn.recv(4096)
                if not data:
                    break

                message = json.loads(data.decode())
                if message["type"] == "register":
                    client_id = message["client_id"]
                    public_key_pem = message["public_key"]

                    # שמירת מפתח הלקוח
                    clients_data[client_id] = {
                        "public_key": public_key_pem,
                        "messages": []
                    }
                    print(f"Registered client: {client_id}")

                    # שליחת תגובה ללקוח
                    conn.sendall(b"Registration successful")
            except Exception as e:
                print(f"Error handling client {addr}: {e}")