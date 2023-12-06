from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import base64
import json

import argon2.exceptions
import jwt
from datetime import datetime, timedelta
# Project 2 (P2) imports
import time
import sqlite3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
#from jose import jwk, jwt, jws # errors
#from datetime import datetime, timedelta # bad

# Project 3 (P3) imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from flask import Flask, request, jsonify
import hashlib
import uuid
from argon2 import PasswordHasher

hostName = "localhost"
serverPort = 8080

# P1: Generates an RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()

# P2 extra data
# Serialize key pair to JSON
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')
# Public key
public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
# Key Pair to act like an RSA key pair
keyPair = {
    "private_key": private_key_pem,
    "public_key": public_key_pem
}

def int_to_base64(value):
    # Converts an integer to a Base64URL-encoded string
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def pem_to_jwk(kid, pem_key, exp=None):
    # Load the PEM key
    priv_key = serialization.load_pem_private_key(
        pem_key,
        password=None,
        backend=default_backend()
    )
    public_key = priv_key.public_key()
    # Convert the public key to JWK format
    public_numbers = public_key.public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": str(kid),
        "exp": exp,
        "n": int_to_base64(public_numbers.n),
        "e": int_to_base64(public_numbers.e)
    }
    return jwk

def StoreKeyInDatabase(priv_key, expiry):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()

    try:
        cursor.execute("CREATE TABLE IF NOT EXISTS keys (kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL)")
        cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (priv_key, int(expiry.timestamp())))
        conn.commit()
        print("Key stored in the database.")
    except sqlite3.Error as e:
        print("Failed to store the key pair in the database:", e)
    finally:
        conn.close()


def GetKeysFromDatabase():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM keys WHERE exp > strftime('%s', 'now')")
        results = cursor.fetchall()
        if results:
            return results
    except sqlite3.Error as e:
        print("Failed to retrieve the keys from the database:", e)
    finally:
        conn.close()

#P3
def StoreUser(username, hashedPassword, email): # Stores the user data for registering a user
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (username, hashedPassword, email))
        conn.commit()
        return True
    except sqlite3.Error as e:
        print("Error occurred during user registration:", e)
        return False
    finally:
        conn.close()

def GetUser(username, password):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        return None
    ph = PasswordHasher()
    try:
        if ph.verify(user[2], password):
            return user
        else:
            return None
    except argon2.exceptions.VerifyMismatchError:
        return None

def InsertAuthLog(ip, id):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, date('now'), ?) ", (ip, id))
    conn.commit()
    return


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            user = GetUser(data["username"], data["password"])
            if user is None:
                self.send_response(401)
                self.end_headers()
                return
            keys = GetKeysFromDatabase()

            #print(keys)
            key = keys[0]
            headers = {
                "kid": str(key[0])
            }
            token_payload = {
                "subj": data["username"],
                "exp": key[2]
            }
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.utcnow() - timedelta(hours=1)
            priv_key = serialization.load_pem_private_key(
                key[1].encode(),
                password=None,
                backend=default_backend()
            )
            encoded_jwt = jwt.encode(token_payload, priv_key, algorithm="RS256", headers=headers)

            InsertAuthLog(self.client_address[0], user[0]) # Calls the InsertAuthLog function

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        elif parsed_path.path == "/register": # Meant for registering users
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            if not data:
                self.send_response(500)
                self.end_headers()
                return

            username = data["username"]
            password = str(uuid.uuid4())
            ph = PasswordHasher()
            hashed_uuid = ph.hash(password) #Hashed
            email = data["email"]
            if not username or not password or not email:
                self.send_response(500)
                self.end_headers()
                return

            if StoreUser(username, hashed_uuid, email):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(json.dumps({"password": f"{password}"}), "utf-8"))
            else:
                self.send_response(500)
                self.end_headers()
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            keys = self.GetKeysInDatabase() # Fetches the data
            # Convert each row to a JWK and add to the JWKS list
            jwks = {"keys": [pem_to_jwk(kid, key, exp) for kid, key, exp in keys]}

            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


    keyID = "newKey1" # The key id
    expiry = datetime.now() + timedelta(hours=1) # Expiration time
    # keyPairJSON = json.dumps(keyPair) # Generates the key pair
    # P2: Stores the new key pair in the database
    #self.StoreKeyInDatabase(self, keyPair, expiry)


    # P3 functions below
    # Encryption function
    def encrypt_AES(key, plaintext):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext

    # Decryption function
    def decrypt_AES(key, ciphertext):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

    # Creates the table for the user with the appropriate fields to store information and hashed passwords
    def create_users_table(self):
        conn = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL UNIQUE,
                            password_hash TEXT NOT NULL,
                            email TEXT UNIQUE,
                            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            last_login TIMESTAMP
                        )''')
        conn.commit()
        conn.close()

    #This database table is created to log authentication requests with schema
    def CreateAuthLogsTable(self):
        conn = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS auth_logs (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            request_ip TEXT NOT NULL,
                            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            user_id INTEGER,
                            FOREIGN KEY(user_id) REFERENCES users(id)
                        )''')
        conn.commit()
        conn.close()


    # Authentication logging used to help authenticate the user
    def LogAuthentication(request_ip, user_id):
        conn = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (request_ip, user_id))
        conn.commit()
        conn.close()

    #app = Flask(__name__)
    #@app.route('/auth', methods=['POST'])
    # def authenticate_user(self, userID):
    #     REQUESTS_DATA = {}
    #     REQUEST_LIMIT = 10
    #     TIME_FRAME = 1  # in seconds
    #     client_ip = request.remote_addr
    #
    #     # Check if the IP is in the dictionary
    #     if client_ip in REQUESTS_DATA:
    #         # Get the list of timestamps for the IP
    #         timestamps = REQUESTS_DATA[client_ip]
    #
    #         # Filter timestamps within the timeframe
    #         recent_timestamps = [ts for ts in timestamps if time.time() - ts <= TIME_FRAME]
    #
    #         # If recent requests exceed the limit, return 429 Too Many Requests
    #         if len(recent_timestamps) >= REQUEST_LIMIT:
    #             return "429 Too Many Requests", 429
    #
    #         # Update the list of timestamps for the IP
    #         REQUESTS_DATA[client_ip] = recent_timestamps + [time.time()]
    #     else:
    #         # If IP not in the dictionary, add it with the current timestamp
    #         REQUESTS_DATA[client_ip] = [time.time()]
    #
    #     # Proceed with authentication logic here
    #
    #     # Log authentication if it succeeds
    #     self.LogAuthentication(client_ip, userID)  # Implement your log function here
    #     return jsonify({'message': 'Authentication successful'})

    # Function Calls
    create_users_table(None)
    CreateAuthLogsTable(None)
    # RegisterUser(None)
    # LogAuthentication(None)
    StoreKeyInDatabase(private_key_pem, expiry)



if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    #app.run(debug=True)
    try:
        print("Server is running on port 8080.....")  # Testing the server
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
