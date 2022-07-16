from cryption import *

HOST = "127.0.0.1"
PORT = 14785

Key_server_public, Key_server_private = RSA_Create_Keys()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen()

print("Server started")
conn, addr = s.accept()

conn.send(RSA_Serialize(Key_server_public))

Key_client_public = RSA_deSerialize(conn.recv(315))

ACK =RSA_Encrypt(Key_client_public, "ACK".encode("ascii"))
conn.send(ACK)

ACK = conn.recv(315)
if b"ACK" != RSA_Decrypt(Key_server_private, ACK):
    print("ACK Error")
    exit()

data = conn.recv(992)

P1_Z2 = base64.b64decode(data)

crypt_P1_Z, crypt_aeskey = P1_Z2.split(b"::")

aeskey = RSA_Decrypt(Key_server_private, crypt_aeskey)

P1_Z = AES_Decrypt(aeskey, crypt_P1_Z)

P1 = zlib.decompress(P1_Z)

crypt_hash_msg, msg = P1.split(b"::")

hash_msg = RSA_Decrypt(Key_server_private, crypt_hash_msg)

if hash_msg != hashlib.md5(msg).hexdigest().encode("ascii"):
    print("Hash error")

print("Message: ", msg.decode("ascii"))