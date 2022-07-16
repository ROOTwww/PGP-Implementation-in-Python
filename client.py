from cryption import *

HOST = "127.0.0.1"
PORT = 14785

Key_client_public, Key_client_private = RSA_Create_Keys()

msg = input("Message->")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

Key_server_public = RSA_deSerialize(s.recv(315))

s.send(RSA_Serialize(Key_client_public) )

ACK = s.recv(315)
if b"ACK" != RSA_Decrypt(Key_client_private, ACK):
    print("ACK Error")
    exit()
s.send(RSA_Encrypt(Key_server_public, "ACK".encode("ascii")))

hash_msg = hashlib.md5(msg.encode("ascii"))

crypt_hash_msg = RSA_Encrypt(Key_server_public, hash_msg.hexdigest().encode("ascii"))

P1 = crypt_hash_msg + b"::" + msg.encode("ascii")

P1_Z = zlib.compress(P1)

crypt_P1_Z, aeskey = AES_Encrypt(P1_Z)

crypt_aeskey = RSA_Encrypt(Key_server_public, aeskey)
P1_Z2 = crypt_P1_Z + b"::" + crypt_aeskey

data = base64.b64encode(P1_Z2)

s.send(data)
