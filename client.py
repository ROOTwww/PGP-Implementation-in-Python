from sifreleme import *

HOST = "127.0.0.1"
PORT = 14785

Key_client_public, Key_client_private = RSAOlustur()

HARDCODEDMESSAGE = input("Message->")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

Key_server_public = RSADeSerialize(s.recv(315))

s.send(RSASerialize(Key_client_public) )

ACK = s.recv(315)
if b"ACK" != RSASifrecoz(Key_client_private, ACK):
    print("ACK Error")
    exit()
s.send(RSASifrele(Key_server_public, "ACK".encode("ascii")))

hash_mesaj = hashlib.md5(HARDCODEDMESSAGE.encode("ascii"))

sifreli_hash_mesaj = RSASifrele(Key_server_public, hash_mesaj.hexdigest().encode("ascii"))

P1 = sifreli_hash_mesaj + b"::" + HARDCODEDMESSAGE.encode("ascii")

P1_Z = zlib.compress(P1)

sifreli_P1_Z, aeskey = AESSifrele(P1_Z)

sifreli_aeskey = RSASifrele(Key_server_public, aeskey)
P1_Z2 = sifreli_P1_Z + b"::" + sifreli_aeskey

data = base64.b64encode(P1_Z2)

s.send(data)
