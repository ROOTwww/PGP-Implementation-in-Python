from sifreleme import *

HOST = "127.0.0.1"
PORT = 14785

Key_server_public, Key_server_private = RSAOlustur()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen()

conn, addr = s.accept()

conn.send(RSASerialize(Key_server_public))

Key_client_public = RSADeSerialize(conn.recv(315))

ACK =RSASifrele(Key_client_public, "ACK".encode("ascii"))
conn.send(ACK)

ACK = conn.recv(315)
if b"ACK" != RSASifrecoz(Key_server_private, ACK):
    print("ACK Error")
    exit()

data = conn.recv(992)

P1_Z2 = base64.b64decode(data)

sifreli_P1_Z, sifreli_aeskey = P1_Z2.split(b"::")

aeskey = RSASifrecoz(Key_server_private, sifreli_aeskey)

P1_Z = AESSifrecoz(aeskey, sifreli_P1_Z)

P1 = zlib.decompress(P1_Z)

sifreli_hash_mesaj, HARDCODEDMESSAGE = P1.split(b"::")

hash_mesaj = RSASifrecoz(Key_server_private, sifreli_hash_mesaj)

if hash_mesaj != hashlib.md5(HARDCODEDMESSAGE).hexdigest().encode("ascii"):
    print("Hash error")

print("Message: ", HARDCODEDMESSAGE.decode("ascii"))