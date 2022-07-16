import socket
import hashlib
import zlib
import base64
import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def RSA_Create_Keys():
    _public, _private = rsa.newkeys(1024)
    return _public, _private

def RSA_Encrypt(key, data):
    return rsa.encrypt(data, key)

def RSA_Decrypt(key, data):
    return rsa.decrypt(data, key)

def RSA_Serialize(key):
    return ( bytes(str(key.n), "ascii") + bytes(",", "ascii") + bytes(str(key.e), "ascii") )

def RSA_deSerialize(key):
    key = str(key)
    n, e = key.split(",")
    e = e.replace("'", "")
    e = int(e)
    n = n.replace("'", "")
    n = n.replace("b", "")
    n = int(n) 
    return rsa.PublicKey(n,e)

def AES_Encrypt(data):
    aeskey = get_random_bytes(16)
    cipher = AES.new(aeskey, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return (cipher.nonce + b":;:" +  tag + b":;:" + ciphertext), aeskey

def AES_Decrypt(aeskey, data):
    nonce, tag, ciphertext = data.split(b":;:")
    cipher = AES.new(aeskey, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)