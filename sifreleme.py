import socket
import hashlib
import zlib
import base64
import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def RSAOlustur():
    _public, _private = rsa.newkeys(1024)
    return _public, _private

def RSASifrele(key, data):
    return rsa.encrypt(data, key)

def RSASifrecoz(key, data):
    return rsa.decrypt(data, key)

def AESSifrele(data):
    aeskey = get_random_bytes(16)
    cipher = AES.new(aeskey, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return (cipher.nonce + b":;:" +  tag + b":;:" + ciphertext), aeskey

def AESSifrecoz(aeskey, data):
    nonce, tag, ciphertext = data.split(b":;:")
    cipher = AES.new(aeskey, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def RSASerialize(key):
    return ( bytes(str(key.n), "ascii") + bytes(",", "ascii") + bytes(str(key.e), "ascii") )

def RSADeSerialize(key):
    key = str(key)
    n, e = key.split(",")
    e = e.replace("'", "")
    e = int(e)
    n = n.replace("'", "")
    n = n.replace("b", "")
    n = int(n)    
    return rsa.PublicKey(n,e)
