import socket
import re
from Crypto.Util.number import *
from Crypto.Cipher import PKCS1_OAEP 
from Crypto.PublicKey import RSA

def recv_chunk(s):
    buf = b""
    while True:
        d = s.recv(1)
        if d == b"":
            return buf
        buf += d
        if buf[-2:] == b"\n\n":
            return buf


s = socket.socket()
s.connect(("itsec.sec.in.tum.de", 7009))

TOKEN = "c39c673a29ae12be" # TODO: Insert personal access token from scoreboard here
s.sendall(TOKEN.encode() + b"\n")
data = recv_chunk(s).decode()
print(data)
keys = {}
for m in re.findall("\[Key (\d+)\]: N = ([0-9a-f]*) e = ([0-9a-f]*)", data):
    k, N, e = int(m[0],16), int(m[1],16), int(m[2],16)
    keys[k] = (N, e)

# Sorry for the bad template... There was not enough time during the U-Bahn ride to get this nice :/
s.sendall(b"1234\n") # TODO: Make a sane choice here

# TODO: Your exploit goes here

data = recv_chunk(s).decode()
print("Encrypted flag:", data)
