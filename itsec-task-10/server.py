import asyncio
from Crypto.Util.number import *
from Crypto.Cipher import PKCS1_OAEP 
from Crypto.PublicKey import RSA
import subprocess
import random

try:
    from scoreboard_util import verify_code
except ImportError:
    print("verify_code not available!")
    # Replace verfiy_code with a mock function
    # allowing students to run the code locally
    verify_code = lambda x: True

def generate_keys(count, primes):
    keys = []
    for i in range(count):
        while True:
            p = random.choice(primes)
            q = random.choice(primes)
            phi = (p-1)*(q-1)
            N = p*q
            e = 3
            if math.gcd(e,p-1) != 1: continue
            if math.gcd(e,q-1) != 1: continue
            break
        d = inverse(e, phi)
        keys.append((p, q, N, e, d))
    return keys

# Primes are expensive to generate, so lets create a few at program start
def generate_primes(count):
    primes = []
    for i in range(count):
        primes.append(getStrongPrime(512))
    return primes

async def handle_connection(primes, reader, writer):
    token = await reader.readline()
    
    # Abort connection if no valid token is provided
    if not verify_code(token.strip().decode()):
        writer.write(b"Access denied - You need a valid token from the Scoreboard!")
        await writer.drain()
        writer.transport.abort()
        return
    
    print("Client connected!")

    # Pick some keys for crypto magic!
    keys = generate_keys(10, primes)
    print(len(keys))

    assert(len(keys) == 10)

    # Send public keys to the user
    for i, k in enumerate(keys):
        p, q, N, e, d = k
        writer.write(f"[Key {i}]: N = {N:x} e = {e:x}\n".encode())
    writer.write(b"\n")
    await writer.drain()
    client_choice = await reader.readline()
    print(f"Got {client_choice.decode()}")
    try:
        client_choice = int(client_choice)
        key = keys[client_choice]
    except ValueError:
        writer.write(b"Something went wrong... Did you use a number between 0 and 9?")
        await writer.drain()

    p, q, N, e, d = key
    cipher = PKCS1_OAEP.new(RSA.construct((N, e, d, p, q)))
    flag = subprocess.check_output(["/bin/flag"])
    encrypted_msg = cipher.encrypt(flag).hex()
    print(encrypted_msg)

    writer.write(encrypted_msg.encode())
    await writer.drain()
    writer.close()

async def run_server():
    primes = generate_primes(100)

    # Start server
    server = await asyncio.start_server(lambda r, w: handle_connection(primes, r, w), "0.0.0.0", 1024)
    ip, port = server.sockets[0].getsockname()
    print(f"Serving on {ip}:{port}")

    await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(run_server())
