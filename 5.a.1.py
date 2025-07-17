# SM2 Basic Python Implementation (Project 5-a Stage 1)


from hashlib import sha256
from random import SystemRandom
from tinyec import registry
import binascii

rand = SystemRandom()
curve = registry.get_curve('secp256r1')  # Same params as SM2
G = curve.g
n = curve.field.n
p = curve.field.p

def int_to_bytes(x: int, length=32) -> bytes:
    return x.to_bytes(length, byteorder='big')

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

def hash_z(ID: str, Px: int, Py: int) -> bytes:
    entl = len(ID) * 8
    z = int_to_bytes(entl, 2) + ID.encode() + \
        int_to_bytes(curve.a) + int_to_bytes(curve.b) + \
        int_to_bytes(G.x) + int_to_bytes(G.y) + \
        int_to_bytes(Px) + int_to_bytes(Py)
    return sha256(z).digest()

def hash_msg(z: bytes, msg: bytes) -> int:
    return bytes_to_int(sha256(z + msg).digest())

# Key generation
def generate_keypair():
    d = rand.randrange(1, n)
    P = d * G
    return d, P

# SM2 Signature (basic)
def sm2_sign(msg: bytes, ID: str, d: int, P):
    z = hash_z(ID, P.x, P.y)
    e = hash_msg(z, msg)
    while True:
        k = rand.randrange(1, n)
        R = k * G
        r = (e + R.x) % n
        if r == 0 or r + k == n:
            continue
        s = ((k - r * d) * pow(1 + d, -1, n)) % n
        if s == 0:
            continue
        return (r, s)

# SM2 Verification (basic)
def sm2_verify(msg: bytes, ID: str, P, signature):
    r, s = signature
    if not (1 <= r <= n - 1 and 1 <= s <= n - 1):
        return False
    z = hash_z(ID, P.x, P.y)
    e = hash_msg(z, msg)
    t = (r + s) % n
    if t == 0:
        return False
    R = s * G + t * P
    R_x = (e + R.x) % n
    return R_x == r

# Demo
if __name__ == '__main__':
    ID = "Alice"
    msg = b"Attack at dawn"
    d, P = generate_keypair()
    print(f"Private key d = {hex(d)}")
    print(f"Public key P = ({hex(P.x)}, {hex(P.y)})")
    sig = sm2_sign(msg, ID, d, P)
    print(f"Signature: r = {hex(sig[0])}, s = {hex(sig[1])}")
    ok = sm2_verify(msg, ID, P, sig)
    print("Verification:", "PASS" if ok else "FAIL")
