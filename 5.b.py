# SM2 Signature Misuse PoC (Project 5-b: reuse of k → leak d)

from hashlib import sha256
from random import SystemRandom
from tinyec import registry

rand = SystemRandom()
curve = registry.get_curve('secp256r1')
G = curve.g
n = curve.field.n

def int_to_bytes(x: int, length=32):
    return x.to_bytes(length, 'big')
def bytes_to_int(b: bytes):
    return int.from_bytes(b, 'big')

def hash_msg(msg):
    return bytes_to_int(sha256(msg).digest())

def generate_keypair():
    d = rand.randrange(1, n)
    P = d * G
    return d, P

def sm2_sign_fixedk(msg: bytes, d: int, k):
    e = hash_msg(msg)
    R = k * G
    r = (e + R.x) % n
    s = ((k - r * d) * pow(1 + d, -1, n)) % n
    return r, s

def recover_privkey_from_reused_k(msg1, sig1, msg2, sig2):
    r1, s1 = sig1
    r2, s2 = sig2
    e1 = hash_msg(msg1)
    e2 = hash_msg(msg2)
    numerator = (s2 - s1) % n
    denominator = (s1 - s2 + r2 - r1) % n
    d = (numerator * pow(denominator, -1, n)) % n
    return d

if __name__ == '__main__':
    d, P = generate_keypair()
    k = rand.randrange(1, n)
    m1 = b"msg one"
    m2 = b"msg two"
    sig1 = sm2_sign_fixedk(m1, d, k)
    sig2 = sm2_sign_fixedk(m2, d, k)
    d_recovered = recover_privkey_from_reused_k(m1, sig1, m2, sig2)
    print("LEAKED" if d == d_recovered else "FAIL")
