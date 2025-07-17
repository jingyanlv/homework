import hashlib
import random
from dataclasses import dataclass, field
from typing import List, Tuple, Dict

from tinyec import registry
from phe import paillier


curve = registry.get\_curve("secp256r1")
q = curve.field.n
G = curve.g


def hash\_to\_int(value: str) -> int:
"""Hash a UTF‑8 string to an integer < q."""
digest = hashlib.sha256(value.encode()).digest()
return int.from\_bytes(digest, "big") % q

def hash\_to\_point(value: str):
"""Map arbitrary string deterministically onto the curve.

```
Re‑hash on rare failures until we land on a valid x‑coordinate.
"""
candidate = value
while True:
    x = hash_to_int(candidate)
    try:
        return x * G
    except ValueError:
        candidate = hashlib.sha256(candidate.encode()).hexdigest()
```

def point\_pow(point, exponent: int):
"""Scalar‑multiply a point (fast exponentiation in group)."""
return exponent \* point

def point\_to\_bytes(point):
"""Serialize a point to 64‑byte (x‖y) big‑endian representation."""
return point.x.to\_bytes(32, "big") + point.y.to\_bytes(32, "big")

# ----- Party definitions ---------------------------------------------------

@dataclass
class Party1:
"""Client holding set V; learns |V∩W| and Σ t\_j."""

```
V: List[str]
k1: int = field(default_factory=lambda: random.SystemRandom().randint(1, q - 1))
pk: paillier.PaillierPublicKey = field(init=False)
sk: paillier.PaillierPrivateKey = field(init=False)

def __post_init__(self):
    self.pk, self.sk = paillier.generate_paillier_keypair()

# Round‑1 ---------------------------------------------------------------
def first_round(self):
    """Blind identifiers and send to P2 with Paillier pk."""
    A = [point_pow(hash_to_point(v), self.k1) for v in self.V]
    random.shuffle(A)
    return A, self.pk

# Round‑3 ---------------------------------------------------------------
def third_round(self, B: List, tagged_ciphertexts: List[Tuple]):
    """Match intersection & decrypt homomorphic sum."""
    B_serial = {point_to_bytes(b) for b in B}
    enc_sum = self.pk.encrypt(0)
    m = 0
    for C_j, E_j in tagged_ciphertexts:
        D_j = point_pow(C_j, self.k1)
        if point_to_bytes(D_j) in B_serial:
            enc_sum += E_j  # Paillier additive homomorphism
            m += 1
    total = self.sk.decrypt(enc_sum)
    return m, total
```

@dataclass
class Party2:
"""Server holding dictionary W: id → tag."""

```
W: Dict[str, int]
k2: int = field(default_factory=lambda: random.SystemRandom().randint(1, q - 1))

# Round‑2 ---------------------------------------------------------------
def second_round(self, A: List, pk: paillier.PaillierPublicKey):
    B = [point_pow(a, self.k2) for a in A]
    tagged_ciphertexts = []
    for w, t_j in self.W.items():
        C_j = point_pow(hash_to_point(w), self.k2)
        E_j = pk.encrypt(t_j)
        tagged_ciphertexts.append((C_j, E_j))
    return B, tagged_ciphertexts
```

# ----- Demo ----------------------------------------------------------------

def run\_demo():
V = \["[alice@example.com](mailto:alice@example.com)", "[bob@example.com](mailto:bob@example.com)", "[carol@example.com](mailto:carol@example.com)"]
W = {
"[carol@example.com](mailto:carol@example.com)": 10,
"[bob@example.com](mailto:bob@example.com)": 6,
"[dave@example.com](mailto:dave@example.com)": 1,
}

```
p1 = Party1(V)
p2 = Party2(W)

# R1: P1 → P2
A, pk = p1.first_round()

# R2: P2 → P1
B, tagged_ciphertexts = p2.second_round(A, pk)

# R3: P1 computes result
size, ssum = p1.third_round(B, tagged_ciphertexts)

print(f"[P1] |V ∩ W| = {size}")
print(f"[P1] Σ t_j over intersection = {ssum}")
```

if **name** == "**main**":
run\_demo()
