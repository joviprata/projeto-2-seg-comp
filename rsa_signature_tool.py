import hashlib
import base64
import os
import random
from math import gcd

# Funções auxiliares substituindo Crypto.Util.number

def bytes_para_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

def int_para_bytes(n: int, length=None) -> bytes:
    if length is None:
        length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder='big')

def inverso_modular(a, m):
    # Algoritmo de Euclides Estendido
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1
    
# Geração de Chaves e Cifração

def miller_rabin(n, k=40):
    if n in (2, 3):
        return True
    if n <= 1 or n % 2 == 0:
        return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x in (1, n - 1):
            continue
        for __ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gerar_primo_grande(bits=1024):
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1
        if miller_rabin(p):
            return p

def gerar_chaves_rsa(bits=1024):
    p = gerar_primo_grande(bits)
    q = gerar_primo_grande(bits)
    while q == p:
        q = gerar_primo_grande(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if gcd(e, phi) != 1:
        return gerar_chaves_rsa(bits)
    d = inverso_modular(e, phi)
    return {'public': (n, e), 'private': (n, d)}

# OAEP

def oaep_cifrar(message: bytes, k: int) -> int:
    m_hash = hashlib.sha3_256(b'').digest()
    ps = b'\x00' * (k - len(message) - 2 * len(m_hash) - 2)
    db = m_hash + ps + b'\x01' + message
    seed = os.urandom(len(m_hash))
    db_mask = hashlib.sha3_256(seed).digest() + hashlib.sha3_256(seed[::-1]).digest()
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    seed_mask = hashlib.sha3_256(masked_db).digest()
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))
    return bytes_para_int(b'\x00' + masked_seed + masked_db)

def oaep_decifrar(em: int, k: int) -> bytes:
    em_bytes = int_para_bytes(em, k)
    h_len = hashlib.sha3_256(b'').digest_size
    masked_seed = em_bytes[1:1 + h_len]
    masked_db = em_bytes[1 + h_len:]
    seed_mask = hashlib.sha3_256(masked_db).digest()
    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))
    db_mask = hashlib.sha3_256(seed).digest() + hashlib.sha3_256(seed[::-1]).digest()
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))
    i = db.find(b'\x01', h_len)
    return db[i+1:]
