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
