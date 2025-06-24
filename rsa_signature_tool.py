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

# Assinatura

def sha3_hash(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()

def assinar_mensagem(data: bytes, private_key: tuple) -> str:
    n, d = private_key
    digest = sha3_hash(data)
    assinatura_int = pow(bytes_para_int(digest), d, n)
    return base64.b64encode(int_para_bytes(assinatura_int)).decode()

# Verificação

def verificar_assinatura(data: bytes, signature_b64: str, public_key: tuple) -> bool:
    n, e = public_key
    try:
        assinatura_int = bytes_para_int(base64.b64decode(signature_b64))
        hash_da_assinatura = int_para_bytes(pow(assinatura_int, e, n))
        hash_real = sha3_hash(data)
        return hash_real == hash_da_assinatura
    except Exception:
        return False

# Utilitários para arquivos

def salvar_arquivo_assinado(filepath: str, data: bytes, signature_b64: str):
    with open(filepath, 'wb') as f:
        f.write(b"-----BEGIN MESSAGE-----\n")
        f.write(base64.b64encode(data) + b"\n")
        f.write(b"-----END MESSAGE-----\n")
        f.write(b"-----BEGIN SIGNATURE-----\n")
        f.write(signature_b64.encode() + b"\n")
        f.write(b"-----END SIGNATURE-----\n")

def carregar_arquivo_assinado(filepath: str) -> tuple:
    with open(filepath, 'rb') as f:
        lines = f.read().split(b"\n")
        msg_b64 = b""
        assinatura_b64 = ""
        lendo_msg = lendo_assinatura = False
        for line in lines:
            if line == b"-----BEGIN MESSAGE-----":
                lendo_msg = True
                continue
            elif line == b"-----END MESSAGE-----":
                lendo_msg = False
            elif line == b"-----BEGIN SIGNATURE-----":
                lendo_assinatura = True
                continue
            elif line == b"-----END SIGNATURE-----":
                lendo_assinatura = False
            elif lendo_msg:
                msg_b64 += line
            elif lendo_assinatura:
                assinatura_b64 += line.decode()
        return base64.b64decode(msg_b64), assinatura_b64

# Exemplo de uso

if __name__ == "__main__":
    # Gerar chaves
    print("Gerando chaves RSA de 1024 bits (isso pode demorar alguns segundos)...")
    chaves = gerar_chaves_rsa(1024)
    pub, priv = chaves['public'], chaves['private']

    # Assinar
    with open("mensagem.txt", "rb") as f:
        msg = f.read()

    assinatura = assinar_mensagem(msg, priv)
    salvar_arquivo_assinado("mensagem_assinada.txt", msg, assinatura)

    # Verificar
    msg_verif, assinatura_verif = carregar_arquivo_assinado("mensagem_assinada.txt")
    valido = verificar_assinatura(msg_verif, assinatura_verif, pub)
    print("Assinatura válida?", valido)
