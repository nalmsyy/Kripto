import numpy as np

# ==========================================================
# KONSTANTA
# ==========================================================
MODULO = 80

CHAR_SET_80 = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "_-`~"
    "!?'().,"
    "#$%^&*@"
)

CHAR_TO_NUM = {c: i for i, c in enumerate(CHAR_SET_80)}
NUM_TO_CHAR = {i: c for i, c in enumerate(CHAR_SET_80)}

# ==========================================================
# UTILITAS DASAR
# ==========================================================
def clean_text(text):
    return ''.join(c for c in text if c in CHAR_TO_NUM)

def char_to_num(c):
    return CHAR_TO_NUM[c]

def num_to_char(n):
    return NUM_TO_CHAR[n % MODULO]

# ==========================================================
# 1️⃣ HILL CIPHER (MODIFIKASI)
# ==========================================================
def build_key_matrix(key, size=4):
    key_nums = [char_to_num(c) for c in clean_text(key)]
    if len(key_nums) < size * size:
        raise ValueError("Key terlalu pendek")
    return np.array(key_nums[:size*size]).reshape(size, size)

def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def matrix_inverse_mod(mat, mod):
    det = int(round(np.linalg.det(mat))) % mod
    inv_det = mod_inverse(det, mod)
    if inv_det is None:
        raise ValueError("Matrix tidak invertible")

    size = len(mat)
    adj = np.zeros((size, size), dtype=int)

    for i in range(size):
        for j in range(size):
            minor = np.delete(np.delete(mat, i, 0), j, 1)
            adj[j][i] = ((-1) ** (i + j)) * int(round(np.linalg.det(minor)))

    return (inv_det * adj) % mod

def hill_encrypt(text, key_matrix):
    text = clean_text(text)
    size = len(key_matrix)

    while len(text) % size != 0:
        text += "@"

    result = ""
    for i in range(0, len(text), size):
        vector = np.array([char_to_num(c) for c in text[i:i+size]])
        encrypted = np.dot(key_matrix, vector) % MODULO
        result += ''.join(num_to_char(n) for n in encrypted)

    return result

def hill_decrypt(cipher, key_matrix):
    inv_matrix = matrix_inverse_mod(key_matrix, MODULO)
    size = len(inv_matrix)

    result = ""
    for i in range(0, len(cipher), size):
        vector = np.array([char_to_num(c) for c in cipher[i:i+size]])
        decrypted = np.dot(inv_matrix, vector) % MODULO
        result += ''.join(num_to_char(n) for n in decrypted)

    return result.rstrip("@")

# ==========================================================
# 2️⃣ MYZKOWSKI CIPHER (MODIFIKASI)
# ==========================================================
def myzkowski_order(key):
    unique = sorted(set(key))
    mapping = {c: i+1 for i, c in enumerate(unique)}
    return [mapping[c] for c in key]

def myzkowski_encrypt(text, key):
    text = text.replace(" ", "@")
    order = myzkowski_order(key)
    cols = len(key)

    while len(text) % cols != 0:
        text += "@"

    rows = len(text) // cols
    matrix = [list(text[i*cols:(i+1)*cols]) for i in range(rows)]

    result = ""
    for num in sorted(set(order)):
        for row in matrix:
            for idx, val in enumerate(order):
                if val == num:
                    result += row[idx]

    return result

def myzkowski_decrypt(cipher, key):
    order = myzkowski_order(key)
    cols = len(key)
    rows = len(cipher) // cols

    matrix = [["" for _ in range(cols)] for _ in range(rows)]
    index = 0

    for num in sorted(set(order)):
        for r in range(rows):
            for c, val in enumerate(order):
                if val == num:
                    matrix[r][c] = cipher[index]
                    index += 1

    return ''.join(''.join(row) for row in matrix).replace("@", " ")

# ==========================================================
# 3️⃣ PLAYFAIR 8x10 (MODIFIKASI)
# ==========================================================
def build_playfair_matrix(key):
    seen = []
    for c in clean_text(key):
        if c not in seen:
            seen.append(c)
    for c in CHAR_SET_80:
        if c not in seen:
            seen.append(c)

    return [seen[i*10:(i+1)*10] for i in range(8)]

def find_pos(c, matrix):
    for i in range(8):
        for j in range(10):
            if matrix[i][j] == c:
                return i, j
    return None

def playfair_encrypt(text, key):
    matrix = build_playfair_matrix(key)
    text = clean_text(text)

    if len(text) % 2 != 0:
        text += "@"

    result = ""
    i = 0
    while i < len(text):
        a, b = text[i], text[i+1]
        ra, ca = find_pos(a, matrix)
        rb, cb = find_pos(b, matrix)

        if ra == rb:
            result += matrix[ra][(ca+1)%10] + matrix[rb][(cb+1)%10]
        elif ca == cb:
            result += matrix[(ra+1)%8][ca] + matrix[(rb+1)%8][cb]
        else:
            result += matrix[ra][cb] + matrix[rb][ca]

        i += 2

    return result

def playfair_decrypt(cipher, key):
    matrix = build_playfair_matrix(key)
    result = ""
    i = 0

    while i < len(cipher):
        a, b = cipher[i], cipher[i+1]
        ra, ca = find_pos(a, matrix)
        rb, cb = find_pos(b, matrix)

        if ra == rb:
            result += matrix[ra][(ca-1)%10] + matrix[rb][(cb-1)%10]
        elif ca == cb:
            result += matrix[(ra-1)%8][ca] + matrix[(rb-1)%8][cb]
        else:
            result += matrix[ra][cb] + matrix[rb][ca]

        i += 2

    return result.rstrip("@")

# ==========================================================
# 🔐 SUPER ENKRIPSI & DEKRIPSI (API FLASK)
# ==========================================================
def encrypt_message(key, plaintext):
    key_matrix = build_key_matrix(key)
    step1 = hill_encrypt(plaintext, key_matrix)
    step2 = myzkowski_encrypt(step1, key)
    final = playfair_encrypt(step2, key)
    return final

def decrypt_message(key, ciphertext):
    step1 = playfair_decrypt(ciphertext, key)
    step2 = myzkowski_decrypt(step1, key)
    key_matrix = build_key_matrix(key)
    final = hill_decrypt(step2, key_matrix)
    return final
