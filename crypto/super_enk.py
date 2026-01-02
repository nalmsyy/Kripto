import numpy as np

# ==========================================================
# KONSTANTA & SETUP
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
# 1. HILL CIPHER
# ==========================================================
def char_ke_angka(c): return CHAR_TO_NUM.get(c, 0)
def angka_ke_char(i): return NUM_TO_CHAR[i % MODULO]
def bersihkan_text(t): return ''.join([c for c in t if c in CHAR_TO_NUM])

def buat_matriks_key(key, m):
    k = [char_ke_angka(c) for c in key if c in CHAR_TO_NUM]
    # Padding jika key kurang panjang
    while len(k) < m * m:
        k.append(0)
    return np.array(k[:m*m]).reshape(m, m)

def mod_inv(a, m):
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def invers_matriks_mod(mat, mod):
    det = int(round(np.linalg.det(mat))) % mod
    inv_det = mod_inv(det, mod)
    if inv_det is None:
        return None
    m = len(mat)
    adj = np.zeros((m, m), dtype=int)
    for i in range(m):
        for j in range(m):
            minor = np.delete(np.delete(mat, i, 0), j, 1)
            cofactor = ((-1)**(i+j)) * int(round(np.linalg.det(minor)))
            adj[j, i] = cofactor
    return (inv_det * adj) % mod

def enkripsi_hill(plain, key_matrix):
    m = len(key_matrix)
    text = bersihkan_text(plain)
    while len(text) % m != 0:
        text += "@"
    hasil = ""
    for i in range(0, len(text), m):
        v = np.array([char_ke_angka(c) for c in text[i:i+m]])
        r = np.dot(key_matrix, v) % MODULO
        hasil += ''.join([angka_ke_char(x) for x in r])
    return hasil

def dekripsi_hill(cipher, key_matrix):
    inv = invers_matriks_mod(key_matrix, MODULO)
    if inv is None:
        # Fallback jika matriks tidak punya invers: kembalikan cipher apa adanya (tanda error)
        return cipher 
    m = len(inv)
    hasil = ""
    for i in range(0, len(cipher), m):
        v = np.array([char_ke_angka(c) for c in cipher[i:i+m]])
        r = np.dot(inv, v) % MODULO
        hasil += ''.join([angka_ke_char(x) for x in r])
    return hasil.rstrip("@")

# ==========================================================
# 2. MYZKOWSKI CIPHER
# ==========================================================
def myzkowski_order(key):
    def prioritas(ch):
        if ch.isalpha(): return (1, ch)
        elif ch.isdigit(): return (2, ch)
        else: return (3, ch)
    klist = list(key)
    unik = sorted(set(klist), key=prioritas)
    peta = {ch: i+1 for i, ch in enumerate(unik)}
    return [peta[ch] for ch in klist]

def enkripsi_myzowski(text, key):
    text = text.replace(" ", "@")
    urut = myzkowski_order(key)
    kolom = len(key)
    while len(text) % kolom != 0:
        text += "@"
    baris = len(text)//kolom
    matriks = [list(text[i*kolom:(i+1)*kolom]) for i in range(baris)]
    hasil = ""
    for num in sorted(set(urut)):
        for row in matriks:
            for idx, n in enumerate(urut):
                if n == num:
                    hasil += row[idx]
    return hasil

def dekripsi_myzowski(cipher, key):
    urut = myzkowski_order(key)
    kolom = len(key)
    baris = len(cipher)//kolom
    matriks = [["" for _ in range(kolom)] for _ in range(baris)]
    pos = 0
    for num in sorted(set(urut)):
        for r in range(baris):
            for idx, n in enumerate(urut):
                if n == num:
                    matriks[r][idx] = cipher[pos]
                    pos += 1
    plain = "".join("".join(r) for r in matriks)
    return plain.replace("@", " ")

# ==========================================================
# 3. PLAYFAIR CIPHER (8x10)
# ==========================================================
def buat_matrix_playfair(key):
    result = []
    for c in key:
        if c not in result and c in CHAR_TO_NUM:
            result.append(c)
    for c in CHAR_SET_80:
        if c not in result:
            result.append(c)
    mat = [result[i*10:(i+1)*10] for i in range(8)]
    return mat

def posisi(c, mat):
    for i in range(8):
        for j in range(10):
            if mat[i][j] == c:
                return (i, j)
    return None

def enkripsi_playfair(text, key):
    mat = buat_matrix_playfair(key)
    teks = ''.join([c for c in text if c in CHAR_TO_NUM])
    if len(teks) % 2 != 0:
        teks += "@"
    hasil = ""
    i = 0
    while i < len(teks):
        a, b = teks[i], teks[i+1]
        pa, pb = posisi(a, mat), posisi(b, mat)
        if pa is None or pb is None:
            hasil += a + b
        elif pa[0] == pb[0]:
            hasil += mat[pa[0]][(pa[1]+1)%10] + mat[pb[0]][(pb[1]+1)%10]
        elif pa[1] == pb[1]:
            hasil += mat[(pa[0]+1)%8][pa[1]] + mat[(pb[0]+1)%8][pb[1]]
        else:
            hasil += mat[pa[0]][pb[1]] + mat[pb[0]][pa[1]]
        i += 2
    return hasil

def dekripsi_playfair(cipher, key):
    mat = buat_matrix_playfair(key)
    teks = ''.join([c for c in cipher if c in CHAR_TO_NUM])
    hasil = ""
    i = 0
    while i < len(teks):
        a, b = teks[i], teks[i+1]
        pa, pb = posisi(a, mat), posisi(b, mat)
        if pa is None or pb is None:
            hasil += a + b
        elif pa[0] == pb[0]:
            hasil += mat[pa[0]][(pa[1]-1)%10] + mat[pb[0]][(pb[1]-1)%10]
        elif pa[1] == pb[1]:
            hasil += mat[(pa[0]-1)%8][pa[1]] + mat[(pb[0]-1)%8][pb[1]]
        else:
            hasil += mat[pa[0]][pb[1]] + mat[pb[0]][pa[1]]
        i += 2
    return hasil 

# ==========================================================
# API UTAMA (Digunakan oleh app.py)
# ==========================================================
def encrypt_message(key, plaintext):
    """Urutan: Hill -> Myzkowski -> Playfair"""
    # 1. Hill
    key_mat = buat_matriks_key(key, 4)
    step1 = enkripsi_hill(plaintext, key_mat)
    # 2. Myzkowski
    step2 = enkripsi_myzowski(step1, key)
    # 3. Playfair
    final = enkripsi_playfair(step2, key)
    return final

def decrypt_message(key, ciphertext):
    """Urutan Balik: Playfair -> Myzkowski -> Hill"""
    # 1. Playfair
    step1 = dekripsi_playfair(ciphertext, key)
    # 2. Myzkowski
    step2 = dekripsi_myzowski(step1, key)
    # 3. Hill
    key_mat = buat_matriks_key(key, 4)
    final = dekripsi_hill(bersihkan_text(step2), key_mat)
    return final