"""
AES-128 (khóa 128 bit = 16 byte, 10 vòng) theo mô hình SPN - code tay 100%, KHÔNG import thư viện nào.
State là ma trận 4x4: state[hàng][cột], nạp theo từng cột.
"""

NR = 10  # số vòng


# ---------- 1. State: 16 byte <-> ma trận 4x4 (theo cột) ----------
def bytes_to_state(block):
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def state_to_bytes(state):
    return bytes(state[r][c] for c in range(4) for r in range(4))


# ---------- 2. Đại số GF(2^8), m(x) = x^8 + x^4 + x^3 + x + 1 ----------
def xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = xtime(a)
        b >>= 1
    return r


def make_sbox():
    sbox = []
    for x in range(256):
        inv = next((y for y in range(1, 256) if gmul(x, y) == 1), 0) if x else 0
        s = inv
        for i in range(1, 5):
            s ^= ((inv << i) | (inv >> (8 - i))) & 0xFF
        sbox.append(s ^ 0x63)
    return sbox


SBOX = make_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i


# ---------- 3. Bốn phép biến đổi ----------
def sub_bytes(s):
    return [[SBOX[b] for b in row] for row in s]


def inv_sub_bytes(s):
    return [[INV_SBOX[b] for b in row] for row in s]


def shift_rows(s):
    return [row[r:] + row[:r] for r, row in enumerate(s)]


def inv_shift_rows(s):
    return [row[4 - r:] + row[:4 - r] for r, row in enumerate(s)]


MIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
INV_MIX = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]


def _mix(s, m):
    out = [[0] * 4 for _ in range(4)]
    for c in range(4):
        for r in range(4):
            v = 0
            for k in range(4):
                v ^= gmul(m[r][k], s[k][c])
            out[r][c] = v
    return out


def mix_columns(s):
    return _mix(s, MIX)


def inv_mix_columns(s):
    return _mix(s, INV_MIX)


def add_round_key(s, rk):
    return [[s[r][c] ^ rk[r][c] for c in range(4)] for r in range(4)]


# ---------- 4. Expand Key: 4 word -> 44 word -> 11 khóa con ----------
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def expand_key(key):
    if len(key) != 16:
        raise ValueError("AES-128 cần khóa đúng 16 byte")
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        t = w[i - 1][:]
        if i % 4 == 0:
            t = t[1:] + t[:1]                      # RotWord
            t = [SBOX[b] for b in t]               # SubWord
            t[0] ^= RCON[i // 4 - 1]               # Rcon
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [[[w[4 * n + c][r] for c in range(4)] for r in range(4)]
            for n in range(NR + 1)]                # 11 khóa con dạng ma trận 4x4


# ---------- Mã hóa / giải mã một khối 16 byte ----------
def encrypt_block(block, round_keys):
    s = add_round_key(bytes_to_state(block), round_keys[0])
    for rnd in range(1, NR):                       # vòng 1..9
        s = add_round_key(mix_columns(shift_rows(sub_bytes(s))), round_keys[rnd])
    s = add_round_key(shift_rows(sub_bytes(s)), round_keys[NR])   # vòng 10: không MixColumns
    return state_to_bytes(s)


def decrypt_block(block, round_keys):
    s = add_round_key(bytes_to_state(block), round_keys[NR])
    for rnd in range(NR - 1, 0, -1):
        s = inv_mix_columns(add_round_key(inv_sub_bytes(inv_shift_rows(s)), round_keys[rnd]))
    s = add_round_key(inv_sub_bytes(inv_shift_rows(s)), round_keys[0])
    return state_to_bytes(s)


# ---------- Văn bản dài: CBC + PKCS7 ----------
def pad(d):
    n = 16 - len(d) % 16
    return d + bytes([n]) * n


def unpad(d):
    n = d[-1]
    if not 1 <= n <= 16 or d[-n:] != bytes([n]) * n:
        raise ValueError("Padding sai (sai khóa hoặc dữ liệu hỏng)")
    return d[:-n]


def encrypt_cbc(plaintext, key, iv=None):
    rk, iv = expand_key(key), iv or rand_bytes(16)
    data, prev, out = pad(plaintext), iv, b""
    for i in range(0, len(data), 16):
        prev = encrypt_block(bytes(a ^ b for a, b in zip(data[i:i + 16], prev)), rk)
        out += prev
    return iv + out


def decrypt_cbc(ct, key):
    rk = expand_key(key)
    iv, data = ct[:16], ct[16:]
    prev, out = iv, b""
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(decrypt_block(blk, rk), prev))
        prev = blk
    return unpad(out)


# ---------- Công cụ tự viết thay cho thư viện ----------
MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF


# --- SHA-256 tự viết (dùng để biến khóa bất kỳ thành 16 byte) ---
def _iroot(n, k):
    """Căn bậc k nguyên của n bằng tìm kiếm nhị phân."""
    lo, hi = 0, 1 << (n.bit_length() // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo


def _primes(n):
    ps, x = [], 2
    while len(ps) < n:
        if all(x % p for p in ps):
            ps.append(x)
        x += 1
    return ps


_P = _primes(64)
# H0: 32 bit đầu phần thập phân căn bậc 2 của 8 số nguyên tố đầu; K: căn bậc 3 của 64 số nguyên tố đầu
_H0 = [_iroot(p << 64, 2) & MASK32 for p in _P[:8]]
_K = [_iroot(p << 96, 3) & MASK32 for p in _P]


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK32


def sha256(msg):
    h = _H0[:]
    ml = len(msg) * 8
    msg = msg + b"\x80"
    msg += b"\x00" * ((56 - len(msg) % 64) % 64)
    msg += bytes((ml >> (8 * i)) & 0xFF for i in range(7, -1, -1))
    for off in range(0, len(msg), 64):
        w = [int.from_bytes(msg[off + 4 * i:off + 4 * i + 4], "big") for i in range(16)]
        for i in range(16, 64):
            s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK32)
        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = (e & f) ^ (~e & MASK32 & g)
            t1 = (hh + S1 + ch + _K[i] + w[i]) & MASK32
            S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + maj) & MASK32
            hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & MASK32, c, b, a, (t1 + t2) & MASK32
        h = [(x + y) & MASK32 for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
    return b"".join(x.to_bytes(4, "big") for x in h)


# --- Bộ sinh số giả ngẫu nhiên xorshift64* để tạo IV (không dùng os/random) ---
# Hạt giống lấy từ địa chỉ bộ nhớ của đối tượng mới (thay đổi mỗi lần chạy).
_rng = [((id(object()) << 20) ^ id([]) ^ 0x9E3779B97F4A7C15) & MASK64 or 1]


def rand_bytes(n):
    out = b""
    while len(out) < n:
        x = _rng[0]
        x ^= x >> 12
        x ^= (x << 25) & MASK64
        x ^= x >> 27
        _rng[0] = x
        out += (((x * 0x2545F4914F6CDD1D) & MASK64) >> 32).to_bytes(4, "big")
    return out[:n]


# --- Hex tự viết ---
HEXCH = "0123456789abcdef"


def to_hex(b):
    return "".join(HEXCH[x >> 4] + HEXCH[x & 15] for x in b)


def from_hex(s):
    s = "".join(s.split()).lower()
    if len(s) % 2 or any(ch not in HEXCH for ch in s):
        return None
    return bytes(HEXCH.index(s[i]) * 16 + HEXCH.index(s[i + 1]) for i in range(0, len(s), 2))


# ---------- Giao diện hai chiều: chuỗi <-> mã ----------
def make_key(text):
    """Khóa đúng 16 byte thì dùng thẳng; ngược lại SHA-256 rồi lấy 16 byte đầu."""
    k = text.encode("utf-8")
    return k if len(k) == 16 else sha256(k)[:16]


def parse_cipher(text):
    """Đọc text như bản mã hex (IV 16 byte + >= 1 khối). Không phải thì trả None."""
    raw = from_hex(text)
    return raw if raw and len(raw) >= 32 and len(raw) % 16 == 0 else None


def convert(text, key, mode="auto"):
    """
    mode = 'enc' : ép mã hóa  -> trả về hex
    mode = 'dec' : ép giải mã -> trả về chuỗi gốc
    mode = 'auto': giống bản mã & giải mã được -> giải mã, còn lại -> mã hóa.
    """
    if mode == "enc":
        return "ENC", to_hex(encrypt_cbc(text.encode("utf-8"), key))
    raw = parse_cipher(text)
    if mode == "dec":
        if raw is None:
            raise ValueError("Đầu vào không phải bản mã hex hợp lệ (bội số 16 byte, >= 32 byte)")
        return "DEC", decrypt_cbc(raw, key).decode("utf-8")
    if raw is not None:
        try:
            return "DEC", decrypt_cbc(raw, key).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            pass
    return "ENC", to_hex(encrypt_cbc(text.encode("utf-8"), key))


def self_test():
    key = from_hex("000102030405060708090a0b0c0d0e0f")
    plain = from_hex("00112233445566778899aabbccddeeff")
    rk = expand_key(key)
    ct = encrypt_block(plain, rk)
    print("AES đúng FIPS-197:", to_hex(ct) == "69c4e0d86a7b0430d8cdb78070b4c55a")
    print("Giải mã đúng     :", decrypt_block(ct, rk) == plain)
    print("SHA-256('abc') đúng:", to_hex(sha256(b"abc")) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


if __name__ == "__main__":
    print("AES-128 CBC: nhập chuỗi -> ra bản mã (hex); nhập bản mã -> ra chuỗi gốc.")
    print("Ép chế độ bằng tiền tố enc: hoặc dec:  |  gõ 'test' để kiểm thử, 'exit' để thoát\n")
    key = make_key(input("Khóa: "))
    while True:
        line = input("\nNhập: ").strip()
        if line.lower() == "exit":
            break
        if line.lower() == "test":
            self_test()
            continue
        mode = "auto"
        if line.lower().startswith("enc:"):
            mode, line = "enc", line[4:].strip()
        elif line.lower().startswith("dec:"):
            mode, line = "dec", line[4:].strip()
        try:
            kind, result = convert(line, key, mode)
            print(("Bản mã (hex): " if kind == "ENC" else "Giải mã     : ") + result)
        except ValueError as e:
            print("Lỗi:", e)
