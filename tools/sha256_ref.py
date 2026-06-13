# Reference implementation of SHA-256 / SHA-224 / HMAC-SHA256, written
# to mirror EXACTLY the decomposition the Capa port uses: an explicit
# u32 mask after every add/shift, rotr32 built from shifts + mask, a
# 64-entry message schedule, and the round-by-round compression. This
# file is the debug anchor: any Capa case that diverges is re-run here
# and the intermediates (W[], a..h per round) are compared.
#
# Validated against Python's hashlib / hmac and the official NIST
# FIPS 180-4 + RFC 4231 vectors at the bottom. Not shipped: lives in
# tools/, outside what `capa install` consumers see.

MASK = 0xFFFFFFFF

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

IV256 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

IV224 = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
]


def rotr32(x, n):
    # x is already masked to <=32 bits. (x << (32-n)) can grow past 32
    # bits, so mask the whole thing back to u32.
    return ((x >> n) | (x << (32 - n))) & MASK


def shr32(x, n):
    # x is masked to <=32 bits, so a plain shift right is logical.
    return x >> n


def pad(msg):
    # msg: list of ints 0..255. Append 0x80, then zeros, then the
    # 64-bit big-endian bit length, to a multiple of 64 bytes.
    ml = len(msg) * 8
    out = list(msg)
    out.append(0x80)
    while len(out) % 64 != 56:
        out.append(0x00)
    for i in range(8):
        shift = (7 - i) * 8
        out.append((ml >> shift) & 0xFF)
    return out


def compress(state, block):
    # block: 64 bytes. Build the 64-word schedule, then run 64 rounds.
    w = []
    for t in range(16):
        b0 = block[t * 4 + 0]
        b1 = block[t * 4 + 1]
        b2 = block[t * 4 + 2]
        b3 = block[t * 4 + 3]
        word = ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) & MASK
        w.append(word)
    for t in range(16, 64):
        s0 = rotr32(w[t - 15], 7) ^ rotr32(w[t - 15], 18) ^ shr32(w[t - 15], 3)
        s1 = rotr32(w[t - 2], 17) ^ rotr32(w[t - 2], 19) ^ shr32(w[t - 2], 10)
        nw = (w[t - 16] + s0 + w[t - 7] + s1) & MASK
        w.append(nw)

    a, b, c, d, e, f, g, h = state

    for t in range(64):
        S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
        ch = (e & f) ^ ((e ^ MASK) & g)
        temp1 = (h + S1 + ch + K[t] + w[t]) & MASK
        S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & MASK
        h = g
        g = f
        f = e
        e = (d + temp1) & MASK
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & MASK

    return [
        (state[0] + a) & MASK,
        (state[1] + b) & MASK,
        (state[2] + c) & MASK,
        (state[3] + d) & MASK,
        (state[4] + e) & MASK,
        (state[5] + f) & MASK,
        (state[6] + g) & MASK,
        (state[7] + h) & MASK,
    ]


def digest_words(msg, iv):
    state = list(iv)
    data = pad(msg)
    nblocks = len(data) // 64
    for i in range(nblocks):
        block = data[i * 64:(i + 1) * 64]
        state = compress(state, block)
    return state


def sha256_bytes(msg):
    words = digest_words(msg, IV256)
    out = []
    for word in words:
        out.append((word >> 24) & 0xFF)
        out.append((word >> 16) & 0xFF)
        out.append((word >> 8) & 0xFF)
        out.append(word & 0xFF)
    return out


def sha224_bytes(msg):
    words = digest_words(msg, IV224)
    out = []
    for word in words[:7]:  # truncate: drop the 8th word
        out.append((word >> 24) & 0xFF)
        out.append((word >> 16) & 0xFF)
        out.append((word >> 8) & 0xFF)
        out.append(word & 0xFF)
    return out


HEX = "0123456789abcdef"


def to_hex(byts):
    s = ""
    for b in byts:
        s += HEX[(b >> 4) & 0xF]
        s += HEX[b & 0xF]
    return s


def sha256_hex(msg):
    return to_hex(sha256_bytes(msg))


def sha224_hex(msg):
    return to_hex(sha224_bytes(msg))


def hmac_sha256_bytes(key, msg):
    # RFC 2104. Block size 64. Key longer than the block is hashed
    # first; shorter is zero-padded to 64.
    block = 64
    if len(key) > block:
        key = sha256_bytes(key)
    k = list(key) + [0x00] * (block - len(key))
    ipad = [k[i] ^ 0x36 for i in range(block)]
    opad = [k[i] ^ 0x5c for i in range(block)]
    inner = sha256_bytes(ipad + list(msg))
    return sha256_bytes(opad + inner)


def hmac_sha256_hex(key, msg):
    return to_hex(hmac_sha256_bytes(key, msg))


# ------------------------------------------------------------------
# Validation. Run `python tools/sha256_ref.py`.
if __name__ == "__main__":
    import hashlib
    import hmac as _hmac

    def b(s):
        return list(s.encode("utf-8"))

    fails = 0

    def check(name, got, want):
        global fails
        if got != want:
            fails += 1
            print(f"FAIL {name}:\n  got  {got}\n  want {want}")
        else:
            print(f"ok   {name}")

    # NIST FIPS 180-4 SHA-256 vectors
    check("sha256 empty", sha256_hex(b("")),
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    check("sha256 abc", sha256_hex(b("abc")),
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    # 448-bit message (two-block boundary case, 56 bytes)
    m448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    check("sha256 448bit", sha256_hex(b(m448)),
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    # 896-bit message (two blocks)
    m896 = ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
            "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
    check("sha256 896bit", sha256_hex(b(m896)),
          "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1")
    # 1,000,000 'a'
    check("sha256 million-a", sha256_hex([ord("a")] * 1000000),
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")

    # NIST SHA-224 vectors
    check("sha224 empty", sha224_hex(b("")),
          "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")
    check("sha224 abc", sha224_hex(b("abc")),
          "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")
    check("sha224 448bit", sha224_hex(b(m448)),
          "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525")
    check("sha224 896bit", sha224_hex(b(m896)),
          "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3")

    # Cross-check against hashlib over random-ish inputs
    import os
    for n in [0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 1000, 4096]:
        data = list(os.urandom(n))
        check(f"hashlib sha256 n={n}", sha256_hex(data),
              hashlib.sha256(bytes(data)).hexdigest())
        check(f"hashlib sha224 n={n}", sha224_hex(data),
              hashlib.sha224(bytes(data)).hexdigest())

    # RFC 4231 HMAC-SHA256 vectors
    # Case 1
    check("hmac rfc4231 case1",
          hmac_sha256_hex([0x0b] * 20, b("Hi There")),
          "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    # Case 2: key "Jefe", data "what do ya want for nothing?"
    check("hmac rfc4231 case2",
          hmac_sha256_hex(b("Jefe"), b("what do ya want for nothing?")),
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    # Case 4: key 0x01..0x19, data 0xcd x 50
    key4 = list(range(0x01, 0x1a))
    check("hmac rfc4231 case4",
          hmac_sha256_hex(key4, [0xcd] * 50),
          "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")
    # Case 6: key 0xaa x 131 (> block), data is a label
    check("hmac rfc4231 case6",
          hmac_sha256_hex([0xaa] * 131,
                          b("Test Using Larger Than Block-Size Key - Hash Key First")),
          "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
    # Case 7: key 0xaa x 131, longer data
    check("hmac rfc4231 case7",
          hmac_sha256_hex([0xaa] * 131,
                          b("This is a test using a larger than block-size key and a "
                            "larger than block-size data. The key needs to be hashed "
                            "before being used by the HMAC algorithm.")),
          "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2")

    # Cross-check HMAC against Python's hmac
    for kn, mn in [(0, 0), (16, 32), (64, 100), (100, 5), (200, 4096)]:
        kk = list(os.urandom(kn))
        mm = list(os.urandom(mn))
        check(f"hmac hashlib k={kn} m={mn}",
              hmac_sha256_hex(kk, mm),
              _hmac.new(bytes(kk), bytes(mm), hashlib.sha256).hexdigest())

    print()
    if fails:
        print(f"{fails} FAILURES")
        raise SystemExit(1)
    print("all reference checks passed")
