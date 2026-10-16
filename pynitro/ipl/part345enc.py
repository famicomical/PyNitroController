#!/usr/bin/env python3
"""part345enc.py - compressor for the DS firmware "part345" huffman format,
the inverse of iplrepack.part345_decompress(). Pure Python, no dependencies.

Reverse-engineered from the decompressor + real firmware blobs (port of
fwunpack's part345enc.cpp). The codec is DEFLATE-like LZ77 (2 KiB window, length
3..258, no extra bits) with two fully-custom Huffman trees serialized as an
explicit preorder tree shape (NOT canonical code lengths):
  - stream0 = 256 literals + 256 length codes (9-bit leaves)
  - stream1 = 2048 distance codes (11-bit leaves)
  - tree shape: '1' = internal(left, right); '0' + symbol = leaf
  - 12-byte header: word0 = 0x80000000 | (bloblen << 2) LE; [4] = 0x80 tag +
    24-bit decompressed size BE; [8] = offset to stream1 BE; stream0 at +12.

This module is OPTIONAL for iplrepack: it is only needed to *replace* the GUI
parts (3/4/5) on `repack`; unpacking and rebuilding the ARM9/ARM7 IPL (parts
1/2) never touches it. Faithful to the C parser/tree-builder, so its output is
byte-identical to the C iplrepack.

Offered under GPL-2.0-or-later (same terms as the fwunpack sources it derives from;
text in LICENSE.GPL-2.0). The rest of the project is MIT.

Public API
  part345_compress(data) -> bytes   # the part345 blob (length is a multiple of 4)
"""

M32 = 0xFFFFFFFF

WINDOW = 2048
MIN_MATCH = 3
MAX_MATCH = 258
HASH_SIZE = 1 << 16
MAX_CHAIN = 256
MAX_CODE_LEN = 120          # decoder build-stack is data_table_0[0x100]


class _BitW:
    """MSB-first bit writer, padded to a 32-bit boundary (the decoder reads
    big-endian 32-bit words, so MSB-first byte order == word order)."""
    __slots__ = ("b", "acc", "n")

    def __init__(self):
        self.b = bytearray()
        self.acc = 0
        self.n = 0

    def bit(self, x):
        self.acc = (self.acc << 1) | (x & 1)
        self.n += 1
        if self.n == 8:
            self.b.append(self.acc & 0xFF)
            self.acc = 0
            self.n = 0

    def bits(self, v, k):
        for i in range(k - 1, -1, -1):
            self.bit((v >> i) & 1)

    def align32(self):
        while self.n:
            self.bit(0)
        while len(self.b) & 3:
            self.b.append(0)


def _lz_parse(data, n):
    """Greedy hash-chain LZ77 parse. Returns a list of (length, lit, dist);
    length == 0 means a literal `lit`, else a (length, dist) match."""
    head = [-1] * HASH_SIZE
    prev = [-1] * (n if n > 0 else 1)
    mask = HASH_SIZE - 1
    win, minm, maxm, chainmax = WINDOW, MIN_MATCH, MAX_MATCH, MAX_CHAIN
    out = []
    pos = 0
    while pos < n:
        maxlen = n - pos
        if maxlen > maxm:
            maxlen = maxm
        best_len, best_dist = 0, 0
        if maxlen >= minm:
            h = ((data[pos] << 8) ^ (data[pos + 1] << 4) ^ data[pos + 2]) & mask
            cand = head[h]
            floor_pos = pos - win
            chain = chainmax
            while cand >= 0 and cand >= floor_pos and chain > 0:
                chain -= 1
                if best_len < maxlen and data[cand + best_len] == data[pos + best_len]:
                    l = 0
                    while l < maxlen and data[cand + l] == data[pos + l]:
                        l += 1
                    if l > best_len:
                        best_len, best_dist = l, pos - cand
                        if l == maxlen:
                            break
                cand = prev[cand]
        if best_len >= minm:
            out.append((best_len, 0, best_dist))
            end = pos + best_len
            while pos < end:                            # insert every covered pos
                if pos + 2 < n:
                    h = ((data[pos] << 8) ^ (data[pos + 1] << 4) ^ data[pos + 2]) & mask
                    prev[pos] = head[h]
                    head[h] = pos
                pos += 1
        else:
            out.append((0, data[pos], 0))
            if pos + 2 < n:
                h = ((data[pos] << 8) ^ (data[pos + 1] << 4) ^ data[pos + 2]) & mask
                prev[pos] = head[h]
                head[h] = pos
            pos += 1
    return out


def _build_huffman(freq, A, symbits):
    """Build a Huffman tree (balanced fallback if it would exceed the decoder's
    depth limit) over the symbols of `freq` (size A). Returns (code, clen,
    nsym, nl, nr, root): per-symbol code bits + length, and the node arrays."""
    nsym, nl, nr = [], [], []

    def leaf(s):
        nsym.append(s); nl.append(-1); nr.append(-1); return len(nsym) - 1

    def inner(a, b):
        nsym.append(-1); nl.append(a); nr.append(b); return len(nsym) - 1

    present = [s for s in range(A) if freq[s]]
    # Guarantee >= 2 leaves (the format/decoder require an internal root).
    s = 0
    while s < A and len(present) < 2:
        if (not freq[s]) or len(present) == 0:
            if s not in present:
                present.append(s)
        s += 1

    idx, w = [], []
    for s in present:
        idx.append(leaf(s)); w.append(freq[s] if freq[s] else 1)

    dead = [False] * len(idx)
    alive = len(idx)
    while alive > 1:                                    # O(n^2) selection merge
        m1, m2 = -1, -1
        for i in range(len(idx)):
            if dead[i]:
                continue
            if m1 < 0 or w[i] < w[m1]:
                m2 = m1; m1 = i
            elif m2 < 0 or w[i] < w[m2]:
                m2 = i
        parent = inner(idx[m1], idx[m2])
        dead[m1] = True
        idx[m2] = parent; w[m2] = w[m1] + w[m2]         # reuse slot m2
        alive -= 1
    root = idx[next(i for i in range(len(idx)) if not dead[i])]

    # Depth check (iterative; node children always precede their parent).
    d = [0] * len(nsym)
    for i in range(len(nsym)):
        d[i] = 0 if nsym[i] >= 0 else 1 + max(d[nl[i]], d[nr[i]])
    if d[root] > MAX_CODE_LEN:                          # balanced fallback
        syms = sorted(present, key=lambda a: -freq[a])
        nsym.clear(); nl.clear(); nr.clear()

        def build_balanced(lo, hi):
            if hi - lo == 1:
                return leaf(syms[lo])
            mid = (lo + hi) // 2
            return inner(build_balanced(lo, mid), build_balanced(mid, hi))
        root = build_balanced(0, len(syms))

    # Assign codes (iterative pre-order; tree depth <= 120 here, well within
    # Python's recursion limit, but iterate anyway to stay uniform).
    code = [0] * A
    clen = [0] * A
    stack = [(root, 0, 0)]
    while stack:
        i, bits, length = stack.pop()
        if nsym[i] >= 0:
            code[nsym[i]] = bits
            clen[nsym[i]] = 1 if length < 1 else length
        else:
            stack.append((nl[i], bits << 1, length + 1))
            stack.append((nr[i], (bits << 1) | 1, length + 1))
    return code, clen, nsym, nl, nr, root


def _serialize_tree(w, nsym, nl, nr, root, symbits):
    """Write the preorder tree shape into `w`: '1' internal(left,right);
    '0' + symbits-wide symbol for a leaf."""
    stack = [root]
    while stack:
        i = stack.pop()
        if nsym[i] >= 0:
            w.bit(0); w.bits(nsym[i], symbits)
        else:
            w.bit(1)
            stack.append(nr[i])         # push right first -> left serialized first
            stack.append(nl[i])


def part345_compress(data):
    """Compress `data` into a DS firmware part345 huffman blob (the inverse of
    iplrepack.part345_decompress). Returns the blob bytes (length is a multiple
    of 4)."""
    n = len(data)
    if n <= 0:
        return b""
    toks = _lz_parse(data, n)

    f0 = [0] * 512                                      # literals + length codes
    f1 = [0] * 2048                                     # distance codes
    for length, lit, dist in toks:
        if length == 0:
            f0[lit] += 1
        else:
            f0[256 + (length - MIN_MATCH)] += 1
            f1[dist - 1] += 1

    c0, l0, n0s, n0l, n0r, r0 = _build_huffman(f0, 512, 9)
    c1, l1, n1s, n1l, n1r, r1 = _build_huffman(f1, 2048, 11)

    s0 = _BitW()
    _serialize_tree(s0, n0s, n0l, n0r, r0, 9)
    for length, lit, dist in toks:
        sym = lit if length == 0 else (256 + (length - MIN_MATCH))
        s0.bits(c0[sym], l0[sym])
    s0.align32()

    s1 = _BitW()
    _serialize_tree(s1, n1s, n1l, n1r, r1, 11)
    for length, lit, dist in toks:
        if length == 0:
            continue
        sym = dist - 1
        s1.bits(c1[sym], l1[sym])
    s1.align32()

    offset = 12 + len(s0.b)
    bloblen = offset + len(s1.b)
    out = bytearray(bloblen)
    w0 = (0x80000000 | (bloblen << 2)) & M32            # word0, little-endian
    out[0:4] = bytes((w0 & 0xFF, (w0 >> 8) & 0xFF, (w0 >> 16) & 0xFF, (w0 >> 24) & 0xFF))
    out[4:8] = bytes((0x80, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF))   # 0x80 tag + declen BE
    out[8:12] = bytes(((offset >> 24) & 0xFF, (offset >> 16) & 0xFF,
                       (offset >> 8) & 0xFF, offset & 0xFF))                # stream1 offset BE
    out[12:12 + len(s0.b)] = s0.b
    out[offset:offset + len(s1.b)] = s1.b
    return bytes(out)
