"""Tiny dependency-free QR Code generator (byte mode, versions 1–4, ECC M).

Renders the dashboard's PAC/CA/connect URLs as SVG (Connect page) and ANSI
blocks (CLI) so a phone can scan them straight off the screen. Scope is
deliberately narrow — our URLs are short, so we implement ISO/IEC 18004
just far enough for them:

* byte mode, error-correction level M, mask pattern 0 (no penalty scan)
* versions 1–4 only → a single Reed–Solomon block per version (no
  block interleaving), max payload 62 bytes
* GF(256) Reed–Solomon for the error-correction codewords

Anything longer raises ``ValueError`` instead of producing a broken code.
"""

from __future__ import annotations

# ── GF(256) arithmetic (primitive poly 0x11d) ─────────────────────────

_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _gmul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


# ── Version tables (byte mode, ECC M — all single-block) ──────────────

_DATA_CW = {1: 14, 2: 26, 3: 42, 4: 62}   # payload bytes (mode+count included)
_ECC_CW = {1: 10, 2: 16, 3: 26, 4: 38}    # RS check codewords
_ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26]}
_FORMAT_BITS_M = 0  # ECC level M indicator (L=1, M=0, Q=3, H=2)
_MASK = 0


def _rs_encode(data: bytes, ecc_len: int) -> bytes:
    """Reed–Solomon check codewords (generator poly over GF(256))."""
    # Build the generator polynomial of the requested degree, stored
    # HIGH-order coefficient first (gen[0] is the x^n term).
    gen = [1]
    for i in range(ecc_len):
        nxt = [0] * (len(gen) + 1)
        for j, c in enumerate(gen):
            nxt[j] ^= c
            nxt[j + 1] ^= _gmul(c, _EXP[i])
        gen = nxt
    rem = [0] * ecc_len
    for byte in data:
        factor = byte ^ rem[0]
        rem = rem[1:] + [0]
        for i, g in enumerate(gen[1:]):
            if g and factor:
                rem[i] ^= _gmul(g, factor)
    return bytes(rem)


def _bits_for(data: bytes, version: int) -> list[int]:
    """Message bitstream: mode, count, payload, terminator, padding."""
    bits: list[int] = [0, 1, 0, 0]  # byte-mode indicator 0100
    n = len(data)
    for i in range(7, -1, -1):  # 8-bit char count (versions 1–9)
        bits.append((n >> i) & 1)
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    cap = _DATA_CW[version] * 8
    bits += [0] * min(4, max(0, cap - len(bits)))  # terminator
    while len(bits) % 8:
        bits.append(0)
    pad = (0xEC, 0x11)
    k = 0
    while len(bits) < cap:
        bits += [(pad[k % 2] >> i) & 1 for i in range(7, -1, -1)]
        k += 1
    return bits


def _codewords(data: bytes, version: int) -> bytes:
    bits = _bits_for(data, version)
    payload = bytearray()
    for i in range(0, len(bits), 8):
        payload.append(int("".join(map(str, bits[i:i + 8])), 2))
    return bytes(payload) + _rs_encode(bytes(payload), _ECC_CW[version])


def _bch_format() -> int:
    """15-bit format value for ECC M + mask 0 (BCH(15,5) + XOR mask)."""
    d = (_FORMAT_BITS_M << 3) | _MASK
    rem = d
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    return ((d << 10) | rem) ^ 0x5412


def _qr_matrix(data: bytes) -> list[list[bool]]:
    if len(data) > _DATA_CW[4]:
        raise ValueError(
            f"URL too long for the connect QR ({len(data)} bytes, max {_DATA_CW[4]})"
        )
    version = next(v for v in (1, 2, 3, 4) if len(data) <= _DATA_CW[v])
    n = 17 + 4 * version
    codewords = _codewords(data, version)

    modules: list[list[bool | None]] = [[None] * n for _ in range(n)]

    def set_function(r: int, c: int, dark: bool) -> None:
        modules[r][c] = dark

    def draw_finder(r0: int, c0: int) -> None:
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                rr, cc = r0 + dr, c0 + dc
                if 0 <= rr < n and 0 <= cc < n:
                    dark = (
                        (0 <= dr <= 6 and dc in (0, 6))
                        or (0 <= dc <= 6 and dr in (0, 6))
                        or (2 <= dr <= 4 and 2 <= dc <= 4)
                    )
                    set_function(rr, cc, dark)

    draw_finder(0, 0)
    draw_finder(0, n - 7)
    draw_finder(n - 7, 0)

    for cy in _ALIGN[version]:
        for cx in _ALIGN[version]:
            if modules[cy][cx] is not None:
                continue  # overlaps a finder — skipped by the spec
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    set_function(cy + dr, cx + dc, max(abs(dr), abs(dc)) != 1)

    for i in range(8, n - 8):  # timing patterns
        set_function(6, i, i % 2 == 0)
        set_function(i, 6, i % 2 == 0)

    # ── reserved-format bookkeeping (needed for data placement) ──
    is_function = [[modules[r][c] is not None for c in range(n)] for r in range(n)]

    # Format info (two copies) + the dark module.
    fmt = _bch_format()

    def getbit(v: int, i: int) -> bool:
        return ((v >> i) & 1) == 1

    for i in range(6):
        set_function(8, i, getbit(fmt, i))
        is_function[8][i] = True
    set_function(8, 7, getbit(fmt, 6))
    set_function(8, 8, getbit(fmt, 7))
    set_function(7, 8, getbit(fmt, 8))
    for i in range(9, 15):
        set_function(14 - i, 8, getbit(fmt, i))
        is_function[14 - i][8] = True
    for i in range(8):
        set_function(n - 1 - i, 8, getbit(fmt, i))
        is_function[n - 1 - i][8] = True
    for i in range(8, 15):
        set_function(8, n - 15 + i, getbit(fmt, i))
        is_function[8][n - 15 + i] = True
    set_function(n - 8, 8, True)  # always-dark module
    is_function[n - 8][8] = True

    # ── data placement: zigzag from the bottom-right, upward first ──
    total_bits = len(codewords) * 8
    bit_index = 0

    def msg_bit(i: int) -> bool:
        return getbit(codewords[i >> 3], 7 - (i & 7))

    right = n - 1
    while right >= 1:
        if right == 6:
            right = 5  # skip the timing column
        upward = ((right + 1) & 2) == 0
        for vert in range(n):
            for j in (0, 1):
                x = right - j
                y = (n - 1 - vert) if upward else vert
                if not is_function[y][x]:
                    bit = msg_bit(bit_index) if bit_index < total_bits else False
                    bit_index += 1
                    if _MASK == 0 and (y + x) % 2 == 0:
                        bit = not bit
                    modules[y][x] = bit
        right -= 2

    return [[bool(v) for v in row] for row in modules]


# ── Renderers ─────────────────────────────────────────────────────────


def qr_svg(text: str, *, border: int = 4, px: int = 4) -> str:
    """Render text as a dark-on-light QR SVG (scannable on any background)."""
    m = _qr_matrix(text.encode("utf-8"))
    n = len(m)
    size = (n + 2 * border) * px
    rects = "".join(
        f'<rect x="{(c + border) * px}" y="{(r + border) * px}" width="{px}" height="{px}"/>'
        for r in range(n)
        for c in range(n)
        if m[r][c]
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" '
        f'shape-rendering="crispEdges"><rect width="{size}" height="{size}" '
        f'fill="#ffffff"/><g fill="#000000">{rects}</g></svg>'
    )


def qr_terminal(text: str) -> str:
    """Render text as ANSI inverted blocks (scannable from most terminals)."""
    m = _qr_matrix(text.encode("utf-8"))
    n = len(m)
    quiet = 2
    grid = [[False] * (n + 2 * quiet) for _ in range(n + 2 * quiet)]
    for r in range(n):
        for c in range(n):
            grid[r + quiet][c + quiet] = m[r][c]
    lines = []
    for r in range(0, len(grid) - 1, 2):
        row = []
        for c in range(len(grid[0])):
            top, bot = grid[r][c], grid[r + 1][c]
            row.append(" " if top and bot else "▄" if top else "▀" if bot else "█")
        lines.append("\x1b[7m" + "".join(row) + "\x1b[0m")
    return "\n".join(lines)
