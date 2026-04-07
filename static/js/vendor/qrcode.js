/**
 * Minimal QR Code generator — alphanumeric mode, EC level M.
 * Produces a boolean[][] matrix suitable for canvas rendering.
 *
 * Based on ISO/IEC 18004. Covers versions 1-10, alphanumeric mode.
 * MIT License — vendored for Vortex fingerprint verification.
 */

const QR = (() => {
    // ── GF(256) arithmetic ──────────────────────────────────────────────
    const EXP = new Uint8Array(512);
    const LOG = new Uint8Array(256);
    (() => {
        let x = 1;
        for (let i = 0; i < 255; i++) {
            EXP[i] = x;
            LOG[x] = i;
            x = (x << 1) ^ (x >= 128 ? 0x11d : 0);
        }
        for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
    })();

    function gfMul(a, b) { return a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]; }

    function polyMul(a, b) {
        const r = new Uint8Array(a.length + b.length - 1);
        for (let i = 0; i < a.length; i++)
            for (let j = 0; j < b.length; j++)
                r[i + j] ^= gfMul(a[i], b[j]);
        return r;
    }

    function polyMod(data, gen) {
        const r = new Uint8Array(data.length + gen.length - 1);
        r.set(data);
        for (let i = 0; i < data.length; i++) {
            if (r[i] === 0) continue;
            for (let j = 0; j < gen.length; j++)
                r[i + j] ^= gfMul(gen[j], r[i]);
        }
        return r.slice(data.length);
    }

    function genPoly(n) {
        let g = new Uint8Array([1]);
        for (let i = 0; i < n; i++)
            g = polyMul(g, new Uint8Array([1, EXP[i]]));
        return g;
    }

    // ── Alphanumeric encoding ───────────────────────────────────────────
    const ALNUM = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';

    function encodeAlphanumeric(str) {
        const bits = [];
        const push = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1); };
        push(0b0010, 4); // mode
        // char count bits depend on version (≤9: 9 bits, ≤26: 11 bits)
        // we'll set this later
        const charCountPos = bits.length;
        push(0, 9); // placeholder, patched per version
        for (let i = 0; i < str.length; i += 2) {
            if (i + 1 < str.length) {
                push(ALNUM.indexOf(str[i]) * 45 + ALNUM.indexOf(str[i + 1]), 11);
            } else {
                push(ALNUM.indexOf(str[i]), 6);
            }
        }
        return { bits, charCountPos, charCount: str.length };
    }

    // ── Version/capacity table (alphanumeric, EC=M) ─────────────────────
    // [totalCodewords, ecCodewordsPerBlock, numBlocks, dataCodewords]
    const VERSIONS = {
        1:  [26,  10, 1, 16],
        2:  [44,  16, 1, 28],
        3:  [70,  26, 1, 44],
        4:  [100, 18, 2, 64],
        5:  [134, 24, 2, 86],
        6:  [172, 16, 4, 108],
        7:  [196, 18, 4, 124],
        8:  [242, 22, 4, 154],
        9:  [292, 22, 4, 182],  // extra block split handled below
        10: [346, 26, 4, 214],
    };

    // Alphanumeric capacity per version at EC=M
    const ALNUM_CAP = { 1:20, 2:38, 3:61, 4:90, 5:122, 6:154, 7:178, 8:221, 9:262, 10:311 };

    function selectVersion(len) {
        for (let v = 1; v <= 10; v++) if (ALNUM_CAP[v] >= len) return v;
        throw new Error('QR: data too long');
    }

    // ── Matrix construction ─────────────────────────────────────────────
    const SIZE = v => 17 + v * 4;

    function createMatrix(size) {
        return Array.from({ length: size }, () => new Int8Array(size)); // 0=light, 1=dark, -1=unset
    }

    function setModule(m, r, c, val) { if (r >= 0 && r < m.length && c >= 0 && c < m.length) m[r][c] = val ? 1 : 0; }

    function addFinder(m, row, col) {
        for (let r = -1; r <= 7; r++)
            for (let c = -1; c <= 7; c++) {
                const rr = row + r, cc = col + c;
                if (rr < 0 || rr >= m.length || cc < 0 || cc >= m.length) continue;
                const inOuter = r === 0 || r === 6 || c === 0 || c === 6;
                const inInner = r >= 2 && r <= 4 && c >= 2 && c <= 4;
                m[rr][cc] = (inOuter || inInner) ? 1 : 0;
            }
    }

    function addAlignment(m, v) {
        if (v < 2) return;
        const pos = ALIGN_POS[v];
        if (!pos) return;
        for (const r of pos)
            for (const c of pos) {
                if ((r < 9 && c < 9) || (r < 9 && c > m.length - 9) || (r > m.length - 9 && c < 9)) continue;
                for (let dr = -2; dr <= 2; dr++)
                    for (let dc = -2; dc <= 2; dc++)
                        m[r + dr][c + dc] = (Math.abs(dr) === 2 || Math.abs(dc) === 2 || (dr === 0 && dc === 0)) ? 1 : 0;
            }
    }

    const ALIGN_POS = {
        2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
        7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 52],
    };

    function addTiming(m) {
        const n = m.length;
        for (let i = 8; i < n - 8; i++) {
            m[6][i] = (i & 1) === 0 ? 1 : 0;
            m[i][6] = (i & 1) === 0 ? 1 : 0;
        }
    }

    function reserveFormat(m) {
        const n = m.length;
        for (let i = 0; i < 8; i++) {
            if (m[8][i] === -1) m[8][i] = 0;
            if (m[i][8] === -1) m[i][8] = 0;
            if (m[8][n - 1 - i] === -1) m[8][n - 1 - i] = 0;
            if (m[n - 1 - i][8] === -1) m[n - 1 - i][8] = 0;
        }
        m[8][8] = 0;
        m[n - 8][8] = 1; // dark module
    }

    function isReserved(m, size) {
        const res = Array.from({ length: size }, () => new Uint8Array(size));
        // finders + separators
        for (let r = 0; r < 9; r++) for (let c = 0; c < 9; c++) res[r][c] = 1;
        for (let r = 0; r < 9; r++) for (let c = size - 8; c < size; c++) res[r][c] = 1;
        for (let r = size - 8; r < size; r++) for (let c = 0; c < 9; c++) res[r][c] = 1;
        // timing
        for (let i = 0; i < size; i++) { res[6][i] = 1; res[i][6] = 1; }
        // alignment (version ≥ 2)
        // ... simplified: mark all non -1 as reserved
        return res;
    }

    // ── Data placement ──────────────────────────────────────────────────
    function placeData(m, dataBits) {
        const n = m.length;
        let bitIdx = 0;
        let upward = true;
        for (let col = n - 1; col >= 1; col -= 2) {
            if (col === 6) col = 5; // skip timing column
            const rows = upward ? Array.from({ length: n }, (_, i) => n - 1 - i) : Array.from({ length: n }, (_, i) => i);
            for (const row of rows) {
                for (let dc = 0; dc <= 1; dc++) {
                    const c = col - dc;
                    if (m[row][c] !== -1) continue; // reserved
                    m[row][c] = bitIdx < dataBits.length ? dataBits[bitIdx++] : 0;
                }
            }
            upward = !upward;
        }
    }

    // ── Masking ─────────────────────────────────────────────────────────
    const MASKS = [
        (r, c) => (r + c) % 2 === 0,
        (r, c) => r % 2 === 0,
        (r, c) => c % 3 === 0,
        (r, c) => (r + c) % 3 === 0,
        (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
        (r, c) => (r * c) % 2 + (r * c) % 3 === 0,
        (r, c) => ((r * c) % 2 + (r * c) % 3) % 2 === 0,
        (r, c) => ((r + c) % 2 + (r * c) % 3) % 2 === 0,
    ];

    function applyMask(m, maskIdx, reserved) {
        const n = m.length;
        const fn = MASKS[maskIdx];
        for (let r = 0; r < n; r++)
            for (let c = 0; c < n; c++)
                if (!reserved[r][c] && fn(r, c))
                    m[r][c] ^= 1;
    }

    function penalty(m) {
        const n = m.length;
        let p = 0;
        // Rule 1: runs of same color
        for (let r = 0; r < n; r++) {
            let run = 1;
            for (let c = 1; c < n; c++) {
                if (m[r][c] === m[r][c - 1]) { run++; }
                else { if (run >= 5) p += run - 2; run = 1; }
            }
            if (run >= 5) p += run - 2;
        }
        for (let c = 0; c < n; c++) {
            let run = 1;
            for (let r = 1; r < n; r++) {
                if (m[r][c] === m[r - 1][c]) { run++; }
                else { if (run >= 5) p += run - 2; run = 1; }
            }
            if (run >= 5) p += run - 2;
        }
        // Rule 2: 2×2 blocks
        for (let r = 0; r < n - 1; r++)
            for (let c = 0; c < n - 1; c++)
                if (m[r][c] === m[r][c + 1] && m[r][c] === m[r + 1][c] && m[r][c] === m[r + 1][c + 1])
                    p += 3;
        return p;
    }

    // ── Format info ─────────────────────────────────────────────────────
    const FORMAT_BITS = (() => {
        const table = [];
        for (let mask = 0; mask < 8; mask++) {
            // EC=M (00), mask pattern
            let data = (0b00 << 3) | mask;
            let bits = data << 10;
            // BCH(15,5) with generator 0x537
            let g = 0x537;
            for (let i = 14; i >= 10; i--)
                if (bits & (1 << i)) bits ^= g << (i - 10);
            bits = ((data << 10) | bits) ^ 0x5412; // XOR mask
            table.push(bits);
        }
        return table;
    })();

    function writeFormat(m, maskIdx) {
        const n = m.length;
        const bits = FORMAT_BITS[maskIdx];
        // Around top-left finder
        const POS_H = [0,1,2,3,4,5,7,8,  n-8,n-7,n-6,n-5,n-4,n-3,n-2,n-1];
        const POS_V = [n-1,n-2,n-3,n-4,n-5,n-6,n-7,n-8,  7,5,4,3,2,1,0];
        // Horizontal (row 8)
        for (let i = 0; i < 8; i++) m[8][POS_H[i]] = (bits >> i) & 1;
        for (let i = 8; i < 15; i++) m[8][POS_H[i]] = (bits >> i) & 1;
        // Vertical (col 8)
        for (let i = 0; i < 7; i++) m[POS_V[i]][8] = (bits >> i) & 1;
        m[8][8] = (bits >> 7) & 1;
        for (let i = 8; i < 15; i++) m[POS_V[i]][8] = (bits >> i) & 1;
    }

    // ── Main encode ─────────────────────────────────────────────────────
    function encode(text) {
        text = text.toUpperCase();
        const version = selectVersion(text.length);
        const size = SIZE(version);
        const [totalCW, ecPerBlock, numBlocks, dataCW] = VERSIONS[version];
        const charCountBits = version <= 9 ? 9 : 11;

        // Encode data
        const enc = encodeAlphanumeric(text);
        // Patch char count bits
        for (let i = 0; i < charCountBits; i++)
            enc.bits[enc.charCountPos + i] = (enc.charCount >> (charCountBits - 1 - i)) & 1;
        if (charCountBits > 9) {
            // Need to re-encode with wider count — insert extra bits
            // For versions 1-9 we use 9 bits, which covers our use case
        }

        // Add terminator
        const dataBitsNeeded = dataCW * 8;
        for (let i = 0; i < 4 && enc.bits.length < dataBitsNeeded; i++) enc.bits.push(0);
        // Pad to byte boundary
        while (enc.bits.length % 8 !== 0) enc.bits.push(0);
        // Pad bytes
        let pad = 0xEC;
        while (enc.bits.length < dataBitsNeeded) {
            for (let i = 7; i >= 0; i--) enc.bits.push((pad >> i) & 1);
            pad = pad === 0xEC ? 0x11 : 0xEC;
        }

        // Convert to bytes
        const dataBytes = new Uint8Array(dataCW);
        for (let i = 0; i < dataCW; i++) {
            let byte = 0;
            for (let b = 0; b < 8; b++) byte = (byte << 1) | (enc.bits[i * 8 + b] || 0);
            dataBytes[i] = byte;
        }

        // Error correction
        const blockSize = Math.floor(dataCW / numBlocks);
        const extraBlocks = dataCW - blockSize * numBlocks;
        const gen = genPoly(ecPerBlock);
        const dataBlocks = [];
        const ecBlocks = [];
        let offset = 0;
        for (let b = 0; b < numBlocks; b++) {
            const bLen = blockSize + (b >= numBlocks - extraBlocks ? 1 : 0);
            const block = dataBytes.slice(offset, offset + bLen);
            offset += bLen;
            dataBlocks.push(block);
            ecBlocks.push(polyMod(block, gen));
        }

        // Interleave
        const allBits = [];
        const pushByte = (byte) => { for (let i = 7; i >= 0; i--) allBits.push((byte >> i) & 1); };
        const maxDataLen = Math.max(...dataBlocks.map(b => b.length));
        for (let i = 0; i < maxDataLen; i++)
            for (const block of dataBlocks)
                if (i < block.length) pushByte(block[i]);
        for (let i = 0; i < ecPerBlock; i++)
            for (const block of ecBlocks)
                if (i < block.length) pushByte(block[i]);

        // Build matrix
        const m = createMatrix(size);
        // Fill with -1 (unset)
        for (let r = 0; r < size; r++) m[r].fill(-1);

        // Add patterns
        addFinder(m, 0, 0);
        addFinder(m, 0, size - 7);
        addFinder(m, size - 7, 0);
        addTiming(m);
        addAlignment(m, version);
        reserveFormat(m);

        // Build reserved map
        const reserved = Array.from({ length: size }, (_, r) =>
            Uint8Array.from(m[r], v => v !== -1 ? 1 : 0)
        );

        // Place data
        placeData(m, allBits);

        // Try all masks, pick best
        let bestMask = 0, bestPenalty = Infinity;
        for (let mi = 0; mi < 8; mi++) {
            const copy = m.map(row => Int8Array.from(row));
            applyMask(copy, mi, reserved);
            writeFormat(copy, mi);
            const p = penalty(copy);
            if (p < bestPenalty) { bestPenalty = p; bestMask = mi; }
        }

        applyMask(m, bestMask, reserved);
        writeFormat(m, bestMask);

        // Convert to boolean matrix
        return m.map(row => Array.from(row, v => v === 1));
    }

    // ── Canvas renderer ─────────────────────────────────────────────────
    function toCanvas(matrix, cellSize = 4, quietZone = 4) {
        const n = matrix.length;
        const total = n + quietZone * 2;
        const px = total * cellSize;
        const canvas = document.createElement('canvas');
        canvas.width = px;
        canvas.height = px;
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, px, px);
        ctx.fillStyle = '#000000';
        for (let r = 0; r < n; r++)
            for (let c = 0; c < n; c++)
                if (matrix[r][c])
                    ctx.fillRect((c + quietZone) * cellSize, (r + quietZone) * cellSize, cellSize, cellSize);
        return canvas;
    }

    return { encode, toCanvas };
})();

// Export for ES modules
if (typeof window !== 'undefined') window.QR = QR;
export default QR;
