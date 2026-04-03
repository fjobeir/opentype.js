/**
 * Shared utilities for test font generation scripts.
 *
 * Provides binary encoding helpers, checksum calculation, common OpenType
 * table builders, and a font assembly function used by the generate-*.mjs
 * scripts in this directory.
 */

// --- binary helpers (big-endian) ---

export function u8(v) { return [v & 0xFF]; }
export function u16(v) { return [(v >> 8) & 0xff, v & 0xff]; }
export function u32(v) { return [(v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]; }
export function i16(v) { return u16(v < 0 ? v + 0x10000 : v); }
export function i64(v) { return [...u32(0), ...u32(v)]; } // simplified LONGDATETIME
export function tag(s) { return [...s].map(c => c.charCodeAt(0)); }
export function pad(arr) { while (arr.length % 4 !== 0) arr.push(0); return arr; }

export function calcChecksum(bytes) {
    const padded = [...bytes];
    while (padded.length % 4 !== 0) padded.push(0);
    let sum = 0;
    for (let i = 0; i < padded.length; i += 4) {
        sum = (sum + ((padded[i] << 24) | (padded[i+1] << 16) | (padded[i+2] << 8) | padded[i+3])) >>> 0;
    }
    return sum;
}

// --- common table builders ---

export function makeHead({ indexToLocFormat = 0 } = {}) {
    return [
        ...u16(1), ...u16(0),          // majorVersion, minorVersion
        ...u16(1), ...u16(0),          // fontRevision (fixed 1.0)
        ...u32(0),                      // checksumAdjustment (filled later)
        ...u32(0x5F0F3CF5),            // magicNumber
        ...u16(0x000B),                // flags
        ...u16(1000),                  // unitsPerEm
        ...i64(0),                      // created
        ...i64(0),                      // modified
        ...i16(0), ...i16(0),          // xMin, yMin
        ...i16(1000), ...i16(1000),    // xMax, yMax
        ...u16(0),                      // macStyle
        ...u16(8),                      // lowestRecPPEM
        ...i16(2),                      // fontDirectionHint
        ...i16(indexToLocFormat),       // indexToLocFormat
        ...i16(0),                      // glyphDataFormat
    ];
}

export function makePost({ underlinePosition = -100, underlineThickness = 50 } = {}) {
    return [
        ...u16(3), ...u16(0),  // version 3.0 (no glyph names)
        ...u32(0),              // italicAngle
        ...i16(underlinePosition),
        ...i16(underlineThickness),
        ...u32(0),              // isFixedPitch
        ...u32(0),              // minMemType42
        ...u32(0),              // maxMemType42
        ...u32(0),              // minMemType1
        ...u32(0),              // maxMemType1
    ];
}

// --- font assembly ---

/**
 * Assembles a complete OpenType/TrueType font file from a table map.
 * @param {Object} tables - Map of tag string to byte array, e.g. { 'head': [...], 'cmap': [...] }
 * @param {Object} [options]
 * @param {string|number} [options.sfVersion] - 'OTTO' for CFF fonts, or a 32-bit number (default 0x00010000 for TrueType)
 * @returns {Uint8Array}
 */
export function assembleFont(tables, { sfVersion = 0x00010000 } = {}) {
    const tags = Object.keys(tables).sort();
    const numTables = tags.length;
    const searchRange = Math.pow(2, Math.floor(Math.log2(numTables))) * 16;
    const entrySelector = Math.floor(Math.log2(numTables));
    const rangeShift = numTables * 16 - searchRange;

    const headerSize = 12 + numTables * 16;
    let dataOffset = headerSize;

    const tableRecords = [];
    const tableData = [];
    for (const t of tags) {
        const data = tables[t];
        const paddedData = pad([...data]);
        tableRecords.push([
            ...tag(t.padEnd(4, ' ')),
            ...u32(calcChecksum(data)),
            ...u32(dataOffset),
            ...u32(data.length),
        ]);
        tableData.push(...paddedData);
        dataOffset += paddedData.length;
    }

    const sfVersionBytes = typeof sfVersion === 'string'
        ? tag(sfVersion)
        : u32(sfVersion);

    const font = [
        ...sfVersionBytes,
        ...u16(numTables),
        ...u16(searchRange),
        ...u16(entrySelector),
        ...u16(rangeShift),
        ...tableRecords.flat(),
        ...tableData,
    ];

    return new Uint8Array(font);
}
