/**
 * Generates a minimal TrueType font with circular composite glyph references.
 *
 * The font contains 3 glyphs:
 *   0: .notdef — empty simple glyph
 *   1: composite referencing glyph 2
 *   2: composite referencing glyph 1
 *
 * Glyph 1 is mapped to U+0041 ('A') via a format-4 cmap subtable.
 * Loading this font and calling getPath() on glyph 1 or 2 should NOT
 * cause a stack overflow.
 *
 * Usage: node test/generate-circular-ref-font.mjs
 * Output: test/fonts/circular-composite.ttf
 */

import { writeFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { u16, u32, i16, i64, tag, pad, makeHead, makePost, assembleFont } from './font-generation-helpers.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));

// --- table builders ---

function makeHhea(numGlyphs) {
    return [
        ...u16(1), ...u16(0),          // majorVersion, minorVersion
        ...i16(800),                    // ascender
        ...i16(-200),                  // descender
        ...i16(0),                      // lineGap
        ...u16(1000),                  // advanceWidthMax
        ...i16(0),                      // minLeftSideBearing
        ...i16(0),                      // minRightSideBearing
        ...i16(1000),                  // xMaxExtent
        ...i16(1), ...i16(0),          // caretSlopeRise, caretSlopeRun
        ...i16(0),                      // caretOffset
        ...i16(0), ...i16(0), ...i16(0), ...i16(0), // reserved
        ...i16(0),                      // metricDataFormat
        ...u16(numGlyphs),            // numberOfHMetrics
    ];
}

function makeMaxp(numGlyphs) {
    return [
        ...u16(1), ...u16(0),          // version 1.0
        ...u16(numGlyphs),            // numGlyphs
        ...u16(0),                      // maxPoints
        ...u16(0),                      // maxContours
        ...u16(0),                      // maxCompositePoints
        ...u16(2),                      // maxCompositeContours
        ...u16(1),                      // maxZones
        ...u16(0),                      // maxTwilightPoints
        ...u16(0),                      // maxStorage
        ...u16(0),                      // maxFunctionDefs
        ...u16(0),                      // maxInstructionDefs
        ...u16(0),                      // maxStackElements
        ...u16(0),                      // maxSizeOfInstructions
        ...u16(2),                      // maxComponentElements
        ...u16(2),                      // maxComponentDepth
    ];
}

function makeOs2() {
    const os2 = new Array(96).fill(0);
    // version
    os2[0] = 0; os2[1] = 4;
    // xAvgCharWidth
    os2[2] = (500 >> 8) & 0xff; os2[3] = 500 & 0xff;
    // usWeightClass = 400
    os2[4] = (400 >> 8) & 0xff; os2[5] = 400 & 0xff;
    // usWidthClass = 5
    os2[6] = 0; os2[7] = 5;
    // sTypoAscender at offset 68
    os2[68] = (800 >> 8) & 0xff; os2[69] = 800 & 0xff;
    // sTypoDescender at offset 70 (-200 = 0xFF38)
    os2[70] = 0xFF; os2[71] = 0x38;
    // sTypoLineGap at offset 72
    os2[72] = 0; os2[73] = 0;
    // usWinAscent at offset 74
    os2[74] = (800 >> 8) & 0xff; os2[75] = 800 & 0xff;
    // usWinDescent at offset 76
    os2[76] = (200 >> 8) & 0xff; os2[77] = 200 & 0xff;
    // ulUnicodeRange1 bit 0 (Basic Latin) at offset 42
    os2[42] = 0; os2[43] = 0; os2[44] = 0; os2[45] = 1;
    // sxHeight at offset 86
    os2[86] = (500 >> 8) & 0xff; os2[87] = 500 & 0xff;
    // sCapHeight at offset 88
    os2[88] = (700 >> 8) & 0xff; os2[89] = 700 & 0xff;
    return os2;
}

function makeHmtx(numGlyphs) {
    const metrics = [];
    for (let i = 0; i < numGlyphs; i++) {
        metrics.push(...u16(500), ...i16(0)); // advanceWidth, lsb
    }
    return metrics;
}

function makeCmap() {
    // Format 4 subtable mapping U+0041 ('A') → glyph 1
    const segCount = 2; // 1 segment + sentinel
    const searchRange = 2 * Math.pow(2, Math.floor(Math.log2(segCount)));
    const entrySelector = Math.floor(Math.log2(segCount));
    const rangeShift = 2 * segCount - searchRange;

    const subtable = [
        ...u16(4),                          // format
        ...u16(24),                         // length of this subtable
        ...u16(0),                          // language
        ...u16(segCount * 2),              // segCountX2
        ...u16(searchRange),
        ...u16(entrySelector),
        ...u16(rangeShift),
        ...u16(0x0041), ...u16(0xFFFF),    // endCode[]: 'A', sentinel
        ...u16(0),                          // reservedPad
        ...u16(0x0041), ...u16(0xFFFF),    // startCode[]: 'A', sentinel
        ...i16(0),      ...i16(1),         // idDelta[]: patched below for 'A' and sentinel
        ...u16(0),      ...u16(0),         // idRangeOffset[]: 0, 0
    ];
    // Fix idDelta: to map 0x41 → glyph 1, delta = 1 - 0x41 = -0x40 = 0xFFC0
    subtable[24] = 0xFF; subtable[25] = 0xC0;
    // Sentinel delta keeps 0xFFFF mapping to glyph 0
    subtable[26] = 0x00; subtable[27] = 0x01;
    // Update length
    const len = subtable.length;
    subtable[2] = (len >> 8) & 0xff; subtable[3] = len & 0xff;

    return [
        ...u16(0),          // version
        ...u16(1),          // numTables
        ...u16(3),          // platformID (Windows)
        ...u16(1),          // encodingID (Unicode BMP)
        ...u32(12),         // offset to subtable
        ...subtable,
    ];
}

function makeName() {
    const names = [
        [0, 'Copyright'],
        [1, 'CircularTest'],
        [2, 'Regular'],
        [4, 'CircularTest Regular'],
        [5, 'Version 1.0'],
        [6, 'CircularTest-Regular'],
    ];
    const stringData = [];
    const records = [];
    let offset = 0;
    for (const [nameID, str] of names) {
        const encoded = [...str].flatMap(c => u16(c.charCodeAt(0)));
        records.push([
            ...u16(3),          // platformID (Windows)
            ...u16(1),          // encodingID (Unicode BMP)
            ...u16(0x0409),     // languageID (English US)
            ...u16(nameID),
            ...u16(encoded.length),
            ...u16(offset),
        ]);
        stringData.push(...encoded);
        offset += encoded.length;
    }
    const storageOffset = 6 + records.length * 12;
    return [
        ...u16(0),                      // format
        ...u16(names.length),           // count
        ...u16(storageOffset),          // stringOffset
        ...records.flat(),
        ...stringData,
    ];
}

function makeGlyf() {
    // Glyph 0: .notdef — simple empty glyph (0 contours)
    const glyph0 = [
        ...i16(0),                              // numberOfContours = 0
        ...i16(0), ...i16(0), ...i16(0), ...i16(0), // xMin, yMin, xMax, yMax
    ];

    // Glyph 1: composite referencing glyph 2
    // Flags: ARG_1_AND_2_ARE_WORDS (0x0001) | ARGS_ARE_XY_OFFSETS (0x0002) = 0x0003
    const glyph1 = [
        ...i16(-1),                             // numberOfContours = -1 (composite)
        ...i16(0), ...i16(0), ...i16(0), ...i16(0), // bbox
        ...u16(0x0003),                         // flags (no MORE_COMPONENTS)
        ...u16(2),                              // glyphIndex = 2
        ...i16(0), ...i16(0),                   // dx, dy
    ];

    // Glyph 2: composite referencing glyph 1
    const glyph2 = [
        ...i16(-1),                             // numberOfContours = -1 (composite)
        ...i16(0), ...i16(0), ...i16(0), ...i16(0), // bbox
        ...u16(0x0003),                         // flags
        ...u16(1),                              // glyphIndex = 1
        ...i16(0), ...i16(0),                   // dx, dy
    ];

    return { glyph0, glyph1, glyph2 };
}

function makeLoca(offsets) {
    // Long format (indexToLocFormat = 1)
    return offsets.flatMap(o => u32(o));
}

// --- assemble font ---

function buildFont() {
    const { glyph0, glyph1, glyph2 } = makeGlyf();

    // Pad each glyph to 4-byte boundary for loca offsets
    const g0 = pad([...glyph0]);
    const g1 = pad([...glyph1]);
    const g2 = pad([...glyph2]);

    const glyfData = [...g0, ...g1, ...g2];
    const locaData = makeLoca([0, g0.length, g0.length + g1.length, g0.length + g1.length + g2.length]);

    const numGlyphs = 3;
    const tables = {
        'head': makeHead({ indexToLocFormat: 1 }),
        'hhea': makeHhea(numGlyphs),
        'maxp': makeMaxp(numGlyphs),
        'OS/2': makeOs2(),
        'hmtx': makeHmtx(numGlyphs),
        'cmap': makeCmap(),
        'loca': locaData,
        'glyf': glyfData,
        'name': makeName(),
        'post': makePost(),
    };

    return assembleFont(tables);
}

const fontBytes = buildFont();
const outPath = join(__dirname, 'fonts', 'circular-composite.ttf');
writeFileSync(outPath, fontBytes);
console.log(`Written ${fontBytes.length} bytes to ${outPath}`);
