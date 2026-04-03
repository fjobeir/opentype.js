import assert from 'assert';
import { parse } from '../src/opentype.mjs';

// DEBUG is normally defined by esbuild at build time; define it for tests.
globalThis.DEBUG = false;

/**
 * Builds a minimal valid TrueType font binary (ArrayBuffer) with the given
 * fpgm (font program) instructions. The font contains just a .notdef glyph
 * and the minimum required tables for opentype.js to parse it as a TrueType font.
 *
 * @param {number[]} fpgmInstructions - byte array of TrueType hinting instructions
 * @returns {ArrayBuffer}
 */
function buildMinimalTTF(fpgmInstructions) {
    // We need these tables for a valid TrueType parse:
    // head, hhea, maxp, OS/2, name, cmap, post, loca, glyf, hmtx, fpgm
    const tables = {};

    // head table (54 bytes)
    tables['head'] = new Uint8Array([
        0x00, 0x01, 0x00, 0x00, // majorVersion=1, minorVersion=0
        0x00, 0x01, 0x00, 0x00, // fontRevision=1.0
        0x00, 0x00, 0x00, 0x00, // checksumAdjustment (placeholder)
        0x5F, 0x0F, 0x3C, 0xF5, // magicNumber
        0x00, 0x0B,             // flags
        0x03, 0xE8,             // unitsPerEm=1000
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // created
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // modified
        0x00, 0x00,             // xMin=0
        0x00, 0x00,             // yMin=0
        0x03, 0xE8,             // xMax=1000
        0x03, 0xE8,             // yMax=1000
        0x00, 0x00,             // macStyle
        0x00, 0x08,             // lowestRecPPEM=8
        0x00, 0x02,             // fontDirectionHint
        0x00, 0x00,             // indexToLocFormat=0 (short)
        0x00, 0x00,             // glyphDataFormat
    ]);

    // hhea table (36 bytes)
    tables['hhea'] = new Uint8Array([
        0x00, 0x01, 0x00, 0x00, // version=1.0
        0x03, 0x20,             // ascender=800
        0xFF, 0x38,             // descender=-200
        0x00, 0x00,             // lineGap=0
        0x02, 0x58,             // advanceWidthMax=600
        0x00, 0x00,             // minLeftSideBearing
        0x00, 0x00,             // minRightSideBearing
        0x02, 0x58,             // xMaxExtent=600
        0x00, 0x01,             // caretSlopeRise
        0x00, 0x00,             // caretSlopeRun
        0x00, 0x00,             // caretOffset
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved
        0x00, 0x00,             // metricDataFormat
        0x00, 0x01,             // numberOfHMetrics=1
    ]);

    // maxp table (32 bytes, TrueType version)
    tables['maxp'] = new Uint8Array([
        0x00, 0x01, 0x00, 0x00, // version=1.0
        0x00, 0x01,             // numGlyphs=1
        0x00, 0x40,             // maxPoints=64
        0x00, 0x01,             // maxContours=1
        0x00, 0x00,             // maxCompositePoints
        0x00, 0x00,             // maxCompositeContours
        0x00, 0x01,             // maxZones=1
        0x00, 0x00,             // maxTwilightPoints
        0x00, 0x10,             // maxStorage=16
        0x00, 0x10,             // maxFunctionDefs=16
        0x00, 0x00,             // maxInstructionDefs
        0x00, 0x40,             // maxStackElements=64
        0x00, 0x00,             // maxSizeOfInstructions
        0x00, 0x00,             // maxComponentElements
        0x00, 0x00,             // maxComponentDepth
    ]);

    // OS/2 table (78 bytes, version 1 minimum)
    const os2 = new Uint8Array(78);
    // version = 1
    os2[0] = 0x00; os2[1] = 0x01;
    // xAvgCharWidth
    os2[2] = 0x02; os2[3] = 0x58; // 600
    // usWeightClass
    os2[4] = 0x01; os2[5] = 0x90; // 400
    // usWidthClass
    os2[6] = 0x00; os2[7] = 0x05; // 5 (Medium)
    // fsType
    os2[8] = 0x00; os2[9] = 0x00;
    // sTypoAscender (offset 68)
    os2[68] = 0x03; os2[69] = 0x20; // 800
    // sTypoDescender (offset 70)
    os2[70] = 0xFF; os2[71] = 0x38; // -200
    // sTypoLineGap (offset 72)
    os2[72] = 0x00; os2[73] = 0x00;
    // usWinAscent (offset 74)
    os2[74] = 0x03; os2[75] = 0xE8; // 1000
    // usWinDescent (offset 76)
    os2[76] = 0x03; os2[77] = 0xE8; // 1000
    tables['OS/2'] = os2;

    // name table - minimal with just familyName and styleName
    // Platform 3 (Windows), Encoding 1 (Unicode BMP), Language 0x0409 (English)
    const familyName = encodeUTF16BE('Test');
    const styleName = encodeUTF16BE('Regular');
    const nameRecords = [
        { nameID: 1, string: familyName },  // fontFamily
        { nameID: 2, string: styleName },   // fontSubfamily
        { nameID: 4, string: familyName },  // fullName
        { nameID: 6, string: familyName },  // postScriptName
    ];
    const stringOffset = 6 + nameRecords.length * 12;
    const nameData = [];
    // format
    push16(nameData, 0);
    // count
    push16(nameData, nameRecords.length);
    // stringOffset
    push16(nameData, stringOffset);
    let strOff = 0;
    for (const rec of nameRecords) {
        push16(nameData, 3);     // platformID (Windows)
        push16(nameData, 1);     // encodingID (Unicode BMP)
        push16(nameData, 0x0409); // languageID (English)
        push16(nameData, rec.nameID);
        push16(nameData, rec.string.length);
        push16(nameData, strOff);
        strOff += rec.string.length;
    }
    for (const rec of nameRecords) {
        for (let i = 0; i < rec.string.length; i++) nameData.push(rec.string[i]);
    }
    tables['name'] = new Uint8Array(nameData);

    // cmap table - format 4 (Windows platform 3, encoding 1)
    // Minimal format 4 with just one segment mapping everything to .notdef
    const cmapData = [];
    push16(cmapData, 0);   // version
    push16(cmapData, 1);   // numTables
    // encoding record
    push16(cmapData, 3);   // platformID (Windows)
    push16(cmapData, 1);   // encodingID (Unicode BMP)
    push32(cmapData, 12);  // offset to subtable

    // Format 4 subtable
    const segCount = 1; // just the sentinel segment
    const segCountX2 = segCount * 2;
    push16(cmapData, 4);            // format
    push16(cmapData, 14 + segCount * 8); // length
    push16(cmapData, 0);            // language
    push16(cmapData, segCountX2);   // segCountX2
    push16(cmapData, 2);            // searchRange
    push16(cmapData, 0);            // entrySelector
    push16(cmapData, 0);            // rangeShift
    // endCount
    push16(cmapData, 0xFFFF);       // sentinel
    // reservedPad
    push16(cmapData, 0);
    // startCount
    push16(cmapData, 0xFFFF);       // sentinel
    // idDelta
    push16(cmapData, 1);            // sentinel delta
    // idRangeOffset
    push16(cmapData, 0);            // sentinel
    tables['cmap'] = new Uint8Array(cmapData);

    // post table (format 3, no glyph names, 32 bytes)
    tables['post'] = new Uint8Array([
        0x00, 0x03, 0x00, 0x00, // format=3.0
        0x00, 0x00, 0x00, 0x00, // italicAngle
        0xFE, 0x00,             // underlinePosition
        0x00, 0x50,             // underlineThickness
        0x00, 0x00, 0x00, 0x00, // isFixedPitch
        0x00, 0x00, 0x00, 0x00, // minMemType42
        0x00, 0x00, 0x00, 0x00, // maxMemType42
        0x00, 0x00, 0x00, 0x00, // minMemType1
        0x00, 0x00, 0x00, 0x00, // maxMemType1
    ]);

    // loca table (short format, 1 glyph = 2 entries)
    // glyph 0 at offset 0, end at offset 0 (empty glyph)
    tables['loca'] = new Uint8Array([
        0x00, 0x00, // glyph 0 offset = 0
        0x00, 0x00, // end offset = 0
    ]);

    // glyf table - empty (glyph 0 has zero length indicated by loca)
    tables['glyf'] = new Uint8Array(0);

    // hmtx table (1 metric)
    tables['hmtx'] = new Uint8Array([
        0x02, 0x58, // advanceWidth=600
        0x00, 0x00, // lsb=0
    ]);

    // fpgm table
    tables['fpgm'] = new Uint8Array(fpgmInstructions);

    // Assemble the font
    const tableNames = Object.keys(tables);
    const numTables = tableNames.length;
    const headerSize = 12 + numTables * 16;

    // Calculate table offsets (each table padded to 4-byte boundary)
    let offset = headerSize;
    const tableOffsets = {};
    for (const name of tableNames) {
        tableOffsets[name] = offset;
        offset += tables[name].length;
        // Pad to 4-byte boundary
        offset = (offset + 3) & ~3;
    }

    const totalSize = offset;
    const buffer = new ArrayBuffer(totalSize);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // Write offset table header
    view.setUint32(0, 0x00010000); // sfVersion (TrueType)
    view.setUint16(4, numTables);
    // searchRange, entrySelector, rangeShift (not strictly needed but let's fill them)
    const searchRange = Math.pow(2, Math.floor(Math.log2(numTables))) * 16;
    view.setUint16(6, searchRange);
    view.setUint16(8, Math.floor(Math.log2(numTables)));
    view.setUint16(10, numTables * 16 - searchRange);

    // Write table records
    let recordOffset = 12;
    for (const name of tableNames) {
        const tag = name.padEnd(4, ' ');
        for (let i = 0; i < 4; i++) {
            view.setUint8(recordOffset + i, tag.charCodeAt(i));
        }
        view.setUint32(recordOffset + 4, 0); // checksum (skip)
        view.setUint32(recordOffset + 8, tableOffsets[name]);
        view.setUint32(recordOffset + 12, tables[name].length);
        recordOffset += 16;
    }

    // Write table data
    for (const name of tableNames) {
        bytes.set(tables[name], tableOffsets[name]);
    }

    return buffer;
}

function encodeUTF16BE(str) {
    const result = [];
    for (let i = 0; i < str.length; i++) {
        result.push((str.charCodeAt(i) >> 8) & 0xFF);
        result.push(str.charCodeAt(i) & 0xFF);
    }
    return result;
}

function push16(arr, val) {
    arr.push((val >> 8) & 0xFF, val & 0xFF);
}

function push32(arr, val) {
    arr.push((val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF);
}

describe('hintingtt.mjs - CVE: TrueType Hinting VM Infinite Loop', function() {
    this.timeout(5000); // Each test should complete well under 5s

    it('should not hang on JMPR with negative offset (infinite backward jump)', function() {
        // PUSHW[0] pushes one 16-bit signed word: -3
        // JMPR does ip += -3 - 1 = ip - 4, then for-loop does ip++
        // Net: ip goes from 3 back to 0, re-executing the push, creating infinite loop
        const fpgm = [
            0xB8,       // PUSHW[0] (push one 16-bit value) - ip 0
            0xFF, 0xFD, // -3 as signed 16-bit               - ip 1,2
            0x1C,       // JMPR                               - ip 3
        ];

        const buffer = buildMinimalTTF(fpgm);
        const font = parse(buffer);

        // fpgm error is caught internally and sets _errorState=3
        font.hinting.exec(font.glyphs.get(0), 12);
        assert.ok(font.hinting._errorState >= 3, 'should have set error state due to instruction limit');
    });

    it('should not hang on JMPR with DUP loop', function() {
        // PUSHW[0] -1, DUP, JMPR creates an infinite loop:
        // ip 0: PUSHW[0]     - push one 16-bit word
        // ip 1-2: 0xFF 0xFF  - value = -1
        // ip 3: DUP           - duplicate -1 on stack
        // ip 4: JMPR          - pops -1, ip += -1 - 1 = ip - 2 = 2, for loop ip++ = 3 (DUP)
        // Loop: DUP at ip 3, JMPR at ip 4, back to DUP at ip 3, forever
        const fpgm = [
            0xB8,       // PUSHW[0]
            0xFF, 0xFF, // -1 as signed 16-bit
            0x20,       // DUP
            0x1C,       // JMPR
        ];

        const buffer = buildMinimalTTF(fpgm);
        const font = parse(buffer);

        font.hinting.exec(font.glyphs.get(0), 12);
        assert.ok(font.hinting._errorState >= 3, 'should have set error state due to instruction limit');
    });

    it('should not hang on LOOPCALL with huge count', function() {
        // Define function 0 as empty (FDEF 0 ... ENDF)
        // Then LOOPCALL function 0 with count = 0x7FFF (32767)
        const fpgm = [
            // PUSHB[0] 0 - function number for FDEF
            0xB0, 0x00,
            // FDEF
            0x2C,
            // ENDF (empty function body)
            0x2D,
            // Now push count (large) and function number for LOOPCALL
            // PUSHW[1] pushes two 16-bit words
            0xB9,                   // PUSHW[1] (push two 16-bit values)
            0x7F, 0xFF,             // count = 32767
            0x00, 0x00,             // fn = 0
            // LOOPCALL
            0x2A,
        ];

        const buffer = buildMinimalTTF(fpgm);
        const font = parse(buffer);

        // Should complete quickly because LOOPCALL count is capped to 10000
        font.hinting.exec(font.glyphs.get(0), 12);
        assert.ok(!font.hinting._errorState, 'should complete without setting an error state');
    });

    it('should not hang on recursive CALL (infinite recursion)', function() {
        // Define function 0 that calls itself:
        // PUSHB[0] 0, FDEF, PUSHB[0] 0, CALL, ENDF
        // Then call function 0
        const fpgm = [
            // PUSHB[0] 0 - define function 0
            0xB0, 0x00,
            // FDEF
            0x2C,
            // function body: PUSHB[0] 0, CALL (calls itself)
            0xB0, 0x00,
            0x2B,
            // ENDF
            0x2D,
            // Now call function 0: PUSHB[0] 0, CALL
            0xB0, 0x00,
            0x2B,
        ];

        const buffer = buildMinimalTTF(fpgm);
        const font = parse(buffer);

        // Error is caught internally by Hinting.prototype.exec
        font.hinting.exec(font.glyphs.get(0), 12);
        assert.ok(font.hinting._errorState >= 3, 'should have set error state due to call depth');
    });

    it('should not hang on mutual recursion between two functions', function() {
        // Function 0 calls function 1, function 1 calls function 0
        const fpgm = [
            // Define function 0: calls function 1
            0xB0, 0x00,  // PUSHB[0] 0
            0x2C,         // FDEF
            0xB0, 0x01,  // PUSHB[0] 1
            0x2B,         // CALL
            0x2D,         // ENDF

            // Define function 1: calls function 0
            0xB0, 0x01,  // PUSHB[0] 1
            0x2C,         // FDEF
            0xB0, 0x00,  // PUSHB[0] 0
            0x2B,         // CALL
            0x2D,         // ENDF

            // Call function 0
            0xB0, 0x00,  // PUSHB[0] 0
            0x2B,         // CALL
        ];

        const buffer = buildMinimalTTF(fpgm);
        const font = parse(buffer);

        font.hinting.exec(font.glyphs.get(0), 12);
        assert.ok(font.hinting._errorState >= 3, 'should have set error state due to call depth');
    });

    it('should cap SLOOP to prevent excessive iterations', function() {
        // Set loop to a huge value (32767) via SLOOP, then execute normally.
        // SLOOP should cap the value to MAX_LOOP_COUNT (10000).
        // The fpgm completes without error because SLOOP just sets state.loop.
        const fpgm = [
            0xB8,             // PUSHW[0]
            0x7F, 0xFF,       // 32767
            0x17,             // SLOOP
        ];

        const buffer = buildMinimalTTF(fpgm);
        const font = parse(buffer);

        font.hinting.exec(font.glyphs.get(0), 12);
        assert.ok(!font.hinting._errorState, 'should complete without setting an error state');
    });

    it('should still allow legitimate font hinting', function() {
        // A simple fpgm that defines a function and returns normally
        const fpgm = [
            // Define function 0: just pops one value (POP = 0x21)
            0xB0, 0x00,  // PUSHB[0] 0
            0x2C,         // FDEF
            0x21,         // POP
            0x2D,         // ENDF

            // Call function 0 with an argument
            0xB0, 0x42,  // PUSHB[0] 0x42
            0xB0, 0x00,  // PUSHB[0] 0 (function number)
            0x2B,         // CALL
        ];

        const buffer = buildMinimalTTF(fpgm);
        const font = parse(buffer);

        // Should execute without error
        assert.doesNotThrow(() => {
            font.hinting.exec(font.glyphs.get(0), 12);
        });
    });
});
