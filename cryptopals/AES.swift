//
//  AES.swift
//  cryptopals
//
//  Created by Jacob Farkas on 5/12/18.
//  Copyright © 2018 Jacob Farkas. All rights reserved.
//

import Foundation

func subBytesWithBox(state : inout [UInt8], sbox : [UInt8]) {
    for index in 0...state.count - 1 {
        let value = state[index]
        let row = (value & 0xf0) >> 4
        let column = (value & 0x0f)
        state[index] = sbox[Int(column + (row * 16))]
    }
}

func subBytes(_ state : inout [UInt8]) {
    subBytesWithBox(state: &state, sbox: AESConstants.sbox)
}

func subBytesInv(_ state : inout [UInt8]) {
    subBytesWithBox(state: &state, sbox: AESConstants.inverse_sbox)
}

func rotateRow(row : inout [UInt8], amount : Int) {
    let orig = row
    for index in amount...(amount + 3) {
        row[index - amount] = orig[index % 4]
    }
}

func shiftRows(state : inout [UInt8]) {
    for row in 1...3 {
        var extractedRow : [UInt8] = extractRow(state: state, row: row)
        rotateRow(row: &extractedRow, amount: row)
        applyRow(state: &state, newRow: extractedRow, row: row)
    }
}

func shiftRowsInv(state : inout [UInt8]) {
    for row in 1...3 {
        var extractedRow : [UInt8] = extractRow(state: state, row: row)
        rotateRow(row: &extractedRow, amount: (4 - row))
        applyRow(state: &state, newRow: extractedRow, row: row)
    }
}

// I'm having trouble understanding the math behind MixColumns,
// so this is copied from the C example on the Wikipedia page
//  https://en.wikipedia.org/wiki/Rijndael_MixColumns
func gmixColumn(_ column : inout [UInt8]) {
    var a : [UInt8] = column;
    var b : [UInt8] = column;
    /* The array 'a' is simply a copy of the input array 'r'
     * The array 'b' is each element of the array 'a' multiplied by 2
     * in Rijndael's Galois field
     * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */
    for c in 0...3 {
        /* h is 0xff if the high bit of r[c] is set, 0 otherwise */
        var h : UInt8 = 0
        if (column[c] & 0x80) == 0x80 {
            h = 0xff
        }
        b[c] = column[c] << 1; /* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
        b[c] ^= 0x1B & h; /* Rijndael's Galois field */
    }
    column[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
    column[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
    column[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
    column[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
}

func gmixColumnInv(_ column : inout [UInt8]) {
    var a : [UInt8] = column;
    var b : [UInt8] = column;
    /* The array 'a' is simply a copy of the input array 'r'
     * The array 'b' is each element of the array 'a' multiplied by 2
     * in Rijndael's Galois field
     * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */
    for c in 0...3 {
        /* h is 0xff if the high bit of r[c] is set, 0 otherwise */
        var h : UInt8 = 0
        if (column[c] & 0x80) == 0x80 {
            h = 0xff
        }
        b[c] = column[c] << 1; /* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
        b[c] ^= 0x1B & h; /* Rijndael's Galois field */
    }
    column[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
    column[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
    column[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
    column[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
}

func mixColumns(state : inout [UInt8]) {
    for index in 0...3 {
        var column = extractColumn(state: state, column: index)
        gmixColumn(&column)
        applyColumn(state: &state, newColumn: column, column: index)
    }
}

func mixColumnsInv(state : inout [UInt8]) {
    for index in 0...3 {
        var column = extractColumn(state: state, column: index)
        gmixColumnInv(&column)
        applyColumn(state: &state, newColumn: column, column: index)
    }
}

func generateKeys(_ key : [UInt8], rounds : Int) -> [[UInt8]] {
    var result : [[UInt8]] = []
    result.append(key)
    for round in 1...rounds {
        let lastKey : [UInt8] = result.last!
        var roundKey : [UInt8] = [UInt8](repeatElement(UInt8(0), count: 16))
        
        // Perform key schedule core to the temp value
        //  (Section 4.3.1): temp = SubByte(RotByte(temp)) ^ Rcon[i / Nk];
        var temp : [UInt8] = extractColumn(state: lastKey, column: 3)
        rotateRow(row: &temp, amount: 1)
        subBytes(&temp)
        temp[0] = (temp[0] ^ AESConstants.rcon[round])
        
        // XOR temp with the first column in the key
        for row in 0...3 {
            roundKey[(row * 4)] = lastKey[(row * 4)] ^ temp[row]
        }
        
        // XOR the rest of the columns with the previous column
        for column in 1...3 {
            for row in 0...3 {
                roundKey[(row * 4) + column] = lastKey[(row * 4) + column] ^ roundKey[(row * 4) + (column - 1)]
            }
        }
        
        result.append(roundKey)
    }
    return result
}

func addRoundKey(state : inout [UInt8], roundKey : [UInt8]) {
    for index in 0...state.count - 1 {
        state[index] = (state[index] ^ roundKey[index])
    }
}

func performRound(state : inout [UInt8], roundKey: [UInt8], isFinalRound : Bool = false) {
    subBytes(&state)
    shiftRows(state: &state)
    if (!isFinalRound) {
        mixColumns(state: &state)
    }
    addRoundKey(state: &state, roundKey: roundKey)
}

func performRoundInv(state : inout [UInt8], roundKey: [UInt8], isFinalRound : Bool = false) {
    subBytesInv(&state)
    shiftRowsInv(state: &state)
    if (!isFinalRound) {
        mixColumnsInv(state: &state)
    }
    addRoundKey(state: &state, roundKey: roundKey)
}

func extractColumn(state : [UInt8], column : Int) -> [UInt8] {
    var result : [UInt8] = []
    for index in 0...3 {
        result.append(state[(index * 4) + column])
    }
    return result
}

func applyColumn(state : inout [UInt8], newColumn : [UInt8], column : Int) {
    for index in 0...3 {
        state[(index * 4) + column] = newColumn[index]
    }
}

func extractRow(state : [UInt8], row : Int) -> [UInt8] {
    let rowStart = (row * 4);
    return Array(state[rowStart...rowStart + 3])
}

func applyRow(state : inout [UInt8], newRow : [UInt8], row : Int) {
    for index in 0...3 {
        state[(row * 4) + index] = newRow[index]
    }
}

func printState(_ state : [UInt8]) {
    var curLine : String = String()
    for index in 0...state.count - 1 {
        curLine.append(String(format: "%02x ", state[index]))
        if (index > 0 && ((index + 1) % 4 == 0)) {
            curLine.append("\n")
        }
    }
    print(curLine)
}

// State is loaded in column order. This rotates the bytes into the correct order in the returned array
func loadState(_ input : [UInt8]) -> [UInt8] {
    var state : [UInt8] = []
    for column in 0...3 {
        for row in 0...3 {
            state.append(input[(row * 4) + column])
        }
    }
    return state
}

func AESEncryptBlock128(plaintext : [UInt8], key : [UInt8]) -> [UInt8] {
    var state : [UInt8] = loadState(plaintext)
    let key = loadState(key)
    let roundKeys = generateKeys(key, rounds: 10)
    addRoundKey(state: &state, roundKey: key)
    for round in 1...10 {
        let isFinalRound = (round == 10)
        performRound(state: &state, roundKey: roundKeys[round], isFinalRound: isFinalRound)
    }
    state = loadState(state)
    return state
}

func AESEncryptECB128(plaintext : [UInt8], key : [UInt8]) -> [UInt8] {
    var cyphertext : [UInt8] = []
    for index in stride(from: 0, to: plaintext.count, by: 16) {
        let length = min(16, plaintext.count - index)
        var plaintextBlock = Array(plaintext[index...(index + length - 1)])
        if length < 16 {
            let padding : [UInt8] = [UInt8](repeating: 0x0, count: 16 - length)
            plaintextBlock += padding
        }
        cyphertext += AESEncryptBlock128(plaintext: plaintextBlock, key: key)
    }
    return cyphertext
}

func AESDecryptBlock128(cyphertext : [UInt8], key : [UInt8]) -> [UInt8] {
    var state : [UInt8] = loadState(cyphertext)
    let key = loadState(key)
    let roundKeys = generateKeys(key, rounds: 10)
    addRoundKey(state: &state, roundKey: key)
    
    for round in stride(from: 10, to: 1, by: -1) {
        let isFinalRound = (round == 1)
        performRoundInv(state: &state, roundKey: roundKeys[round], isFinalRound: isFinalRound)
    }
    
    return state
}

func AESDecryptECB128(cyphertext : [UInt8], key : [UInt8]) -> [UInt8]? {
    var plaintext : [UInt8] = []
    if (plaintext.count % 16) != 0 {
        return plaintext
    }
    
    for index in stride(from: 0, to: cyphertext.count, by: 16) {
        let cyphertextBlock = Array(plaintext[index...(index + 15)])
        plaintext += AESDecryptBlock128(cyphertext: cyphertextBlock, key: key)
    }
    
    return plaintext
}
