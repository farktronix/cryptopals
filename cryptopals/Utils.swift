//
//  Utils.swift
//  cryptopals
//
//  Created by Jacob Farkas on 4/28/18.
//  Copyright © 2018 Jacob Farkas. All rights reserved.
//

import Foundation

enum CryptoPalsError : Error {
    case invalidArugments
}

func hexStringToBytes(hexString : String) -> [UInt8] {
    var retval : [UInt8] = []
    var isMSB = true
    var accum : UInt8 = 0
    for c in hexString.utf8 {
        var curValue : UInt8 = 0
        switch c {
            // c >= '0' && c <= '9'
            case 0x30...0x39:
                curValue = (c - 0x30)
            // c >= 'A' && c <= 'Z'
            case 0x41...0x5a:
                curValue = (c - 0x41) + 10
            // c >= 'a' && c <= 'z'
            case 0x61...0x7a:
                curValue = (c - 0x61) + 10
            default:
                // TODO: Throw an error or something
                break
        }
        if (isMSB) {
            accum = (curValue << 4)
            isMSB = false
        } else {
            accum |= curValue
            retval.append(accum)
            isMSB = true
        }
    }
    if hexString.utf8.count % 2 == 1 {
        retval.append(accum)
    }
    return retval
}

func bytesToHexString(bytes : [UInt8], uppercase : Bool = false) -> String {
    struct hexMapTable {
        static let map = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]
        static let uppercasemap = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"]
    }
    let hexMap = uppercase ? hexMapTable.uppercasemap : hexMapTable.map
    var retval = ""
    for b in bytes {
        retval.append(hexMap[Int(b>>4)])
        retval.append(hexMap[Int(b&0xf)])
    }
    return retval
}

func base64Encode(bytes : [UInt8]) -> String {
    struct b64MapTable {
        static let map = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
                          "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d", "e", "f",
                          "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v",
                          "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "+", "/"]
    }
    var retval = ""
    var accum : UInt8 = 0
    var idx = 0
    while (idx < bytes.count) {
        let bitcount = (((idx % 3) + 1) * 2)
        let mask : UInt8 = 0x3f << bitcount
        let remaindermask : UInt8 = 0x3f >> UInt8(6 - bitcount)
        accum |= ((bytes[idx] & mask) >> bitcount)
        retval.append(b64MapTable.map[Int(accum)])
        accum = ((bytes[idx] & UInt8(remaindermask)) << (6 - bitcount))
        idx += 1
        
        if (bitcount == 6) {
            retval.append(b64MapTable.map[Int(accum)])
            accum = 0
        }
    }
    switch (bytes.count % 3) {
        case 1:
            retval.append(b64MapTable.map[Int(accum)])
            retval.append("==")
        case 2:
            retval.append(b64MapTable.map[Int(accum)])
            retval.append("=")
        default:
            break
    }
    return retval
}

func decodeBase64Char(character : Unicode.UTF8.CodeUnit) -> UInt8 {
    switch character {
    // c >= 'A' && c <= 'Z'
    case 0x41...0x5a:
        return (character - 0x41)
    // c >= 'a' && c <= 'z'
    case 0x61...0x7a:
        return (character - 0x61) + 26
    // c >= '0' && c <= '9'
    case 0x30...0x39:
        return (character - 0x30) + 52
    // c == '+'
    case 0x2b:
        return 62
    // c == '/'
    case 0x2f:
        return 63
    default:
        // TODO: Throw an error or something
        break
    }
    return 0
}

func base64Decode(b64String : String) -> [UInt8] {
    var retval : [UInt8] = []
    var byteIdx = 0
    var charCount = 0
    for c in b64String.utf8 {
        // check for '='
        if c == 0x3d {
            if retval[byteIdx] == 0 {
                retval.remove(at: byteIdx)
            }
            break
        }
        let decodedChar = decodeBase64Char(character: c)
        switch (charCount % 4) {
            case 0:
                retval.append(decodedChar << 2)
            case 1:
                retval[byteIdx] |= ((decodedChar & 0x30) >> 4)
                byteIdx += 1
                retval.append((decodedChar & 0x0f) << 4)
            case 2:
                retval[byteIdx] |= (decodedChar & 0x3c) >> 2
                byteIdx += 1
                retval.append((decodedChar & 0x03) << 6)
            case 3:
                retval[byteIdx] |= decodedChar
                byteIdx += 1
            default:
                break
        }
        charCount += 1
    }
    return retval
}

func xorBytes(bytes1 : [UInt8]? = nil, bytes2 : [UInt8]? = nil, hexString1 : String? = nil, hexString2 : String? = nil) throws -> [UInt8] {
    var retval : [UInt8] = []
    let source1 : [UInt8]
    let source2 : [UInt8]
    
    if (bytes1 == nil) {
        if (hexString1 == nil) {
            throw CryptoPalsError.invalidArugments
        } else {
            source1 = hexStringToBytes(hexString: hexString1!)
        }
    } else {
        source1 = bytes1!
    }
    
    if (bytes2 == nil) {
        if (hexString2 == nil) {
            throw CryptoPalsError.invalidArugments
        } else {
            source2 = hexStringToBytes(hexString: hexString2!)
        }
    } else {
        source2 = bytes2!
    }
    
    if (source1.count != source2.count) {
        throw CryptoPalsError.invalidArugments
    }
    
    var idx = 0
    while (idx < source1.count) {
        retval.append(source1[idx] ^ source2[idx])
        idx += 1
    }
    
    return retval
}

// Lower scores are better
func englishPlaintextScore(plaintext : [UInt8]) -> Double {
    struct letterFrequency {
        // https://web.archive.org/web/20170918020907/http://www.data-compression.com/english.html
        static let freqArray = [
            0.0651738, // "a"
            0.0124248, // "b"
            0.0217339, // "c"
            0.0349835, // "d"
            0.1041442, // "e"
            0.0197881, // "f"
            0.0158610, // "g"
            0.0492888, // "h"
            0.0558094, // "i"
            0.0009033, // "j"
            0.0050529, // "k"
            0.0331490, // "l"
            0.0202124, // "m"
            0.0564513, // "n"
            0.0596302, // "o"
            0.0137645, // "p"
            0.0008606, // "q"
            0.0497563, // "r"
            0.0515760, // "s"
            0.0729357, // "t"
            0.0225134, // "u"
            0.0082903, // "v"
            0.0171272, // "w"
            0.0013692, // "x"
            0.0145984, // "y"
            0.0007836, // "z"
            0.1918182, // " "
            ]
    }
    
    if (plaintext.count == 0) {
        return Double.infinity
    }
    
    var score : Double = 0
    var letterCount : [Int : Int] = [:]
    for i in 0...plaintext.count - 1 {
        let curLetter = plaintext[i]
        var index : Int = -1
        switch curLetter {
            // c >= 'A' && c <= 'Z'
            case 0x41...0x5a:
                index = Int(curLetter - 0x41)
            // c >= 'a' && c <= 'z'
            case 0x61...0x7a:
                index = Int(curLetter - 0x61)
            case 0x20:
                index = 26
            default:
                score += 1
        }
        if (index >= 0) {
            if letterCount[index] != nil {
                letterCount[index]! += 1
            } else {
                letterCount[index] = 1
            }
        }
    }
    
    let totalLetters = plaintext.count
    for curIndex in 0...26 {
        if let count = letterCount[curIndex] {
            let curFreq = Double(count) / Double(totalLetters)
            let expectedFreq = letterFrequency.freqArray[curIndex]
            // Calculate Chi^2
            score += pow((curFreq - expectedFreq), 2) / expectedFreq
        }
    }
    
    return score
}

func englishPlaintextScore(plaintext : String) -> Double {
    return englishPlaintextScore(plaintext: Array(plaintext.utf8))
}

func xorBytesWithKey(bytes: [UInt8], key : UInt8) -> [UInt8] {
    return bytes.map({ (curChar) -> UInt8 in
        return curChar ^ key
    })
}

func findXORKey(cyphertext : [UInt8], completion : @escaping (_ key: UInt8, _ score : Double, _ plaintext : [UInt8]?) -> ()) {
    var bestScore = Double.infinity
    var bestKey : UInt8 = 0
    var bestText : [UInt8]?
    let decryptGroup = DispatchGroup()
    let resultQueue = DispatchQueue(label: "com.farktronix.cryptopals.XORResultQueue")
    for i : UInt8 in 0...255 {
        decryptGroup.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            let plaintextBytes : [UInt8] = xorBytesWithKey(bytes: cyphertext, key: i)
            let score = englishPlaintextScore(plaintext: plaintextBytes)
        
        // Debug
//          var mPlaintextBytes = plaintextBytes
//          mPlaintextBytes.append(0)
//          mPlaintextBytes.withUnsafeBufferPointer { ptr in
//              let text = String(cString: ptr.baseAddress!)
//              print("xor \(i), score \(score): \(text)")
//          }
        
            if score < bestScore {
                resultQueue.async {
                    if score < bestScore {
                        bestScore = score
                        bestKey = i
                        bestText = plaintextBytes
                    }
                    decryptGroup.leave()
                }
            } else {
                decryptGroup.leave()
            }
        }
    }
    decryptGroup.notify(queue: DispatchQueue.global(qos: .userInitiated)) {
        completion(bestKey, bestScore, bestText)
    }
}

func findXORKey(cyphertext : String, completion : @escaping (_ key: UInt8, _ score : Double, _ plaintext : String?) -> ()) {
    let cypherbytes = hexStringToBytes(hexString: cyphertext)
    findXORKey(cyphertext: cypherbytes) { (bestKey, bestScore, bestTextBytes) in
        var bestText : String?
        if var bestTextBytes = bestTextBytes {
            bestTextBytes.append(0)
            bestTextBytes.withUnsafeBufferPointer { ptr in
                bestText = String(cString: ptr.baseAddress!)
            }
        }
        completion(bestKey, bestScore, bestText)
    }
}
