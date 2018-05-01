//
//  Utils.swift
//  cryptopals
//
//  Created by Jacob Farkas on 4/28/18.
//  Copyright © 2018 Jacob Farkas. All rights reserved.
//

import Foundation

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

func xorBytes(bytes1 : [UInt8], bytes2 : [UInt8]) -> [UInt8] {
    
}
}
