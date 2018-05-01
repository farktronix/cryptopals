//: Playground - noun: a place where people can play

import Cocoa

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
        break
    case 2:
        retval.append(b64MapTable.map[Int(accum)])
        retval.append("=")
        break
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
                retval[byteIdx] |= (decodedChar & 0x0f)
                byteIdx += 1
                retval.append((decodedChar & 0x30) << 6)
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

let b64string = base64Encode(bytes: [0x4d, 0x61, 0x6e])
base64Decode(b64String: b64string)

//let cryptopalsString = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
//let bytes = hexStringToBytes(hexString: cryptopalsString)
//let hexString = bytesToHexString(bytes: bytes)
//if hexString == cryptopalsString {
//    print("yay")
//} else {
//    print("boo")
//}
