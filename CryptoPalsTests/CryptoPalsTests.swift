//
//  CryptoPalsTests.swift
//  CryptoPalsTests
//
//  Created by Jacob Farkas on 4/29/18.
//  Copyright © 2018 Jacob Farkas. All rights reserved.
//

import XCTest

class CryptoPalsTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testHexStringConversion() {
        let cryptopalsString = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        let bytes = hexStringToBytes(hexString: cryptopalsString)
        let hexString = bytesToHexString(bytes: bytes)
        XCTAssertEqual(hexString, cryptopalsString)
    }
    
    func testB64Conversion() {
        let bytes : [UInt8] = [0x4d, 0x61, 0x6e]
        let b64string = base64Encode(bytes: bytes)
        XCTAssertEqual(b64string, "TWFu")
        
        let bytes2 : [UInt8] = [0x4d, 0x61]
        let b64string2 = base64Encode(bytes: bytes2)
        XCTAssertEqual(b64string2, "TWE=")
        
        let bytes3 : [UInt8] = [0x4d]
        let b64string3 = base64Encode(bytes: bytes3)
        XCTAssertEqual(b64string3, "TQ==")
        
        let cryptopalsString = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        let bytes4 = hexStringToBytes(hexString: cryptopalsString)
        let b64string4 = base64Encode(bytes: bytes4)
        XCTAssertEqual(b64string4, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
    }
    
    func testB64RoundTrip() {
        for _ in 1...100 {
            var randBytes : [UInt8] = []
            for _ in 0...arc4random_uniform(256) {
                randBytes.append(UInt8(arc4random_uniform(256)))
            }
            let b64String = base64Encode(bytes: randBytes)
            let decodedBytes = base64Decode(b64String: b64String)
            XCTAssertEqual(randBytes, decodedBytes)
        }
    }
    
    func testB64Decode() {
        let bytes = base64Decode(b64String: "TWFu")
        XCTAssertEqual(bytes, [0x4d, 0x61, 0x6e])
        
        let bytes3 = base64Decode(b64String: "TWE=")
        XCTAssertEqual(bytes3, [0x4d, 0x61])
        
        let bytes2 = base64Decode(b64String: "TQ==")
        XCTAssertEqual(bytes2, [0x4d])
        
        let cryptopalsString = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        let expectedBytes = hexStringToBytes(hexString: cryptopalsString)
        let bytes4 = base64Decode(b64String: "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
        XCTAssertEqual(bytes4, expectedBytes)
    }
    
    func testXOR() {
        let hexString1 = "1c0111001f010100061a024b53535009181c"
        let hexString2 = "686974207468652062756c6c277320657965"
        var resultBytes : [UInt8]
        do {
            try resultBytes = xorBytes(hexString1: hexString1, hexString2: hexString2)
            XCTAssertEqual(bytesToHexString(bytes: resultBytes), "746865206b696420646f6e277420706c6179")
        } catch {
            XCTFail()
        }
    }
    
    func testEnglishPlaintextScore() {
        let score = englishPlaintextScore(plaintext: "Hello, world");
        let badScore = englishPlaintextScore(plaintext: "sadfasfadfbadfbhgsadfqw jkhasdf kljasd lkjqwjkfhqweugbqer ew e e e d e e fge");
        XCTAssertGreaterThan(score, badScore)
    }
    
    func xorBytesWithKey(bytes: [UInt8], key : UInt8) -> [UInt8] {
        return bytes.map({ (curChar) -> UInt8 in
            return curChar ^ key
        })
    }
    
    // TODO: This doesn't work right because it doesn't append a null byte to the data before making it into a string.
    // I can't find an easy way to do that in Swift, and I already got the answer so ¯\_(ツ)_/¯
    func testChallenge3() {
        let cyphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        let cypherbytes = hexStringToBytes(hexString: cyphertext)
        var maxScore : Double = 0.0
        var bestKey : UInt8 = 0
        var bestText = ""
        for i : UInt8 in 0...255 {
            let plaintextBytes = xorBytesWithKey(bytes: cypherbytes, key: i)
            var plaintext : String?
            plaintextBytes.withUnsafeBufferPointer { ptr in
                plaintext = String(cString: plaintextBytes)
            }
            if let plaintext = plaintext {
                let score = englishPlaintextScore(plaintext: plaintext)
                if score > maxScore {
                    maxScore = score
                    bestKey = i
                    bestText = plaintext
                }
            }
        }
        print("\(bestKey)(\(maxScore)): \(bestText))")
    }
    
}
