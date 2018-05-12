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
        XCTAssertLessThan(score, badScore)
    }
    
    func testChallenge3() {
        let expect = expectation(description: "Finding XOR String")
        let cyphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        findXORKey(cyphertext: cyphertext) { (bestKey, _, _) in
            XCTAssertEqual(bestKey, 88)
            expect.fulfill()
        }
        waitForExpectations(timeout: 10) { (error) in
            XCTFail()
        }
    }
    
    func runChallenge4() {
        let testBundle = Bundle(for: type(of: self))
        if let cyphertextPath = testBundle.path(forResource: "Challenge4", ofType: "txt", inDirectory: nil) {
            do {
                let allCyphertext = try String(contentsOfFile: cyphertextPath)
                var bestScore = Double.infinity
//                var bestBytes : [UInt8]?
                var bestKey : UInt8 = 0
                let decryptGroup = DispatchGroup()
                let resultQueue = DispatchQueue(label: "com.farktronix.cryptopals.Challenge4ResultQueue")
                for cyphertext in allCyphertext.components(separatedBy: "\n") {
                    decryptGroup.enter()
                    DispatchQueue.global(qos: .userInitiated).async {
                        let cypherbytes = hexStringToBytes(hexString: cyphertext)
                        findXORKey(cyphertext: cypherbytes, completion: { (curKey, curScore, _) in
                            if (curScore < bestScore) {
                                resultQueue.async {
                                    if (curScore < bestScore) {
                                        bestScore = curScore
//                                      bestBytes = curBytes
                                        bestKey = curKey
                                    }
                                    decryptGroup.leave()
                                }
                            } else {
                                decryptGroup.leave()
                            }

                        })
                    }
                }
                decryptGroup.wait()
                XCTAssertEqual(bestKey, 53)
//                if var bestBytes = bestBytes {
//                    bestBytes.append(0)
//                    bestBytes.withUnsafeBufferPointer { ptr in
//                        let bestText = String(cString: ptr.baseAddress!)
//                        print("Answer: \(bestText) (Score: \(bestScore), key: \(bestKey))")
//                    }
//                } else {
//                    XCTFail("Didn't have a best result in bytes")
//                }
            } catch {
                XCTFail("Couldn't read from the cyphertext file at \(cyphertextPath)")
            }
        } else {
            XCTFail("Couldn't find the challenge 4 file")
        }
    }
    
    func testChallenge4() {
        self.measure {
            runChallenge4()
        }
    }
    
    func testChallenge5() {
        let plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        let expectedCrypto = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        
        let line1Hex = encryptXOR(plaintext: plaintext, key: "ICE")
        XCTAssertEqual(line1Hex, expectedCrypto)
        
        let decryptedText = decryptXOR(cryptotext: line1Hex, key: "ICE")
        XCTAssertEqual(decryptedText, plaintext)
    }
}
