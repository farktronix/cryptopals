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
            if (error != nil) {
                XCTFail()
            }
        }
    }
    
    func runChallenge4() {
        let testBundle = Bundle(for: type(of: self))
        if let cyphertextPath = testBundle.path(forResource: "Challenge4", ofType: "txt", inDirectory: nil) {
            do {
                let allCyphertext = try String(contentsOfFile: cyphertextPath)
                var bestScore = Double.infinity
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
        
        let decryptedText = decryptXOR(cyphertext: line1Hex, key: "ICE")
        XCTAssertEqual(decryptedText, plaintext)
    }
    
    func testHammingDistance() {
        XCTAssertEqual(hammingDistance(asciiString1: "this is a test", asciiString2: "wokka wokka!!!"), 37)
    }
    
    func guessKeySize(cyphertext : [UInt8]) -> [Int] {
        let maxSize = min(40, cyphertext.count / 4)
        
        var keyDistances : [Int : Double] = [:]
        for keysize in 2...maxSize {
            let data1 = Array(cyphertext[0..<keysize])
            let data2 = Array(cyphertext[keysize..<(2*keysize)])
            let data3 = Array(cyphertext[(2*keysize)..<(3*keysize)])
            let data4 = Array(cyphertext[(3*keysize)..<(4*keysize)])
            
            var avgDistance = 0.0
            avgDistance += Double(hammingDistance(data1, data2)) / Double(keysize)
            avgDistance += Double(hammingDistance(data1, data3)) / Double(keysize)
            avgDistance += Double(hammingDistance(data1, data4)) / Double(keysize)
            avgDistance += Double(hammingDistance(data2, data3)) / Double(keysize)
            avgDistance += Double(hammingDistance(data2, data4)) / Double(keysize)
            avgDistance += Double(hammingDistance(data3, data4)) / Double(keysize)
            avgDistance /= 6
            
            keyDistances[keysize] = avgDistance
        }
        
        return Array(keyDistances.keys).sorted() {
            return keyDistances[$0]! < keyDistances[$1]!
        }
    }
    
    func getBlocksOfKeysize(cyphertext : [UInt8], keysize : Int) -> [[UInt8]] {
        var cyphertextBlocks : [[UInt8]] = []
        for index in stride(from: 0, through: cyphertext.count, by: keysize) {
            if (index == cyphertext.count) {
                continue
            }
            let rangeEnd = min(index + keysize, cyphertext.count)
            cyphertextBlocks.append(Array(cyphertext[index..<rangeEnd]))
        }
        
        return cyphertextBlocks;
    }
    
    func transposeBlocks(cyphertextBlocks : [[UInt8]], keysize : Int) -> [[UInt8]] {
        var transposedBlocks : [[UInt8]] = []
        for _ in 0...keysize - 1 {
            transposedBlocks.append([])
        }
        for block in cyphertextBlocks {
            for (curIndex, byte) in block.enumerated() {
                transposedBlocks[curIndex % keysize].append(byte)
            }
        }
        return transposedBlocks
    }
    
    func testChallenge6() {
        let testBundle = Bundle(for: type(of: self))
        if let cyphertextPath = testBundle.path(forResource: "Challenge6", ofType: "txt", inDirectory: nil) {
            do {
                let fileCyphertextString = try String(contentsOfFile: cyphertextPath).replacingOccurrences(of: "\n", with: "")
                let cyphertext : [UInt8] = base64Decode(b64String: fileCyphertextString)
                
                // Find the most likely key size
                let keysizes = guessKeySize(cyphertext: cyphertext)
                let keysize = keysizes.first!
                
                // Break the cyphertext into blocks of keysize
                let cyphertextBlocks = getBlocksOfKeysize(cyphertext: cyphertext, keysize: keysize)
                
                // Transpose the cyphertext blocks
                let transposedBlocks = transposeBlocks(cyphertextBlocks: cyphertextBlocks, keysize: keysize)
                
                // Find the key for each block
                var bestKeys : [UInt8] = [UInt8](repeating: 0, count: keysize)
                let group = DispatchGroup()
                let queue = DispatchQueue(label: "com.farktronix.cryptopals.Challenge6")
                for blockNumber in 0...keysize - 1 {
                    group.enter()
                    findXORKey(cyphertext: transposedBlocks[blockNumber], completion: { (foundKey, _, _) in
                        queue.async {
                            bestKeys[blockNumber] = foundKey
                            group.leave()
                        }
                    })
                }
                group.wait()
                
                // Use the key to decrypt the cyphertext
                let decryptedBytes = decryptXOR(cyphertext: cyphertext, key: bestKeys)
                let decryptedString = String(ascii: decryptedBytes)
                print("String is \"\(decryptedString)\"")
            } catch {
                XCTFail("Couldn't read from the cyphertext file at \(cyphertextPath)")
            }
        }
    }
    
    func testChallenge7() {
        let testBundle = Bundle(for: type(of: self))
        if let cyphertextPath = testBundle.path(forResource: "Challenge6", ofType: "txt", inDirectory: nil) {
            do {
                let fileCyphertextString = try String(contentsOfFile: cyphertextPath).replacingOccurrences(of: "\n", with: "")
                let decodedData = Data(base64Encoded: fileCyphertextString)
                XCTAssertNotNil(decodedData)
                let cyphertext : [UInt8] = [UInt8](decodedData!)
                
            } catch {
                XCTFail("Couldn't read from the cyphertext file at \(cyphertextPath)")
            }
        }
    }
    
    func testAESEncrypt() {
        let plaintext : [UInt8] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]
        let expectedCyphertext : [UInt8] = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32]
        let key : [UInt8] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
        let cyphertext = AESEncryptBlock128(plaintext: plaintext, key: key)
        XCTAssertEqual(cyphertext, expectedCyphertext)
    }
    
    func testAESEncryptBlock() {
        let plaintext : [UInt8] = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A, 0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51, 0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF, 0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10]
        let expectedCyphertext : [UInt8] = [0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97, 0xF5, 0xD3, 0xD5, 0x85, 0x03, 0xB9, 0x69, 0x9D, 0xE7, 0x85, 0x89, 0x5A, 0x96, 0xFD, 0xBA, 0xAF, 0x43, 0xB1, 0xCD, 0x7F, 0x59, 0x8E, 0xCE, 0x23, 0x88, 0x1B, 0x00, 0xE3, 0xED, 0x03, 0x06, 0x88, 0x7B, 0x0C, 0x78, 0x5E, 0x27, 0xE8, 0xAD, 0x3F, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5D, 0xD4]
        let key : [UInt8] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
        let cyphertext = AESEncryptECB128(plaintext: plaintext, key: key)
        XCTAssertEqual(cyphertext, expectedCyphertext)
    }
    
    func testAESDecrypt() {
        let cyphertext : [UInt8] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]
        let key : [UInt8] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
        //AESDecryptECB128(cyphertext: cyphertext, key: key)
        
        let state = loadState(key)
        //printState(state)
        var nextKey : [[UInt8]] = generateKeys(state, rounds: 10)
        for key in nextKey {
            printState(key)
        }
    }
}
