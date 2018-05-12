//
//  main.swift
//  cryptopals
//
//  Created by Jacob Farkas on 4/28/18.
//  Copyright © 2018 Jacob Farkas. All rights reserved.
//

import Foundation

let cyphertextPath = "/tmp/Challenge4.txt";
do {
    let allCyphertext = try String(contentsOfFile: cyphertextPath)
    var bestScore = Double.infinity
    var bestBytes : [UInt8]?
    var bestKey : UInt8 = 0
    for cyphertext in allCyphertext.components(separatedBy: "\n") {
        let cypherbytes = hexStringToBytes(hexString: cyphertext)
        let (curKey, curScore, curBytes) = findXORKey(cyphertext: cypherbytes)
        if (curScore < bestScore) {
            bestScore = curScore
            bestBytes = curBytes
            bestKey = curKey
        }
    }
    if var bestBytes = bestBytes {
        bestBytes.append(0)
        bestBytes.withUnsafeBufferPointer { ptr in
            let bestText = String(cString: ptr.baseAddress!)
            print("Answer: \(bestText) (Score: \(bestScore), key: \(bestKey))")
        }
    }
} catch {
    print("Couldn't read from the cyphertext file at \(cyphertextPath)")
}

