//
//  PGPSignature.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  Tag 2

#import <Foundation/Foundation.h>
#import "PGPPacketFactory.h"
#import "PGPKeyID.h"

@class PGPKey, PGPUser, PGPUserIDPacket;

@interface PGPSignaturePacket : PGPPacket

@property (assign) UInt8 version;
@property (assign) PGPSignatureType type;
@property (assign) PGPPublicKeyAlgorithm publicKeyAlgorithm;
@property (assign) PGPHashAlgorithm hashAlgoritm;
@property (strong, readonly, nonatomic) NSArray *hashedSubpackets;
@property (strong, readonly, nonatomic) NSArray *unhashedSubpackets;
@property (strong) NSArray *signatureMPIs;

@property (assign, nonatomic, readonly) BOOL canBeUsedToSign;

// Two-octet field holding left 16 bits of signed hash value. (not signatureData, but full data
// The concatenation of the data being signed and the
// !!! signature data from the version number through the hashed subpacket data (inclusive) is hashed. !!!
// The resulting hash value is what is signed.
@property (strong) NSData *signedHashValueData; // BE

/**
 *  Create signature packet for signing. This is convienience constructor.
 *
 *  @param type               example: PGPSignatureBinaryDocument
 *  @param publicKeyAlgorithm public key algorith to be used for signature
 *  @param hashAlgorithm      hash algorithm to be used for signature
 *
 *  @return Packet instance ready to call signData:secretKey
 */
+ (PGPSignaturePacket *) signaturePacket:(PGPSignatureType)type hashAlgorithm:(PGPHashAlgorithm)hashAlgorithm;

// Issuer key id
- (PGPKeyID *) issuerKeyID;
// All subpackets
- (NSArray *) subpackets;
- (NSArray *) subpacketsOfType:(PGPSignatureSubpacketType)type;

/**
 *  Build signature data (signature packet with subpackets).
 *
 *  @param secretKey Secret key used to create signature
 *  @param inputData Data to sign
 *  @param userID    Optional. User ID
 *
 *  @return Signature packet data
 */
- (void) signData:(NSData *)inputData  secretKey:(PGPKey *)secretKey userID:(NSString *)userID;
- (void) signData:(NSData *)inputData  secretKey:(PGPKey *)secretKey;


- (BOOL) verifyData:(NSData *)inputData  withKey:(PGPKey *)publicKey;
- (BOOL) verifyData:(NSData *)inputData  withKey:(PGPKey *)publicKey userID:(NSString *)userID;


@end
