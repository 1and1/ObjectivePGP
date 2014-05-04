//
//  OpenPGPKeyring.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 03/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "OpenPGPKeyring.h"
#import "PGPPublicKey.h"
#import "PGPPublicSubKey.h"

@interface OpenPGPKeyring () <NSStreamDelegate>
@property (strong) NSInputStream *keyringStream;
@end

@implementation OpenPGPKeyring

- (BOOL) open:(NSString *)path
{
    NSString *fullPath = [path stringByExpandingTildeInPath];

    if (![[NSFileManager defaultManager] fileExistsAtPath:fullPath]) {
        return NO;
    }

    self.keyringStream = [[NSInputStream alloc] initWithFileAtPath:fullPath];
    [self.keyringStream setDelegate:self];
    [self.keyringStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [self.keyringStream open];

//    NSData *ringData = [NSData dataWithContentsOfFile:fullPath];
//    if (!ringData) {
//        return NO;
//    }
//
//    [self parseKeyring:ringData];
    return YES;
}

#pragma mark - NSStreamDelegate

- (void)stream:(NSInputStream *)stream handleEvent:(NSStreamEvent)eventCode
{
    switch (eventCode) {
        case NSStreamEventHasBytesAvailable:
        {
            NSUInteger bufLength = 1;
            UInt8 *buf[bufLength];
            NSInteger readBytes = [stream read:(UInt8 *)buf maxLength:bufLength];
            if (readBytes > 0) {
                [self parsePacketHeader:[NSData dataWithBytes:buf length:bufLength]];
            }
        }
            break;
        case NSStreamEventEndEncountered:
        {
            [stream close];
            [stream removeFromRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
            stream = nil;
        }
            break;
        default:
            break;
    }
}

#pragma mark - Parse keyring

//TODO: whole keyring is parsed at once, for big files it may be a problem
- (BOOL) parseKeyring:(NSData *)keyringData
{
    BOOL ret = NO;
    PGPFormatType formatType = [self parsePacketHeader:keyringData];
    switch (formatType) {
        case PGPFormatNew:
            ret = [self readNewFormatPacket:keyringData];
            break;
        case PGPFormatOld:
            ret = [self readOldFormatPacket:keyringData];
            break;
        default:
            ret = NO;
            break;
    }
    return ret;
}

// 4.2.  Packet Headers
- (PGPFormatType) parsePacketHeader:(NSData *)packetData
{
    UInt8 *headerBytes = (UInt8 *)[packetData subdataWithRange:NSMakeRange(0, 1)].bytes;
    UInt8 headerByte = headerBytes[0];

    BOOL isPGPHeader = !!(headerByte & PGPHeaderPacketTagAllwaysSet);
    BOOL isNewFormat = !!(headerByte & PGPHeaderPacketTagNewFormat);

    if (!isPGPHeader) {
        return PGPFormatUnknown;
    }

    if (isNewFormat) {
        return PGPFormatNew;
    } else {
        return PGPFormatOld;
    }

    return PGPFormatUnknown;
}

// 4.2.  Packet Headers
- (BOOL) readNewFormatPacket:(NSData *)packetData
{
    UInt8 *headerBytes = (UInt8 *)[packetData subdataWithRange:NSMakeRange(0, 1)].bytes;
    // Bits 5-0 -- packet tag
    UInt8 packetTag = (headerBytes[0] << 2);
    packetTag = (packetTag >> 2);

    // body length
    BOOL isPartialBodyLength    = NO;
    UInt32 bodyLength           = 0;
    NSInteger packetBodyByteIdx = 2;

    UInt8 *lengthOctets = (UInt8 *)[packetData subdataWithRange:NSMakeRange(1, 5)].bytes;

    UInt8 firstOctet  = lengthOctets[0];
    UInt8 secondOctet = lengthOctets[1];
    UInt8 thirdOctet  = lengthOctets[2];
    UInt8 fourthOctet = lengthOctets[3];
    UInt8 fifthOctet  = lengthOctets[4];

    if (firstOctet < 192) {
        // 4.2.2.1.  One-Octet Length
        // bodyLen = 1st_octet;
        bodyLength        = firstOctet;
        packetBodyByteIdx = 1 + 1;
    } else if (firstOctet >= 192 && firstOctet <= 223) {
        // 4.2.2.2.  Two-Octet Lengths
        // bodyLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192
        bodyLength        = ((firstOctet - 192) << 8) + (secondOctet) + 192;
        packetBodyByteIdx = 1 + 2;
    } else if (firstOctet >= 223 && firstOctet < 255) {
        // 4.2.2.4.  Partial Body Length
        // partialBodyLen = 1 << (1st_octet & 0x1F);
        UInt32 partianBodyLength = CFSwapInt32BigToHost(firstOctet << (firstOctet & 0x1F));
        bodyLength               = partianBodyLength;
        packetBodyByteIdx        = 1 + 1;
        isPartialBodyLength      = YES;
    } else if (firstOctet == 255) {
        // 4.2.2.3.  Five-Octet Length
        // bodyLen = (2nd_octet << 24) | (3rd_octet << 16) |
        //           (4th_octet << 8)  | 5th_octet
        bodyLength        = (secondOctet << 24) | (thirdOctet << 16) | (fourthOctet << 8)  | fifthOctet;
        packetBodyByteIdx = 1 + 5;
    }

    [self readPacketType:packetTag packetBody:[packetData subdataWithRange:NSMakeRange(packetBodyByteIdx, bodyLength)]];

    return YES;
}

// 4.2.  Packet Headers
//TODO: read old format
- (BOOL) readOldFormatPacket:(NSData *)packetData
{
    @throw [NSException exceptionWithName:@"PGPUnknownFormat" reason:@"Old format is not supported" userInfo:nil];
    return NO;
}

- (BOOL) readPacketType:(PGPPacketTag)packetTag packetBody:(NSData *)packetBody
{
    NSLog(@"Reading packet tag %#x", packetTag);
    
    switch (packetTag) {
        case PGPPublicKeyPacketTag:
        {
            PGPPublicKey *publicKey = [[PGPPublicKey alloc] init];
            [publicKey parsePacketBody:packetBody];
        }
            break;
        case PGPPublicSubkeyPacketTag:
        {
            PGPPublicSubKey *publicSubKey = [[PGPPublicSubKey alloc] init];
            [publicSubKey parsePacketBody:packetBody];
        }
            break;

        default:
            break;
    }
    return YES;
}

@end
