//
//  PGPModificationDetectionCodePacket.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 12/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPModificationDetectionCodePacket.h"

@implementation PGPModificationDetectionCodePacket

- (PGPPacketTag)tag
{
    return PGPModificationDetectionCodePacketTag;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody
{
    NSUInteger position = [super parsePacketBody:packetBody];

    // 5.14.  Modification Detection Code Packet (Tag 19)
    NSAssert(self.bodyLength == 20, @"A Modification Detection Code packet MUST have a length of 20 octets");

    self.hashData = [packetBody subdataWithRange:(NSRange){0,20}];
    position = position + self.hashData.length;

    return position;
}

@end
