//
//  PGPTrustPacket.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 06/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPTrustPacket.h"

@interface PGPTrustPacket ()
@property (strong, readwrite) NSData *data;
@end

@implementation PGPTrustPacket

- (instancetype) initWithBody:(NSData *)packetData
{
    if (self = [self init]) {
        [self parsePacketBody:packetData];
    }
    return self;
}

- (PGPPacketTag)tag
{
    return PGPTrustPacketTag;
}

- (void) parsePacketBody:(NSData *)packetBody
{
    // 5.10.  Trust Packet (Tag 12)
    // The format of Trust packets is defined by a given implementation.
    self.data = packetBody;
}

@end
