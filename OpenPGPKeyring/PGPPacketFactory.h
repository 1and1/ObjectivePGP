//
//  PGPPacket.h
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPTypes.h"
#import "PGPPacket.h"

@interface PGPPacketFactory : NSObject

+ (id <PGPPacket> ) packetWithData:(NSData *)packetsData offset:(NSUInteger)offset;

@end
