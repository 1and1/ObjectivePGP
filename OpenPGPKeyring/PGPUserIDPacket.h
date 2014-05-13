//
//  PGPUserID.h
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 05/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  Tag 13

#import <Foundation/Foundation.h>
#import "PGPPacketFactory.h"

@interface PGPUserIDPacket : PGPPacket <PGPPacket>

@property (retain, readonly) NSString *userID;

@end
