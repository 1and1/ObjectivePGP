//
//  NSData+NSValue.h
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (NSValue)

+(NSData*) dataWithValue:(NSValue*)value;
+(NSData*) dataWithNumber:(NSNumber*)number;

@end
