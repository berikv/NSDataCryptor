//
//  NSData+Cryptor.h
//  Ziggo TV
//
//  Created by Berik Visschers on 2012-08-28.
//  Copyright (c) 2012 Xaton. All rights reserved.
//

#import <Foundation/Foundation.h>

NSData *encryptData(NSData *dataToEncrypt, NSData *key);
NSData *decryptData(NSData *dataToDecrypt, NSData *key);
