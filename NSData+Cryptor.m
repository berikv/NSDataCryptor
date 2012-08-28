//
//  NSData+Cryptor.m
//  Ziggo TV
//
//  Created by Berik Visschers on 2012-08-28.
//  Copyright (c) 2012 Xaton. All rights reserved.
//

// From: http://stackoverflow.com/a/5621909/439096

#import "NSData+Cryptor.h"

#import <CommonCrypto/CommonCryptor.h>

__attribute__((always_inline)) NSData *encryptData(NSData *dataToEncrypt, NSData *key) {
    //According to the doc: For block ciphers, the output size will always be less than or
    //equal to the input size plus the size of one block.
    //That's why we need to add the size of one block here
    const void *input_raw_data = dataToEncrypt.bytes;
    size_t buffer_size           = dataToEncrypt.length + kCCBlockSizeAES128;
    void* buffer                 = malloc(buffer_size);
    size_t num_bytes_encrypted   = 0;
    
    CCCryptorStatus crypt_status = CCCrypt(kCCEncrypt,
                                           kCCAlgorithmAES128,
                                           kCCOptionPKCS7Padding,
                                           key.bytes,
                                           kCCKeySizeAES256,
                                           NULL,
                                           input_raw_data,
                                           dataToEncrypt.length,
                                           buffer,
                                           buffer_size,
                                           &num_bytes_encrypted);
    
    NSData *encryptedData = nil;
    if (crypt_status == kCCSuccess){
        encryptedData = [NSData dataWithBytesNoCopy:buffer length:num_bytes_encrypted];
    }
    free(buffer);
    
    return encryptedData;
}

__attribute__((always_inline)) NSData *decryptData(NSData *dataToDecrypt, NSData *key) {
    //See the doc: For block ciphers, the output size will always be less than or
    //equal to the input size plus the size of one block.
    //That's why we need to add the size of one block here
    size_t buffer_size           = dataToDecrypt.length + kCCBlockSizeAES128;
    void* buffer                 = malloc(buffer_size);
    size_t num_bytes_decrypted   = 0;
    
    CCCryptorStatus crypt_status = CCCrypt(kCCDecrypt,
                                           kCCAlgorithmAES128,
                                           kCCOptionPKCS7Padding,
                                           key.bytes,
                                           kCCKeySizeAES256,
                                           NULL /* initialization vector (optional) */,
                                           [dataToDecrypt bytes],
                                           dataToDecrypt.length, /* input */
                                           buffer,
                                           buffer_size, /* output */
                                           &num_bytes_decrypted);
    
    NSData *decryptedData = nil;
    if (crypt_status == kCCSuccess){
        decryptedData = [NSData dataWithBytesNoCopy:buffer length:num_bytes_decrypted];
    }
    free(buffer);
    
    return decryptedData;
}
