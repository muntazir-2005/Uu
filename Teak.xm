#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <AdSupport/AdSupport.h>
#import <AppTrackingTransparency/AppTrackingTransparency.h>
#import "fishhook.h"

#pragma mark - Cryptographic Hooks (Memory-Based, No Patching)

// ===== AES-128/256 CBC Encrypt =====
int (*orig_AES_cbc_encrypt)(const unsigned char *in, unsigned char *out, size_t len, const void *key, unsigned char *ivec, int enc);
int hooked_AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len, const void *key, unsigned char *ivec, int enc) {
    return orig_AES_cbc_encrypt(in, out, len, key, ivec, enc);
}

// ===== AES_encrypt =====
void (*orig_AES_encrypt)(const unsigned char *in, unsigned char *out, const void *key);
void hooked_AES_encrypt(const unsigned char *in, unsigned char *out, const void *key) {
    orig_AES_encrypt(in, out, key);
}

// ===== AES_decrypt =====
void (*orig_AES_decrypt)(const unsigned char *in, unsigned char *out, const void *key);
void hooked_AES_decrypt(const unsigned char *in, unsigned char *out, const void *key) {
    orig_AES_decrypt(in, out, key);
}

// ===== AES_set_encrypt_key =====
int (*orig_AES_set_encrypt_key)(const unsigned char *userKey, int bits, void *key);
int hooked_AES_set_encrypt_key(const unsigned char *userKey, int bits, void *key) {
    int ret = orig_AES_set_encrypt_key(userKey, bits, key);
    return (ret != 0) ? 0 : ret;
}

// ===== AES_set_decrypt_key =====
int (*orig_AES_set_decrypt_key)(const unsigned char *userKey, int bits, void *key);
int hooked_AES_set_decrypt_key(const unsigned char *userKey, int bits, void *key) {
    int ret = orig_AES_set_decrypt_key(userKey, bits, key);
    return (ret != 0) ? 0 : ret;
}

// ===== DES_encrypt =====
void (*orig_DES_encrypt)(unsigned long *input, void *schedule, int encrypting);
void hooked_DES_encrypt(unsigned long *input, void *schedule, int encrypting) {
    orig_DES_encrypt(input, schedule, encrypting);
}

// ===== DES_decrypt =====
void (*orig_DES_decrypt)(unsigned long *input, void *schedule, int encrypting);
void hooked_DES_decrypt(unsigned long *input, void *schedule, int encrypting) {
    orig_DES_decrypt(input, schedule, encrypting);
}

// ===== DES_cbc_encrypt =====
int (*orig_DES_cbc_encrypt)(const unsigned char *input, unsigned char *output, long length, void *schedule, unsigned char *ivec, int enc);
int hooked_DES_cbc_encrypt(const unsigned char *input, unsigned char *output, long length, void *schedule, unsigned char *ivec, int enc) {
    return orig_DES_cbc_encrypt(input, output, length, schedule, ivec, enc);
}

// ===== DES_set_key =====
int (*orig_DES_set_key)(const unsigned char *key, void *schedule);
int hooked_DES_set_key(const unsigned char *key, void *schedule) {
    int ret = orig_DES_set_key(key, schedule);
    return (ret != 0) ? 0 : ret;
}

#pragma mark - RSA Hooks

// ===== RSA_public_encrypt =====
int (*orig_RSA_public_encrypt)(int flen, const unsigned char *from, unsigned char *to, void *rsa, int padding);
int hooked_RSA_public_encrypt(int flen, const unsigned char *from, unsigned char *to, void *rsa, int padding) {
    int ret = orig_RSA_public_encrypt(flen, from, to, rsa, padding);
    return (ret < 0) ? flen : ret;
}

// ===== RSA_private_decrypt =====
int (*orig_RSA_private_decrypt)(int flen, const unsigned char *from, unsigned char *to, void *rsa, int padding);
int hooked_RSA_private_decrypt(int flen, const unsigned char *from, unsigned char *to, void *rsa, int padding) {
    int ret = orig_RSA_private_decrypt(flen, from, to, rsa, padding);
    return (ret < 0) ? flen : ret;
}

// ===== RSA_private_encrypt =====
int (*orig_RSA_private_encrypt)(int flen, const unsigned char *from, unsigned char *to, void *rsa, int padding);
int hooked_RSA_private_encrypt(int flen, const unsigned char *from, unsigned char *to, void *rsa, int padding) {
    int ret = orig_RSA_private_encrypt(flen, from, to, rsa, padding);
    return (ret < 0) ? flen : ret;
}

// ===== RSA_public_decrypt =====
int (*orig_RSA_public_decrypt)(int flen, const unsigned char *from, unsigned char *to, void *rsa, int padding);
int hooked_RSA_public_decrypt(int flen, const unsigned char *from, unsigned char *to, void *rsa, int padding) {
    int ret = orig_RSA_public_decrypt(flen, from, to, rsa, padding);
    return (ret < 0) ? flen : ret;
}

// ===== RSA_sign =====
int (*orig_RSA_sign)(int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, void *rsa);
int hooked_RSA_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, void *rsa) {
    int ret = orig_RSA_sign(type, m, m_len, sigret, siglen, rsa);
    return (ret != 1) ? 1 : ret;
}

// ===== RSA_verify =====
int (*orig_RSA_verify)(int type, const unsigned char *m, unsigned int m_len, const unsigned char *sigbuf, unsigned int siglen, void *rsa);
int hooked_RSA_verify(int type, const unsigned char *m, unsigned int m_len, const unsigned char *sigbuf, unsigned int siglen, void *rsa) {
    int ret = orig_RSA_verify(type, m, m_len, sigbuf, siglen, rsa);
    return (ret != 1) ? 1 : ret;
}

// ===== RSA_check_key =====
int (*orig_RSA_check_key)(const void *rsa);
int hooked_RSA_check_key(const void *rsa) {
    int ret = orig_RSA_check_key(rsa);
    return (ret != 1) ? 1 : ret;
}

// ===== RSA_generate_key =====
int (*orig_RSA_generate_key)(void *rsa, int bits, unsigned long e, void *cb);
int hooked_RSA_generate_key(void *rsa, int bits, unsigned long e, void *cb) {
    int ret = orig_RSA_generate_key(rsa, bits, e, cb);
    return (ret != 1) ? 1 : ret;
}

// ===== RSA_padding_add_PKCS1_type_1 =====
int (*orig_RSA_padding_add_PKCS1_type_1)(unsigned char *to, int tlen, const unsigned char *f, int fl);
int hooked_RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen, const unsigned char *f, int fl) {
    int ret = orig_RSA_padding_add_PKCS1_type_1(to, tlen, f, fl);
    return (ret != 1) ? 1 : ret;
}

// ===== RSA_padding_add_PKCS1_type_2 =====
int (*orig_RSA_padding_add_PKCS1_type_2)(unsigned char *to, int tlen, const unsigned char *f, int fl);
int hooked_RSA_padding_add_PKCS1_type_2(unsigned char *to, int tlen, const unsigned char *f, int fl) {
    int ret = orig_RSA_padding_add_PKCS1_type_2(to, tlen, f, fl);
    return (ret != 1) ? 1 : ret;
}

// ===== RSA_padding_add_SSLv23 =====
int (*orig_RSA_padding_add_SSLv23)(unsigned char *to, int tlen, const unsigned char *f, int fl);
int hooked_RSA_padding_add_SSLv23(unsigned char *to, int tlen, const unsigned char *f, int fl) {
    int ret = orig_RSA_padding_add_SSLv23(to, tlen, f, fl);
    return (ret != 1) ? 1 : ret;
}

// ===== RSA_padding_add_X931 =====
int (*orig_RSA_padding_add_X931)(unsigned char *to, int tlen, const unsigned char *f, int fl);
int hooked_RSA_padding_add_X931(unsigned char *to, int tlen, const unsigned char *f, int fl) {
    int ret = orig_RSA_padding_add_X931(to, tlen, f, fl);
    return (ret != 1) ? 1 : ret;
}

// ===== RSA_padding_check_PKCS1_OAEP =====
int (*orig_RSA_padding_check_PKCS1_OAEP)(unsigned char *to, int tlen, const unsigned char *f, int fl, int rlen, unsigned char *param, int plen);
int hooked_RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen, const unsigned char *f, int fl, int rlen, unsigned char *param, int plen) {
    int ret = orig_RSA_padding_check_PKCS1_OAEP(to, tlen, f, fl, rlen, param, plen);
    return (ret < 0) ? tlen : ret;
}

// ===== RSA_padding_check_SSLv23 =====
int (*orig_RSA_padding_check_SSLv23)(unsigned char *to, int tlen, const unsigned char *f, int fl, int rlen);
int hooked_RSA_padding_check_SSLv23(unsigned char *to, int tlen, const unsigned char *f, int fl, int rlen) {
    int ret = orig_RSA_padding_check_SSLv23(to, tlen, f, fl, rlen);
    return (ret < 0) ? tlen : ret;
}

// ===== rsa_cms_decrypt =====
int (*orig_rsa_cms_decrypt)(void *cms, void *rsa, int keyidx);
int hooked_rsa_cms_decrypt(void *cms, void *rsa, int keyidx) {
    int ret = orig_rsa_cms_decrypt(cms, rsa, keyidx);
    return (ret != 1) ? 1 : ret;
}

// ===== rsa_item_verify =====
int (*orig_rsa_item_verify)(void *it, const void *a, int alen, void *asn1, void *ctx);
int hooked_rsa_item_verify(void *it, const void *a, int alen, void *asn1, void *ctx) {
    int ret = orig_rsa_item_verify(it, a, alen, asn1, ctx);
    return (ret != 1) ? 1 : ret;
}

#pragma mark - Hash Hooks (MD5, SHA1, SHA256, SHA512, HMAC)

// ===== MD5_Init =====
int (*orig_MD5_Init)(void *c);
int hooked_MD5_Init(void *c) {
    int ret = orig_MD5_Init(c);
    return (ret != 1) ? 1 : ret;
}

// ===== MD5_Update =====
int (*orig_MD5_Update)(void *c, const void *data, size_t len);
int hooked_MD5_Update(void *c, const void *data, size_t len) {
    return orig_MD5_Update(c, data, len);
}

// ===== MD5_Final =====
int (*orig_MD5_Final)(unsigned char *md, void *c);
int hooked_MD5_Final(unsigned char *md, void *c) {
    int ret = orig_MD5_Final(md, c);
    return (ret != 1) ? 1 : ret;
}

// ===== SHA1_Init =====
int (*orig_SHA1_Init)(void *c);
int hooked_SHA1_Init(void *c) {
    int ret = orig_SHA1_Init(c);
    return (ret != 1) ? 1 : ret;
}

// ===== SHA1_Update =====
int (*orig_SHA1_Update)(void *c, const void *data, size_t len);
int hooked_SHA1_Update(void *c, const void *data, size_t len) {
    return orig_SHA1_Update(c, data, len);
}

// ===== SHA1_Final =====
int (*orig_SHA1_Final)(unsigned char *md, void *c);
int hooked_SHA1_Final(unsigned char *md, void *c) {
    int ret = orig_SHA1_Final(md, c);
    return (ret != 1) ? 1 : ret;
}

// ===== SHA256_Init =====
int (*orig_SHA256_Init)(void *c);
int hooked_SHA256_Init(void *c) {
    int ret = orig_SHA256_Init(c);
    return (ret != 1) ? 1 : ret;
}

// ===== SHA256_Update =====
int (*orig_SHA256_Update)(void *c, const void *data, size_t len);
int hooked_SHA256_Update(void *c, const void *data, size_t len) {
    return orig_SHA256_Update(c, data, len);
}

// ===== SHA256_Final =====
int (*orig_SHA256_Final)(unsigned char *md, void *c);
int hooked_SHA256_Final(unsigned char *md, void *c) {
    int ret = orig_SHA256_Final(md, c);
    return (ret != 1) ? 1 : ret;
}

// ===== SHA512_Init =====
int (*orig_SHA512_Init)(void *c);
int hooked_SHA512_Init(void *c) {
    int ret = orig_SHA512_Init(c);
    return (ret != 1) ? 1 : ret;
}

// ===== SHA512_Update =====
int (*orig_SHA512_Update)(void *c, const void *data, size_t len);
int hooked_SHA512_Update(void *c, const void *data, size_t len) {
    return orig_SHA512_Update(c, data, len);
}

// ===== SHA512_Final =====
int (*orig_SHA512_Final)(unsigned char *md, void *c);
int hooked_SHA512_Final(unsigned char *md, void *c) {
    int ret = orig_SHA512_Final(md, c);
    return (ret != 1) ? 1 : ret;
}

// ===== MD5 (one-shot) =====
unsigned char *(*orig_MD5)(const unsigned char *d, size_t n, unsigned char *md);
unsigned char *hooked_MD5(const unsigned char *d, size_t n, unsigned char *md) {
    return orig_MD5(d, n, md);
}

// ===== HMAC_Init =====
int (*orig_HMAC_Init)(void *ctx, const void *key, int key_len, const void *md);
int hooked_HMAC_Init(void *ctx, const void *key, int key_len, const void *md) {
    int ret = orig_HMAC_Init(ctx, key, key_len, md);
    return (ret != 1) ? 1 : ret;
}

// ===== HMAC_Update =====
int (*orig_HMAC_Update)(void *ctx, const void *data, size_t len);
int hooked_HMAC_Update(void *ctx, const void *data, size_t len) {
    return orig_HMAC_Update(ctx, data, len);
}

// ===== HMAC_Final =====
int (*orig_HMAC_Final)(void *ctx, unsigned char *md, unsigned int *len);
int hooked_HMAC_Final(void *ctx, unsigned char *md, unsigned int *len) {
    int ret = orig_HMAC_Final(ctx, md, len);
    return (ret != 1) ? 1 : ret;
}

#pragma mark - EVP Hooks

// ===== EVP_SignFinal =====
int (*orig_EVP_SignFinal)(void *ctx, unsigned char *md, unsigned int *s, void *pkey);
int hooked_EVP_SignFinal(void *ctx, unsigned char *md, unsigned int *s, void *pkey) {
    int ret = orig_EVP_SignFinal(ctx, md, s, pkey);
    return (ret != 1) ? 1 : ret;
}

// ===== EVP_VerifyFinal =====
int (*orig_EVP_VerifyFinal)(void *ctx, const unsigned char *sigbuf, unsigned int siglen, void *pkey);
int hooked_EVP_VerifyFinal(void *ctx, const unsigned char *sigbuf, unsigned int siglen, void *pkey) {
    int ret = orig_EVP_VerifyFinal(ctx, sigbuf, siglen, pkey);
    return (ret != 1) ? 1 : ret;
}

// ===== EVP_DigestSign =====
int (*orig_EVP_DigestSign)(void *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
int hooked_EVP_DigestSign(void *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen) {
    int ret = orig_EVP_DigestSign(ctx, sig, siglen, tbs, tbslen);
    return (ret != 1) ? 1 : ret;
}

// ===== EVP_DigestVerify =====
int (*orig_EVP_DigestVerify)(void *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
int hooked_EVP_DigestVerify(void *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen) {
    int ret = orig_EVP_DigestVerify(ctx, sig, siglen, tbs, tbslen);
    return (ret != 1) ? 1 : ret;
}

// ===== EVP_PKEY_sign =====
int (*orig_EVP_PKEY_sign)(void *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
int hooked_EVP_PKEY_sign(void *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen) {
    int ret = orig_EVP_PKEY_sign(ctx, sig, siglen, tbs, tbslen);
    return (ret != 1) ? 1 : ret;
}

// ===== EVP_PKEY_verify =====
int (*orig_EVP_PKEY_verify)(void *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
int hooked_EVP_PKEY_verify(void *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen) {
    int ret = orig_EVP_PKEY_verify(ctx, sig, siglen, tbs, tbslen);
    return (ret != 1) ? 1 : ret;
}

#pragma mark - X509 & SSL Hooks

// ===== X509_verify_cert =====
int (*orig_X509_verify_cert)(void *ctx);
int hooked_X509_verify_cert(void *ctx) {
    int ret = orig_X509_verify_cert(ctx);
    return (ret != 1) ? 1 : ret;
}

// ===== X509_check_private_key =====
int (*orig_X509_check_private_key)(const void *x509, const void *pkey);
int hooked_X509_check_private_key(const void *x509, const void *pkey) {
    int ret = orig_X509_check_private_key(x509, pkey);
    return (ret != 1) ? 1 : ret;
}

// ===== SSL_CTX_set_verify =====
void (*orig_SSL_CTX_set_verify)(void *ctx, int mode, void *cb);
void hooked_SSL_CTX_set_verify(void *ctx, int mode, void *cb) {
    orig_SSL_CTX_set_verify(ctx, 0x00, NULL);
}

// ===== SSL_CTX_set_cert_verify_callback =====
void (*orig_SSL_CTX_set_cert_verify_callback)(void *ctx, void *cb, void *arg);
void hooked_SSL_CTX_set_cert_verify_callback(void *ctx, void *cb, void *arg) {
    return;
}

// ===== SSL_get_verify_result =====
long (*orig_SSL_get_verify_result)(const void *ssl);
long hooked_SSL_get_verify_result(const void *ssl) {
    return 0;
}

// ===== SSL_read =====
int (*orig_SSL_read)(void *ssl, void *buf, int num);
int hooked_SSL_read(void *ssl, void *buf, int num) {
    return orig_SSL_read(ssl, buf, num);
}

// ===== SSL_write =====
int (*orig_SSL_write)(void *ssl, const void *buf, int num);
int hooked_SSL_write(void *ssl, const void *buf, int num) {
    return orig_SSL_write(ssl, buf, num);
}

// ===== X509_STORE_CTX_verify =====
int (*orig_X509_STORE_CTX_verify)(void *ctx);
int hooked_X509_STORE_CTX_verify(void *ctx) {
    int ret = orig_X509_STORE_CTX_verify(ctx);
    return (ret != 1) ? 1 : ret;
}

// ===== SSL_set_verify =====
void (*orig_SSL_set_verify)(void *ssl, int mode, void *cb);
void hooked_SSL_set_verify(void *ssl, int mode, void *cb) {
    orig_SSL_set_verify(ssl, 0x00, NULL);
}

#pragma mark - iOS Security Framework Hooks (SecItem*, SecKey*)

// ===== SecItemAdd =====
OSStatus (*orig_SecItemAdd)(CFDictionaryRef attributes, CFTypeRef *result);
OSStatus hooked_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    return orig_SecItemAdd(attributes, result);
}

// ===== SecItemUpdate =====
OSStatus (*orig_SecItemUpdate)(CFDictionaryRef query, CFDictionaryRef attributesToUpdate);
OSStatus hooked_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    return orig_SecItemUpdate(query, attributesToUpdate);
}

// ===== SecItemCopyMatching =====
OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef query, CFTypeRef *result);
OSStatus hooked_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    OSStatus status = orig_SecItemCopyMatching(query, result);
    if (status == errSecItemNotFound) {
        NSString *queryDesc = [(__bridge NSDictionary *)query description];
        if ([queryDesc containsString:@"kSecClassKey"] || [queryDesc containsString:@"private"]) {
            return status;
        }
        return errSecSuccess;
    }
    return status;
}

// ===== SecItemDelete =====
OSStatus (*orig_SecItemDelete)(CFDictionaryRef query);
OSStatus hooked_SecItemDelete(CFDictionaryRef query) {
    return orig_SecItemDelete(query);
}

// ===== SecKeyEncrypt =====
OSStatus (*orig_SecKeyEncrypt)(SecKeyRef key, SecPadding padding, const uint8_t *plainText, size_t plainTextLen, uint8_t *cipherText, size_t *cipherTextLen);
OSStatus hooked_SecKeyEncrypt(SecKeyRef key, SecPadding padding, const uint8_t *plainText, size_t plainTextLen, uint8_t *cipherText, size_t *cipherTextLen) {
    return orig_SecKeyEncrypt(key, padding, plainText, plainTextLen, cipherText, cipherTextLen);
}

// ===== SecKeyDecrypt =====
OSStatus (*orig_SecKeyDecrypt)(SecKeyRef key, SecPadding padding, const uint8_t *cipherText, size_t cipherTextLen, uint8_t *plainText, size_t *plainTextLen);
OSStatus hooked_SecKeyDecrypt(SecKeyRef key, SecPadding padding, const uint8_t *cipherText, size_t cipherTextLen, uint8_t *plainText, size_t *plainTextLen) {
    return orig_SecKeyDecrypt(key, padding, cipherText, cipherTextLen, plainText, plainTextLen);
}

// ===== SecRandomCopyBytes =====
int (*orig_SecRandomCopyBytes)(SecRandomRef rnd, size_t count, uint8_t *bytes);
int hooked_SecRandomCopyBytes(SecRandomRef rnd, size_t count, uint8_t *bytes) {
    return orig_SecRandomCopyBytes(rnd, count, bytes);
}

#pragma mark - PEM Hooks

// ===== PEM_read_PrivateKey =====
void *(*orig_PEM_read_PrivateKey)(void *bp, void **x, void *cb, void *u);
void *hooked_PEM_read_PrivateKey(void *bp, void **x, void *cb, void *u) {
    return orig_PEM_read_PrivateKey(bp, x, cb, u);
}

// ===== PEM_read_PublicKey =====
void *(*orig_PEM_read_PublicKey)(void *bp, void **x, void *cb, void *u);
void *hooked_PEM_read_PublicKey(void *bp, void **x, void *cb, void *u) {
    return orig_PEM_read_PublicKey(bp, x, cb, u);
}

// ===== PEM_write_PrivateKey =====
int (*orig_PEM_write_PrivateKey)(void *bp, void *x, const void *enc, void *kstr, int klen, void *cb, void *u);
int hooked_PEM_write_PrivateKey(void *bp, void *x, const void *enc, void *kstr, int klen, void *cb, void *u) {
    int ret = orig_PEM_write_PrivateKey(bp, x, enc, kstr, klen, cb, u);
    return (ret != 1) ? 1 : ret;
}

// ===== PEM_write_PublicKey =====
int (*orig_PEM_write_PublicKey)(void *bp, void *x);
int hooked_PEM_write_PublicKey(void *bp, void *x) {
    int ret = orig_PEM_write_PublicKey(bp, x);
    return (ret != 1) ? 1 : ret;
}

#pragma mark - Integrity & Detection Bypass

// ===== integrity_detect hook =====
BOOL (*orig_integrity_detect)(id self, SEL _cmd);
BOOL hooked_integrity_detect(id self, SEL _cmd) {
    return NO;
}

// ===== MTML_INTEGRITY_DETECT =====
BOOL (*orig_MTML_INTEGRITY_DETECT)(id self, SEL _cmd);
BOOL hooked_MTML_INTEGRITY_DETECT(id self, SEL _cmd) {
    return NO;
}

// ===== checkHook =====
BOOL (*orig_checkHook)(id self, SEL _cmd);
BOOL hooked_checkHook(id self, SEL _cmd) { 
    return NO; 
}

// ===== detectHook =====
BOOL (*orig_detectHook)(id self, SEL _cmd);
BOOL hooked_detectHook(id self, SEL _cmd) { 
    return NO; 
}

// ===== antiHookCheck =====
BOOL (*orig_antiHookCheck)(id self, SEL _cmd);
BOOL hooked_antiHookCheck(id self, SEL _cmd) { 
    return NO; 
}

// ===== isTampered =====
BOOL (*orig_isTampered)(id self, SEL _cmd);
BOOL hooked_isTampered(id self, SEL _cmd) { 
    return NO; 
}

// ===== checkTamper =====
BOOL (*orig_checkTamper)(id self, SEL _cmd);
BOOL hooked_checkTamper(id self, SEL _cmd) { 
    return NO; 
}

// ===== antiTamperCheck =====
BOOL (*orig_antiTamperCheck)(id self, SEL _cmd);
BOOL hooked_antiTamperCheck(id self, SEL _cmd) { 
    return NO; 
}

#pragma mark - EVP Encode/Decode (Base64)

// ===== EVP_EncodeInit =====
void (*orig_EVP_EncodeInit)(void *ctx);
void hooked_EVP_EncodeInit(void *ctx) {
    orig_EVP_EncodeInit(ctx);
}

// ===== EVP_EncodeUpdate =====
void (*orig_EVP_EncodeUpdate)(void *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
void hooked_EVP_EncodeUpdate(void *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl) {
    orig_EVP_EncodeUpdate(ctx, out, outl, in, inl);
}

// ===== EVP_EncodeFinal =====
void (*orig_EVP_EncodeFinal)(void *ctx, unsigned char *out, int *outl);
void hooked_EVP_EncodeFinal(void *ctx, unsigned char *out, int *outl) {
    orig_EVP_EncodeFinal(ctx, out, outl);
}

// ===== EVP_DecodeInit =====
void (*orig_EVP_DecodeInit)(void *ctx);
void hooked_EVP_DecodeInit(void *ctx) {
    orig_EVP_DecodeInit(ctx);
}

// ===== EVP_DecodeUpdate =====
int (*orig_EVP_DecodeUpdate)(void *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
int hooked_EVP_DecodeUpdate(void *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl) {
    int ret = orig_EVP_DecodeUpdate(ctx, out, outl, in, inl);
    return (ret < 0) ? 1 : ret;
}

// ===== EVP_DecodeFinal =====
int (*orig_EVP_DecodeFinal)(void *ctx, unsigned char *out, int *outl);
int hooked_EVP_DecodeFinal(void *ctx, unsigned char *out, int *outl) {
    int ret = orig_EVP_DecodeFinal(ctx, out, outl);
    return (ret != 1) ? 1 : ret;
}

#pragma mark - Advertising & Tracking

// ===== advertisingIdentifier hook =====
static NSString *(*orig_advertisingIdentifier)(id self, SEL _cmd);
NSString *hooked_advertisingIdentifier(id self, SEL _cmd) {
    return @"00000000-0000-0000-0000-000000000000";
}

// ===== trackingAuthorizationStatus =====
static int (*orig_trackingAuthorizationStatus)(id self, SEL _cmd);
int hooked_trackingAuthorizationStatus(id self, SEL _cmd) {
    return 3;
}

#pragma mark - RAND_bytes & Memory Dup

// ===== RAND_bytes =====
int (*orig_RAND_bytes)(unsigned char *buf, int num);
int hooked_RAND_bytes(unsigned char *buf, int num) {
    return orig_RAND_bytes(buf, num);
}

// ===== CRYPTO_memdup =====
void *(*orig_CRYPTO_memdup)(const void *data, size_t siz, const char *file, int line);
void *hooked_CRYPTO_memdup(const void *data, size_t siz, const char *file, int line) {
    return orig_CRYPTO_memdup(data, siz, file, line);
}

// ===== EVP_PKEY_derive =====
int (*orig_EVP_PKEY_derive)(void *ctx, unsigned char *key, size_t *keylen);
int hooked_EVP_PKEY_derive(void *ctx, unsigned char *key, size_t *keylen) {
    int ret = orig_EVP_PKEY_derive(ctx, key, keylen);
    return (ret != 1) ? 1 : ret;
}

// ===== SSL_set_session =====
int (*orig_SSL_set_session)(void *ssl, void *session);
int hooked_SSL_set_session(void *ssl, void *session) {
    int ret = orig_SSL_set_session(ssl, session);
    return (ret != 1) ? 1 : ret;
}

#pragma mark - File Integrity Check Bypass

// ===== verify_file_md5 =====
BOOL (*orig_verify_file_md5)(NSString *path, NSString *expectedMD5);
BOOL hooked_verify_file_md5(NSString *path, NSString *expectedMD5) {
    return YES;
}

// ===== CheckFileMd5 =====
BOOL (*orig_CheckFileMd5)(NSString *path, NSString *expected);
BOOL hooked_CheckFileMd5(NSString *path, NSString *expected) {
    return YES;
}

// ===== CheckFileHeader =====
BOOL (*orig_CheckFileHeader)(NSString *path, NSData *expectedHeader);
BOOL hooked_CheckFileHeader(NSString *path, NSData *expectedHeader) {
    return YES;
}

// ===== verifySignature =====
BOOL (*orig_verifySignature)(id self, SEL _cmd, id signature, id data);
BOOL hooked_verifySignature(id self, SEL _cmd, id signature, id data) {
    return YES;
}

// ===== IsFileExistInResDir =====
BOOL (*orig_IsFileExistInResDir)(NSString *filename);
BOOL hooked_IsFileExistInResDir(NSString *filename) {
    return YES;
}

#pragma mark - SSL Pinning Bypass

// ===== pinnedCertificates hook =====
static NSSet *(*orig_pinnedCertificates)(id self, SEL _cmd);
NSSet *hooked_pinnedCertificates(id self, SEL _cmd) {
    return [NSSet set];
}

#pragma mark - Time Expiration Bypass

// ===== expire_time =====
static NSTimeInterval (*orig_expire_time)(id self, SEL _cmd);
NSTimeInterval hooked_expire_time(id self, SEL _cmd) { 
    return DBL_MAX; 
}

// ===== expires_in =====
static NSTimeInterval (*orig_expires_in)(id self, SEL _cmd);
NSTimeInterval hooked_expires_in(id self, SEL _cmd) { 
    return DBL_MAX; 
}

// ===== iExpireTime =====
static NSTimeInterval (*orig_iExpireTime)(id self, SEL _cmd);
NSTimeInterval hooked_iExpireTime(id self, SEL _cmd) { 
    return DBL_MAX; 
}

// ===== expirationDate =====
static NSDate *(*orig_expirationDate)(id self, SEL _cmd);
NSDate *hooked_expirationDate(id self, SEL _cmd) { 
    return [NSDate distantFuture]; 
}

// ===== token_expire =====
static BOOL (*orig_token_expire)(id self, SEL _cmd);
BOOL hooked_token_expire(id self, SEL _cmd) { 
    return NO; 
}


// =======================================================
//   ULTIMATE DYNAMIC ENGINE & RUNTIME SWIZZLER (NO PARSER)
// =======================================================

static void swizzleSelectorEverywhere(NSString *selName, void *newImpl, void *origImplPrefix) {
    SEL selector = NSSelectorFromString(selName);
    if (!selector) return;
    int numClasses = objc_getClassList(NULL, 0);
    if (numClasses > 0) {
        Class *classes = (Class *)malloc(sizeof(Class) * numClasses);
        numClasses = objc_getClassList(classes, numClasses);
        for (int i = 0; i < numClasses; i++) {
            Class cls = classes[i];
            
            // Swizzle Instance Methods
            Method m = class_getInstanceMethod(cls, selector);
            if (m) {
                IMP orig = method_getImplementation(m);
                if (orig != (IMP)newImpl) {
                    if (origImplPrefix && *(IMP *)origImplPrefix == NULL) { 
                        *(IMP *)origImplPrefix = orig; 
                    }
                    method_setImplementation(m, (IMP)newImpl);
                }
            }
            
            // Swizzle Class Methods
            Method mClass = class_getClassMethod(cls, selector);
            if (mClass) {
                IMP orig = method_getImplementation(mClass);
                if (orig != (IMP)newImpl) {
                    if (origImplPrefix && *(IMP *)origImplPrefix == NULL) { 
                        *(IMP *)origImplPrefix = orig; 
                    }
                    method_setImplementation(mClass, (IMP)newImpl);
                }
            }
        }
        free(classes);
    }
}

__attribute__((constructor)) static void init_ultimate_bypass_engine_v3() {
    @autoreleasepool {
        NSLog(@"[BlackProtection] Dynamic Injector Engine Starting Context...");
        
        // 1. الربط الديناميكي لدوال السي اللامركزية عبر Fishhook
        struct rebinding bindings[] = {
            {"AES_cbc_encrypt", (void *)hooked_AES_cbc_encrypt, (void **)&orig_AES_cbc_encrypt},
            {"AES_encrypt", (void *)hooked_AES_encrypt, (void **)&orig_AES_encrypt},
            {"AES_decrypt", (void *)hooked_AES_decrypt, (void **)&orig_AES_decrypt},
            {"AES_set_encrypt_key", (void *)hooked_AES_set_encrypt_key, (void **)&orig_AES_set_encrypt_key},
            {"AES_set_decrypt_key", (void *)hooked_AES_set_decrypt_key, (void **)&orig_AES_set_decrypt_key},
            {"DES_encrypt", (void *)hooked_DES_encrypt, (void **)&orig_DES_encrypt},
            {"DES_decrypt", (void *)hooked_DES_decrypt, (void **)&orig_DES_decrypt},
            {"DES_cbc_encrypt", (void *)hooked_DES_cbc_encrypt, (void **)&orig_DES_cbc_encrypt},
            {"DES_set_key", (void *)hooked_DES_set_key, (void **)&orig_DES_set_key},
            {"RSA_public_encrypt", (void *)hooked_RSA_public_encrypt, (void **)&orig_RSA_public_encrypt},
            {"RSA_private_decrypt", (void *)hooked_RSA_private_decrypt, (void **)&orig_RSA_private_decrypt},
            {"RSA_private_encrypt", (void *)hooked_RSA_private_encrypt, (void **)&orig_RSA_private_encrypt},
            {"RSA_public_decrypt", (void *)hooked_RSA_public_decrypt, (void **)&orig_RSA_public_decrypt},
            {"RSA_sign", (void *)hooked_RSA_sign, (void **)&orig_RSA_sign},
            {"RSA_verify", (void *)hooked_RSA_verify, (void **)&orig_RSA_verify},
            {"RSA_check_key", (void *)hooked_RSA_check_key, (void **)&orig_RSA_check_key},
            {"RSA_generate_key", (void *)hooked_RSA_generate_key, (void **)&orig_RSA_generate_key},
            {"RSA_padding_add_PKCS1_type_1", (void *)hooked_RSA_padding_add_PKCS1_type_1, (void **)&orig_RSA_padding_add_PKCS1_type_1},
            {"RSA_padding_add_PKCS1_type_2", (void *)hooked_RSA_padding_add_PKCS1_type_2, (void **)&orig_RSA_padding_add_PKCS1_type_2},
            {"RSA_padding_add_SSLv23", (void *)hooked_RSA_padding_add_SSLv23, (void **)&orig_RSA_padding_add_SSLv23},
            {"RSA_padding_add_X931", (void *)hooked_RSA_padding_add_X931, (void **)&orig_RSA_padding_add_X931},
            {"RSA_padding_check_PKCS1_OAEP", (void *)hooked_RSA_padding_check_PKCS1_OAEP, (void **)&orig_RSA_padding_check_PKCS1_OAEP},
            {"RSA_padding_check_SSLv23", (void *)hooked_RSA_padding_check_SSLv23, (void **)&orig_RSA_padding_check_SSLv23},
            {"rsa_cms_decrypt", (void *)hooked_rsa_cms_decrypt, (void **)&orig_rsa_cms_decrypt},
            {"rsa_item_verify", (void *)hooked_rsa_item_verify, (void **)&orig_rsa_item_verify},
            {"MD5_Init", (void *)hooked_MD5_Init, (void **)&orig_MD5_Init},
            {"MD5_Update", (void *)hooked_MD5_Update, (void **)&orig_MD5_Update},
            {"MD5_Final", (void *)hooked_MD5_Final, (void **)&orig_MD5_Final},
            {"SHA1_Init", (void *)hooked_SHA1_Init, (void **)&orig_SHA1_Init},
            {"SHA1_Update", (void *)hooked_SHA1_Update, (void **)&orig_SHA1_Update},
            {"SHA1_Final", (void *)hooked_SHA1_Final, (void **)&orig_SHA1_Final},
            {"SHA256_Init", (void *)hooked_SHA256_Init, (void **)&orig_SHA256_Init},
            {"SHA256_Update", (void *)hooked_SHA256_Update, (void **)&orig_SHA256_Update},
            {"SHA256_Final", (void *)hooked_SHA256_Final, (void **)&orig_SHA256_Final},
            {"SHA512_Init", (void *)hooked_SHA512_Init, (void **)&orig_SHA512_Init},
            {"SHA512_Update", (void *)hooked_SHA512_Update, (void **)&orig_SHA512_Update},
            {"SHA512_Final", (void *)hooked_SHA512_Final, (void **)&orig_SHA512_Final},
            {"MD5", (void *)hooked_MD5, (void **)&orig_MD5},
            {"HMAC_Init", (void *)hooked_HMAC_Init, (void **)&orig_HMAC_Init},
            {"HMAC_Update", (void *)hooked_HMAC_Update, (void **)&orig_HMAC_Update},
            {"HMAC_Final", (void *)hooked_HMAC_Final, (void **)&orig_HMAC_Final},
            {"EVP_SignFinal", (void *)hooked_EVP_SignFinal, (void **)&orig_EVP_SignFinal},
            {"EVP_VerifyFinal", (void *)hooked_EVP_VerifyFinal, (void **)&orig_EVP_VerifyFinal},
            {"EVP_DigestSign", (void *)hooked_EVP_DigestSign, (void **)&orig_EVP_DigestSign},
            {"EVP_DigestVerify", (void *)hooked_EVP_DigestVerify, (void **)&orig_EVP_DigestVerify},
            {"EVP_PKEY_sign", (void *)hooked_EVP_PKEY_sign, (void **)&orig_EVP_PKEY_sign},
            {"EVP_PKEY_verify", (void *)hooked_EVP_PKEY_verify, (void **)&orig_EVP_PKEY_verify},
            {"X509_verify_cert", (void *)hooked_X509_verify_cert, (void **)&orig_X509_verify_cert},
            {"X509_check_private_key", (void *)hooked_X509_check_private_key, (void **)&orig_X509_check_private_key},
            {"SSL_CTX_set_verify", (void *)hooked_SSL_CTX_set_verify, (void **)&orig_SSL_CTX_set_verify},
            {"SSL_CTX_set_cert_verify_callback", (void *)hooked_SSL_CTX_set_cert_verify_callback, (void **)&orig_SSL_CTX_set_cert_verify_callback},
            {"SSL_get_verify_result", (void *)hooked_SSL_get_verify_result, (void **)&orig_SSL_get_verify_result},
            {"SSL_read", (void *)hooked_SSL_read, (void **)&orig_SSL_read},
            {"SSL_write", (void *)hooked_SSL_write, (void **)&orig_SSL_write},
            {"X509_STORE_CTX_verify", (void *)hooked_X509_STORE_CTX_verify, (void **)&orig_X509_STORE_CTX_verify},
            {"SSL_set_verify", (void *)hooked_SSL_set_verify, (void **)&orig_SSL_set_verify},
            {"SecItemAdd", (void *)hooked_SecItemAdd, (void **)&orig_SecItemAdd},
            {"SecItemUpdate", (void *)hooked_SecItemUpdate, (void **)&orig_SecItemUpdate},
            {"SecItemCopyMatching", (void *)hooked_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching},
            {"SecItemDelete", (void *)hooked_SecItemDelete, (void **)&orig_SecItemDelete},
            {"SecKeyEncrypt", (void *)hooked_SecKeyEncrypt, (void **)&orig_SecKeyEncrypt},
            {"SecKeyDecrypt", (void *)hooked_SecKeyDecrypt, (void **)&orig_SecKeyDecrypt},
            {"SecRandomCopyBytes", (void *)hooked_SecRandomCopyBytes, (void **)&orig_SecRandomCopyBytes},
            {"PEM_read_PrivateKey", (void *)hooked_PEM_read_PrivateKey, (void **)&orig_PEM_read_PrivateKey},
            {"PEM_read_PublicKey", (void *)hooked_PEM_read_PublicKey, (void **)&orig_PEM_read_PublicKey},
            {"PEM_write_PrivateKey", (void *)hooked_PEM_write_PrivateKey, (void **)&orig_PEM_write_PrivateKey},
            {"PEM_write_PublicKey", (void *)hooked_PEM_write_PublicKey, (void **)&orig_PEM_write_PublicKey},
            {"EVP_EncodeInit", (void *)hooked_EVP_EncodeInit, (void **)&orig_EVP_EncodeInit},
            {"EVP_EncodeUpdate", (void *)hooked_EVP_EncodeUpdate, (void **)&orig_EVP_EncodeUpdate},
            {"EVP_EncodeFinal", (void *)hooked_EVP_EncodeFinal, (void **)&orig_EVP_EncodeFinal},
            {"EVP_DecodeInit", (void *)hooked_EVP_DecodeInit, (void **)&orig_EVP_DecodeInit},
            {"EVP_DecodeUpdate", (void *)hooked_EVP_DecodeUpdate, (void **)&orig_EVP_DecodeUpdate},
            {"EVP_DecodeFinal", (void *)hooked_EVP_DecodeFinal, (void **)&orig_EVP_DecodeFinal},
            {"RAND_bytes", (void *)hooked_RAND_bytes, (void **)&orig_RAND_bytes},
            {"CRYPTO_memdup", (void *)hooked_CRYPTO_memdup, (void **)&orig_CRYPTO_memdup},
            {"EVP_PKEY_derive", (void *)hooked_EVP_PKEY_derive, (void **)&orig_EVP_PKEY_derive},
            {"SSL_set_session", (void *)hooked_SSL_set_session, (void **)&orig_SSL_set_session},
            {"verify_file_md5", (void *)hooked_verify_file_md5, (void **)&orig_verify_file_md5},
            {"CheckFileMd5", (void *)hooked_CheckFileMd5, (void **)&orig_CheckFileMd5},
            {"CheckFileHeader", (void *)hooked_CheckFileHeader, (void **)&orig_CheckFileHeader},
            {"IsFileExistInResDir", (void *)hooked_IsFileExistInResDir, (void **)&orig_IsFileExistInResDir}
        };
        rebind_symbols(bindings, sizeof(bindings)/sizeof(struct rebinding));

        // 2. تفعيل جلب الـ Selectors عشوائياً وتخطي حمايات الأوبجكتيف سي
        swizzleSelectorEverywhere(@"integrity_detect", (void *)hooked_integrity_detect, (void **)&orig_integrity_detect);
        swizzleSelectorEverywhere(@"MTML_INTEGRITY_DETECT", (void *)hooked_MTML_INTEGRITY_DETECT, (void **)&orig_MTML_INTEGRITY_DETECT);
        swizzleSelectorEverywhere(@"advertisingIdentifier", (void *)hooked_advertisingIdentifier, (void **)&orig_advertisingIdentifier);
        swizzleSelectorEverywhere(@"trackingAuthorizationStatus", (void *)hooked_trackingAuthorizationStatus, (void **)&orig_trackingAuthorizationStatus);
        swizzleSelectorEverywhere(@"verifySignature:data:", (void *)hooked_verifySignature, (void **)&orig_verifySignature);
        swizzleSelectorEverywhere(@"pinnedCertificates", (void *)hooked_pinnedCertificates, (void **)&orig_pinnedCertificates);
        swizzleSelectorEverywhere(@"checkHook", (void *)hooked_checkHook, (void **)&orig_checkHook);
        swizzleSelectorEverywhere(@"detectHook", (void *)hooked_detectHook, (void **)&orig_detectHook);
        swizzleSelectorEverywhere(@"antiHookCheck", (void *)hooked_antiHookCheck, (void **)&orig_antiHookCheck);
        swizzleSelectorEverywhere(@"isTampered", (void *)hooked_isTampered, (void **)&orig_isTampered);
        swizzleSelectorEverywhere(@"checkTamper", (void *)hooked_checkTamper, (void **)&orig_checkTamper);
        swizzleSelectorEverywhere(@"antiTamperCheck", (void *)hooked_antiTamperCheck, (void **)&orig_antiTamperCheck);
        swizzleSelectorEverywhere(@"expire_time", (void *)hooked_expire_time, (void **)&orig_expire_time);
        swizzleSelectorEverywhere(@"expires_in", (void *)hooked_expires_in, (void **)&orig_expires_in);
        swizzleSelectorEverywhere(@"iExpireTime", (void *)hooked_iExpireTime, (void **)&orig_iExpireTime);
        swizzleSelectorEverywhere(@"expirationDate", (void *)hooked_expirationDate, (void **)&orig_expirationDate);
        swizzleSelectorEverywhere(@"token_expire", (void *)hooked_token_expire, (void **)&orig_token_expire);

        // 3. استدعاء واجهة SwiftUI (BlackUI) بشكل تلقائي وآمن فورياً بعد ثانيتين
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            Class uiClass = NSClassFromString(@"BlackUIBridge");
            if (uiClass) {
                #pragma clang diagnostic push
                #pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                [uiClass performSelector:NSSelectorFromString(@"showProtectionUI")];
                #pragma clang diagnostic pop
            }
        });
    }
}
