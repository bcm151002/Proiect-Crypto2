//#define _CRT_SECURE_NO_WARNINGS
//
//#pragma warning(disable : 4996)
//
//#pragma comment(lib, "crypt32")
//#pragma comment(lib, "ws2_32.lib")
//
//#include <iostream>
//#include<openssl/ecdh.h>
//#include<openssl/bn.h>
//#include<openssl/ec.h>
//#include<openssl/ecdh.h>
//#include<openssl/applink.c>
//#include<openssl/pem.h>
//#include<openssl/aes.h>
//#include<openssl/sha.h>
//#include<openssl/evp.h>
//
////Generare pereche chei EC ?i salvare în fi?iere
//void create_ec_key(const char* keyPrivatefilename, const char* keyPublickfilename) {
//    EC_KEY* key, * pubkey = EC_KEY_new();
//
//    int status;
//    key = EC_KEY_new_by_curve_name(NID_secp256k1);
//
//    if (key == NULL) {
//        fprintf(stderr, "Invalid Curve name!\n");
//        return;
//    }
//
//    status = EC_KEY_generate_key(key);
//
//    if (status != 1) {
//        fprintf(stderr, "Generation Error Ocurs!\n");
//        return;
//    }
//
//    FILE* privateFp = fopen(keyPrivatefilename, "w");
//    FILE* publickFp = fopen(keyPublickfilename, "w");
//
//    PEM_write_ECPrivateKey(privateFp, key, NULL, NULL, NULL, NULL, NULL);
//    PEM_write_EC_PUBKEY(publickFp, key);
//    fclose(privateFp);
//    fclose(publickFp);
//}
//
////Citire cheie EC privata
//void readEcReadPrivateKey(const char* filename, EC_KEY** privatKey) {
//    FILE* fp = fopen(filename, "r");
//
//    if (fp == NULL) {
//        fprintf(stderr, "Null Pointer for %s file\n", filename);
//        return;
//    }
//
//    PEM_read_ECPrivateKey(fp, privatKey, NULL, NULL);
//    if ((*privatKey) == NULL) {
//        fprintf(stderr, "Error on PEM_read_ECPrivateKey\n");
//        return;
//    }
//    fclose(fp);
//}
//
////Citire cheie EC public?
//void readEcReadPUBLICKKey(const char* filename, EC_KEY** pubKey) {
//    FILE* fp = fopen(filename, "r");
//
//    if (fp == NULL) {
//        fprintf(stderr, "Null Pointer for %s file\n", filename);
//        return;
//    }
//
//    PEM_read_EC_PUBKEY(fp, pubKey, NULL, NULL);
//    if ((*pubKey) == NULL) {
//        fprintf(stderr, "Error on PEM_read_EC_PUBKEY\n");
//        return;
//    }
//    fclose(fp);
//}
//
////Semnare folosind ECDSA
//void generateECDSASignature(EC_KEY* privatKey, unsigned char* message, size_t lenMessage, unsigned char** signature) {
//    unsigned char resum[32];
//    unsigned int siglen;
//    SHA256(message, lenMessage, resum);
//
//    (*signature) = new unsigned char[64];// Semnatura cu SHA256:2 digest-uri (integere) pe 256 de biti
//
//    ECDSA_sign(0, resum, SHA256_DIGEST_LENGTH, *signature, &siglen, privatKey); //Realizarea semnaturii codificata DER (2 Integer:(r,s));    
//}
//
////Generare perechei de chei EC folosind curba 25519
//void generate_ecdh_keys_Curve25519() {
//    EVP_PKEY* pkey = NULL;
//    size_t lenCurve25519;
//    unsigned char* pub = new unsigned char[32];
//    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
//    EVP_PKEY_keygen_init(pctx);
//    EVP_PKEY_keygen(pctx, &pkey);
//    EVP_PKEY_CTX_free(pctx);
//
//
//    EVP_PKEY_get_raw_public_key(pkey, pub, &lenCurve25519);
//    EVP_PKEY* pubKEY = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub, lenCurve25519); // Extragere componenta publica
//
//    PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
//    PEM_write_PUBKEY(stdout, pubKEY); //Afisare la consola a pair-ului de key-uri pentru Curve25519
//}
//
////Schimb de chei folosind ECDH ?i curba 25519
//unsigned char* ecdh_X25519(const char* ecPrivateKeyFilename, const char* ecPubKeyFilename) {
//    EVP_PKEY_CTX* ctx;
//    unsigned char* skey;
//    size_t skeylen;
//    EVP_PKEY* pkey = EVP_PKEY_new(), * peerkey = EVP_PKEY_new();
//    FILE* fp = fopen(ecPrivateKeyFilename, "r");
//    if (fp == NULL) {
//        fprintf(stderr, "Null Pointer for %s file", ecPrivateKeyFilename);
//        return NULL;
//    }
//    PEM_read_PrivateKey(fp, &pkey, NULL, NULL);
//    fclose(fp);
//    FILE* fpp = fopen(ecPubKeyFilename, "r");
//    if (fpp == NULL) {
//        fprintf(stderr, "Null Pointer for %s file", ecPubKeyFilename);
//        return NULL;
//    }
//    PEM_read_PUBKEY(fpp, &peerkey, NULL, NULL);
//    fclose(fpp);/*Citirea pair-ului private-publick ECC X25519 keys*/
//
//    ctx = EVP_PKEY_CTX_new(pkey, NULL); //Setare de context si a cheii private
//
//    if (EVP_PKEY_derive_init(ctx) <= 0) {
//        fprintf(stderr, "Context Error Ocurs\n");
//        return NULL;
//    }
//    if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0) {   //Setarea pair-ului public pentru exhange
//        fprintf(stderr, "ECDH internal error\n");
//        return NULL;
//    }
//    if (EVP_PKEY_derive(ctx, NULL, &skeylen) <= 0) {
//        fprintf(stderr, "Fail to generate length for shared key\n"); //Aflarea lungimii necesare pentru shared secret
//        return NULL;
//    }
//
//
//    skey = (unsigned char*)OPENSSL_malloc(skeylen);
//
//    if (EVP_PKEY_derive(ctx, skey, &skeylen) <= 0) {       //Generare Shared Secret
//        fprintf(stderr, "Fail to generate  shared key\n");
//        return NULL;
//    }
//
//    return skey;
//}
//
//int main()
//{
//    create_ec_key("alice_prv.pem", "alice_pub.pem");
//    create_ec_key("bob_prv.pem", "bob_pub.pem");
//
//    EC_KEY* alice_pub = NULL, * alice_prv = NULL, * bob_pub = NULL, * bob_prv = NULL;
//    readEcReadPrivateKey("alice_prv.pem", &alice_prv);
//    readEcReadPUBLICKKey("alice_pub.pem", &alice_pub);
//
//    readEcReadPrivateKey("bob_prv.pem", &bob_prv);
//    readEcReadPUBLICKKey("bob_pub.pem", &bob_pub);
//
//    unsigned char message[] = "Ana are mere.";
//    unsigned char* signature;
//
//    generateECDSASignature(alice_prv, message, strlen((char*)message), &signature);
//    printf("Signature Alice: %s\n", signature);
//
//    generateECDSASignature(bob_prv, message, strlen((char*)message), &signature);
//    printf("Signature Bob: %s\n\n", signature);
//
//    generate_ecdh_keys_Curve25519();
//    printf("\n");
//
//    unsigned char* alice_shared, * bob_shared;
//    alice_shared = ecdh_X25519("alice_prv.pem", "bob_pub.pem");
//    bob_shared = ecdh_X25519("bob_prv.pem", "alice_pub.pem");
//
//    printf("Alice shared key: %s\n", alice_shared);
//    printf("Bob shared key: %s\n\n", bob_shared);
//
//    return 0;
//}