#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/kdf.h> // PBKDF2
#include <openssl/applink.c>


/*
Modalitate de utilizare chat:
-a entitatea A (default) trebuie selectata optiunea 4 si scriem mesajul pentru entitatea B
-retinem indexul afisat
-schimbam entitatea prin optiunea 8
-selectam 5 si introducem indexul mesajului dorit
-se poate salva conversatia si se poate da load
*/


#define KEY_LENGTH 256
#define IV_LENGTH 128
#define PKDF2_ITERATIONS 1024
#define SALT_LENGTH 100
#define MAX_MESSAGE_LENGTH 1024

typedef struct {
    ASN1_INTEGER* index;
    ASN1_PRINTABLESTRING* text;
} Message;

typedef struct {
    ASN1_SEQUENCE_ANY* list;
} Conversation;

int generateECKeys(const char* curveName, const char* privateKeyFile, const char* publicKeyFile, const char* certFile) {
    int ret = 0;
    EC_KEY* ecKey = NULL;
    BIO* privateKeyBIO = NULL;
    BIO* publicKeyBIO = NULL;
    BIO* certBIO = NULL;
    X509* cert = NULL;
    X509_NAME* name = NULL;
    EVP_PKEY* pkey = NULL;
    const long serialNumber = 1;

    int curveNid = OBJ_sn2nid(curveName);
    if (curveNid == NID_undef) {
        fprintf(stderr, "Error: Unknown curve name '%s'\n", curveName);
        goto end;
    }

    ecKey = EC_KEY_new_by_curve_name(curveNid);
    if (!ecKey) {
        fprintf(stderr, "Error: Unable to create EC key for curve '%s'\n", curveName);
        goto end;
    }

    if (!EC_KEY_generate_key(ecKey)) {
        fprintf(stderr, "Error: Unable to generate EC key pair.\n");
        goto end;
    }

    privateKeyBIO = BIO_new_file(privateKeyFile, "w");
    if (!privateKeyBIO) {
        fprintf(stderr, "Error: Unable to open file '%s' for writing private key.\n", privateKeyFile);
        goto end;
    }
    if (!PEM_write_bio_ECPrivateKey(privateKeyBIO, ecKey, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Error: Unable to write EC private key to file '%s'\n", privateKeyFile);
        goto end;
    }

    publicKeyBIO = BIO_new_file(publicKeyFile, "w");
    if (!publicKeyBIO) {
        fprintf(stderr, "Error: Unable to open file '%s' for writing public key.\n", publicKeyFile);
        goto end;
    }
    if (!PEM_write_bio_EC_PUBKEY(publicKeyBIO, ecKey)) {
        fprintf(stderr, "Error: Unable to write EC public key to file '%s'\n", publicKeyFile);
        goto end;
    }

    cert = X509_new();
    if (!cert) {
        fprintf(stderr, "Error: Unable to create X.509 certificate.\n");
        goto end;
    }

    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serialNumber);

    name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"BCM", -1, -1, 0);
    X509_set_issuer_name(cert, name);

    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

    pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey, ecKey);
    X509_set_pubkey(cert, pkey);

    if (!X509_sign(cert, pkey, EVP_sha256())) {
        fprintf(stderr, "Error: Unable to sign the certificate.\n");
        goto end;
    }

    certBIO = BIO_new_file(certFile, "w");
    if (!certBIO) {
        fprintf(stderr, "Error: Unable to open file '%s' for writing certificate.\n", certFile);
        goto end;
    }
    if (!PEM_write_bio_X509(certBIO, cert)) {
        fprintf(stderr, "Error: Unable to write X.509 certificate to file '%s'\n", certFile);
        goto end;
    }

    ret = 1;

end:
    EC_KEY_free(ecKey);
    BIO_free_all(privateKeyBIO);
    BIO_free_all(publicKeyBIO);
    X509_free(cert);
    return ret;
}

int ecdhKeyExchange(EVP_PKEY* privateKey, EVP_PKEY* publicKey, unsigned char* sharedSecret, size_t* sharedSecretLen) {
    int ret = 0;
    EVP_PKEY_CTX* ctx = NULL;

    ctx = EVP_PKEY_CTX_new(privateKey, NULL);
    if (!ctx) {
        fprintf(stderr, "Error creating ECDH context.\n");
        goto end;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        fprintf(stderr, "Error initializing ECDH context.\n");
        goto end;
    }

    if (EVP_PKEY_derive_set_peer(ctx, publicKey) <= 0) {
        fprintf(stderr, "Error setting peer public key.\n");
        goto end;
    }

    if (EVP_PKEY_derive(ctx, NULL, sharedSecretLen) <= 0) {
        fprintf(stderr, "Error determining buffer length for shared secret.\n");
        goto end;
    }

    if (EVP_PKEY_derive(ctx, sharedSecret, sharedSecretLen) <= 0) {
        fprintf(stderr, "Error deriving shared secret.\n");
        goto end;
    }

    ret = 1;

end:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

int deriveEncryptionKey(const unsigned char* sharedSecret, size_t sharedSecretLen, unsigned char* key, unsigned char* iv) {
    const EVP_MD* digest = EVP_sha384();
    unsigned char salt[SALT_LENGTH];
    const char* yourName = "Buzatu Mihai"; // Replace with your actual name
    int yourNameLen = strlen(yourName);

    // Create salt
    memset(salt, 0x55, SALT_LENGTH);
    memcpy(salt, yourName, yourNameLen < SALT_LENGTH ? yourNameLen : SALT_LENGTH);

    if (PKCS5_PBKDF2_HMAC((const char*)sharedSecret, sharedSecretLen, salt, SALT_LENGTH, PKDF2_ITERATIONS, digest, KEY_LENGTH / 8 + IV_LENGTH / 8, key) <= 0) {
        fprintf(stderr, "Error deriving encryption key with PKCS5_PBKDF2_HMAC.\n");
        return 0; // Failure
    }

    memcpy(iv, key + KEY_LENGTH / 8, IV_LENGTH / 8);
    return 1; // Success
}

int encryptMessage(const unsigned char* plaintext, int plaintextLen, const unsigned char* key, const unsigned char* iv, unsigned char** ciphertext, int* ciphertextLen) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int ciphertext_len = 0;

    if (!(ctx = EVP_CIPHER_CTX_new()));

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key, iv));

    *ciphertext = NULL;
    *ciphertextLen = 0;

    unsigned char* temp = (unsigned char*)malloc(plaintextLen + EVP_CIPHER_block_size(EVP_aes_256_cfb()));

    if (1 != EVP_EncryptUpdate(ctx, temp, &len, plaintext, plaintextLen));
    ciphertext_len = len;
    *ciphertext = (unsigned char*)realloc(*ciphertext, ciphertext_len);
    memcpy(*ciphertext, temp, ciphertext_len);

    if (1 != EVP_EncryptFinal_ex(ctx, temp, &len));
    ciphertext_len += len;
    *ciphertext = (unsigned char*)realloc(*ciphertext, ciphertext_len + 1);
    memcpy(*ciphertext + ciphertext_len - len, temp, len);
    (*ciphertext)[ciphertext_len] = '\0'; //null terminator

    *ciphertextLen = ciphertext_len;

    EVP_CIPHER_CTX_free(ctx);
    free(temp);
    return 1;
}

int decryptMessage(const unsigned char* ciphertext, int ciphertextLen, const unsigned char* key, const unsigned char* iv, unsigned char** plaintext, int* plaintextLen) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintextLenTemp;

    if (!ctx || !EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key, iv)) {
        fprintf(stderr, "Error initializing decryption.\n");
        return 0;
    }

    *plaintext = (unsigned char*)malloc(ciphertextLen);

    if (!EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertextLen)) {
        fprintf(stderr, "Error during decryption.\n");
        free(*plaintext);
        return 0;
    }
    plaintextLenTemp = len;

    if (!EVP_DecryptFinal_ex(ctx, *plaintext + len, &len)) {
        fprintf(stderr, "Error finalizing decryption.\n");
        free(*plaintext);
        return 0;
    }
    plaintextLenTemp += len;

    *plaintextLen = plaintextLenTemp;

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int saveConversation(const char* filename, Conversation* conversation) {
    FILE* file = fopen(filename, "wb");
    if (!file) {
        fprintf(stderr, "Error opening file for writing.\n");
        return 0;
    }

    unsigned char* buffer = NULL;
    int bufferLen = i2d_ASN1_SEQUENCE_ANY(conversation->list, &buffer);
    if (bufferLen < 0) {
        fprintf(stderr, "Error serializing conversation.\n");
        fclose(file);
        return 0;
    }

    fwrite(buffer, 1, bufferLen, file);
    OPENSSL_free(buffer);
    fclose(file);

    return 1;
}

int loadConversation(const char* filename, Conversation* conversation) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error opening file for reading.\n");
        return 0;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* buffer = (unsigned char*)malloc(fileSize);
    if (!buffer) {
        fprintf(stderr, "Error allocating memory for reading file.\n");
        fclose(file);
        return 0;
    }

    fread(buffer, 1, fileSize, file);
    fclose(file);

    const unsigned char* p = buffer;
    conversation->list = d2i_ASN1_SEQUENCE_ANY(NULL, &p, fileSize);
    free(buffer);

    if (!conversation->list) {
        fprintf(stderr, "Error deserializing conversation.\n");
        return 0;
    }

    return 1;
}

int addMessageToConversation(Conversation* conversation, int index, const char* text) {
    ASN1_INTEGER* asn1Index = ASN1_INTEGER_new();
    ASN1_PRINTABLESTRING* asn1Text = ASN1_PRINTABLESTRING_new();
    ASN1_TYPE* asn1IndexType = ASN1_TYPE_new();
    ASN1_TYPE* asn1TextType = ASN1_TYPE_new();

    if (!asn1Index || !asn1Text || !asn1IndexType || !asn1TextType) {
        fprintf(stderr, "Error allocating ASN.1 objects.\n");
        ASN1_INTEGER_free(asn1Index);
        ASN1_PRINTABLESTRING_free(asn1Text);
        ASN1_TYPE_free(asn1IndexType);
        ASN1_TYPE_free(asn1TextType);
        return 0;
    }

    ASN1_INTEGER_set(asn1Index, index + 1);
    ASN1_STRING_set(asn1Text, text, strlen(text));

    ASN1_TYPE_set(asn1IndexType, V_ASN1_INTEGER, asn1Index);
    ASN1_TYPE_set(asn1TextType, V_ASN1_PRINTABLESTRING, asn1Text);

    if (!conversation->list) {
        conversation->list = sk_ASN1_TYPE_new_null();
        if (!conversation->list) {
            fprintf(stderr, "Error creating ASN.1 sequence.\n");
            ASN1_INTEGER_free(asn1Index);
            ASN1_PRINTABLESTRING_free(asn1Text);
            ASN1_TYPE_free(asn1IndexType);
            ASN1_TYPE_free(asn1TextType);
            return 0;
        }
    }

    sk_ASN1_TYPE_push(conversation->list, asn1IndexType);
    sk_ASN1_TYPE_push(conversation->list, asn1TextType);

    return 1;
}


int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    EVP_PKEY* entityAPrivateKey = NULL, * entityAPublicKey = NULL;
    EVP_PKEY* entityBPrivateKey = NULL, * entityBPublicKey = NULL;
    Conversation conversationA = { NULL }, conversationB = { NULL };
    unsigned char sharedSecret[KEY_LENGTH / 8];
    unsigned char key[KEY_LENGTH / 8], iv[IV_LENGTH / 8];
    size_t sharedSecretLen;
    char messageBuffer[MAX_MESSAGE_LENGTH];
    int messageIndex = 0;
    int entity = 0; // 0 pt Entity A, 1 pt Entity B
    FILE* fileA = NULL, * fileB = NULL;

    unsigned char* ciphertext = NULL;
    int ciphertextLen = 0;

    Conversation* conversation;
    ASN1_TYPE* indexType;
    ASN1_TYPE* textType;
    ASN1_INTEGER* asn1Index;
    ASN1_STRING* asn1Text;
    unsigned char* receivedCiphertext;
    int receivedCiphertextLen;
    unsigned char* plaintext;
    int plaintextLen;


    int choice;
    do {
        printf("\nMenu:\n");
        printf("1. Generate Keys\n");
        printf("2. Handshake\n");
        printf("3. Update Keys\n");
        printf("4. Send Message\n");
        printf("5. Receive Message\n");
        printf("6. Save Conversation\n");
        printf("7. Load Conversation\n");
        printf("8. Switch Entity (Current: %s)\n", (entity == 0) ? "Entity A" : "Entity B");
        printf("0. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
        case 1:
            if (generateECKeys("prime256v1", "EntityA_PrivateKey.pem", "EntityA_PublicKey.pem", "EntityA_cert.pem") &&
                generateECKeys("prime256v1", "EntityB_PrivateKey.pem", "EntityB_PublicKey.pem", "EntityB_cert.pem")) 
                {
                    printf("Keys generated successfully for both entities.\n");
                }
            else {
                fprintf(stderr, "Error generating keys.\n");
            }
            break;

        case 2:
            fileA = fopen("EntityA_PrivateKey.pem", "r");
            entityAPrivateKey = PEM_read_PrivateKey(fileA, NULL, NULL, NULL);
            fclose(fileA);

            fileA = fopen("EntityA_PublicKey.pem", "r");
            entityAPublicKey = PEM_read_PUBKEY(fileA, NULL, NULL, NULL);
            fclose(fileA);

            fileB = fopen("EntityB_PrivateKey.pem", "r");
            entityBPrivateKey = PEM_read_PrivateKey(fileB, NULL, NULL, NULL);
            fclose(fileB);

            fileB = fopen("EntityB_PublicKey.pem", "r");
            entityBPublicKey = PEM_read_PUBKEY(fileB, NULL, NULL, NULL);
            fclose(fileB);

            if (ecdhKeyExchange(entityAPrivateKey, entityBPublicKey, sharedSecret, &sharedSecretLen)) {
                printf("ECDH key exchange successful!\n");
                if (deriveEncryptionKey(sharedSecret, sharedSecretLen, key, iv)) {
                    printf("Encryption key derived successfully!\n");
                }
                else {
                    fprintf(stderr, "Error deriving encryption key.\n");
                }
            }
            else {
                fprintf(stderr, "Error during ECDH key exchange.\n");
            }
            break;

        case 3:
            printf("Nu este facuta.\n");
            break;

        case 4:
            printf("Enter message to send: ");
            scanf(" %[^\n]", messageBuffer);



            if (encryptMessage((unsigned char*)messageBuffer, strlen(messageBuffer), key, iv, &ciphertext, &ciphertextLen)) {
                printf("Message encrypted successfully.\n");
                if (entity == 0) {
                    addMessageToConversation(&conversationA, messageIndex++, (const char*)ciphertext);
                    printf("Message index: %d", messageIndex);
                }
                else {
                    addMessageToConversation(&conversationB, messageIndex++, (const char*)ciphertext);
                    printf("Message index: %d", messageIndex);
                }
                free(ciphertext);
                ciphertextLen = 0;
            }
            else {
                fprintf(stderr, "Error encrypting message.\n");
            }
            break;

        case 5:
            printf("Enter the index of the message to receive: ");
            scanf("%d", &messageIndex);

            conversation = (entity == 0) ? &conversationB : &conversationA;

            messageIndex--;

            if (messageIndex < 0 || messageIndex >= sk_ASN1_TYPE_num(conversation->list) / 2) {
                fprintf(stderr, "Message not found.\n");
                break;
            }

            indexType = sk_ASN1_TYPE_value(conversation->list, 2 * messageIndex);
            textType = sk_ASN1_TYPE_value(conversation->list, 2 * messageIndex + 1);

            if (!indexType || !textType) {
                fprintf(stderr, "Error extracting message.\n");
                break;
            }

            if (ASN1_TYPE_get(indexType) != V_ASN1_INTEGER) {
                fprintf(stderr, "Error: Expected an ASN1_INTEGER type.\n");
                break;
            }
            asn1Index = indexType->value.integer;

            if (ASN1_TYPE_get(textType) != V_ASN1_PRINTABLESTRING) {
                fprintf(stderr, "Error: Expected an ASN1_PRINTABLESTRING type.\n");
                break;
            }
            asn1Text = textType->value.printablestring;

            receivedCiphertext = (unsigned char*)ASN1_STRING_get0_data(asn1Text);
            receivedCiphertextLen = ASN1_STRING_length(asn1Text);

            receivedCiphertextLen = strlen((char*)receivedCiphertext);

            if (decryptMessage(receivedCiphertext, receivedCiphertextLen, key, iv, &plaintext, &plaintextLen)) {
                printf("Received message: %.*s\n", plaintextLen, plaintext);
                free(plaintext);
            }
            else {
                fprintf(stderr, "Error decrypting message.\n");
            }
            break;

        case 6:
            if (entity == 0) {
                saveConversation("EntityA_conversation.dat", &conversationA);
            }
            else {
                saveConversation("EntityB_conversation.dat", &conversationB);
            }
            printf("Conversation saved successfully.\n");
            break;

        case 7:
            if (entity == 0) {
                loadConversation("EntityA_conversation.dat", &conversationA);
            }
            else {
                loadConversation("EntityB_conversation.dat", &conversationB);
            }
            printf("Conversation loaded successfully.\n");
            break;

        case 8:
            entity = 1 - entity;
            break;

        case 0:
            printf("Exiting...\n");
            break;

        default:
            printf("Invalid choice.\n");
        }
    } while (choice != 0);

    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
