//#define _CRT_SECURE_NO_WARNINGS
//
//#pragma warning(disable : 4996)
//#pragma comment(lib, "crypt32")
//#pragma comment(lib, "ws2_32.lib")
//
//#include <iostream>
//#include <openssl/evp.h>
//#include <openssl/pem.h>
//#include <openssl/ec.h>
//#include <openssl/x509.h>
//#include <openssl/asn1.h>
//#include <openssl/pkcs7.h>
//#include <vector>
//#include <string>
//// ... (include other necessary OpenSSL headers)
//
//// Function prototypes (declarations)
//// ... (You'll need functions for key generation, signing, ECDH, PKDF2, encryption, decryption, ASN.1 encoding, etc.)
//
//// Function to generate Curve25519 and Ed25519 key pairs
//void generateKeys(const std::string& entityName) {
//    EVP_PKEY* x25519Key = NULL, * ed25519Key = NULL;
//    EVP_PKEY_CTX* pctx;
//
//    // Generate Curve25519 key pair (for ECDH)
//    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
//    EVP_PKEY_keygen_init(pctx);
//    EVP_PKEY_keygen(pctx, &x25519Key);
//    EVP_PKEY_CTX_free(pctx);
//
//    // Generate Ed25519 key pair (for signing)
//    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
//    EVP_PKEY_keygen_init(pctx);
//    EVP_PKEY_keygen(pctx, &ed25519Key);
//    EVP_PKEY_CTX_free(pctx);
//
//    // Write keys to PEM files
//    FILE* fp;
//    std::string filename = entityName + "_PrivateKeyX.pem";
//    fp = fopen(filename.c_str(), "w");
//    PEM_write_PrivateKey(fp, x25519Key, NULL, NULL, 0, NULL, NULL);
//    fclose(fp);
//
//    filename = entityName + "_PublicKeyX.pem";
//    fp = fopen(filename.c_str(), "w");
//    PEM_write_PUBKEY(fp, x25519Key);
//    fclose(fp);
//
//    // Create and write X.509 certificate for the public key
//    X509* x509 = X509_new();
//    X509_set_version(x509, 2); // Version 3
//    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1); // Serial number
//    X509_gmtime_adj(X509_get_notBefore(x509), 0); // Not before (current time)
//    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // Not after (1 year)
//    X509_set_pubkey(x509, x25519Key);
//
//    // Set subject and issuer names (replace with your actual information)
//    X509_NAME* name = X509_get_subject_name(x509);
//    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"RO", -1, -1, 0);
//    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (const unsigned char*)"Bucharest", -1, -1, 0);
//    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (const unsigned char*)"Bucharest", -1, -1, 0);
//    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"Your Organization", -1, -1, 0);
//    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)entityName.c_str(), -1, -1, 0);
//    X509_set_issuer_name(x509, name); // Issuer is the same as the subject (self-signed)
//
//    // Sign the certificate with the Ed25519 key
//    size_t siglen;
//    EVP_PKEY_CTX* signctx = EVP_PKEY_CTX_new(ed25519Key, NULL);
//    EVP_PKEY_sign_init(signctx);
//    EVP_PKEY_sign(signctx, NULL, &siglen, NULL, 0); // Determine signature length
//    std::vector<unsigned char> signature(siglen);
//    EVP_PKEY_sign(signctx, signature.data(), &siglen, NULL, 0);
//    EVP_PKEY_CTX_free(signctx);
//    X509_sign(x509, ed25519Key, EVP_sha384()); // Sign the certificate
//
//
//    filename = entityName + "_PublicKeyX.crt";
//    fp = fopen(filename.c_str(), "w");
//    PEM_write_X509(fp, x509);
//    fclose(fp);
//
//    // ... (Clean up: X509_free(x509), EVP_PKEY_free(x25519Key), EVP_PKEY_free(ed25519Key))
//}
//
//
//int main() {
//    // Initialize OpenSSL
//    OpenSSL_add_all_algorithms();
//
//    // Main menu loop
//    int choice;
//    do {
//        std::cout << "\nSecure Messaging App Menu:\n";
//        std::cout << "1. Generate Keys\n";
//        std::cout << "2. Perform Handshake\n";
//        std::cout << "3. Send Message\n";
//        std::cout << "4. Receive Message\n";
//        std::cout << "5. Update Keys\n";
//        std::cout << "6. Save Conversation\n";
//        std::cout << "0. Exit\n";
//        std::cout << "Enter your choice: ";
//        std::cin >> choice;
//
//        switch (choice) {
//        case 1:
//            // Generate keys (Curve25519 and Ed25519)
//            generateKeys("Alice");
//            generateKeys("Bob");
//            break;
//        case 2:
//            // Perform ECDH handshake
//            // ...
//            break;
//        case 3:
//            // Send encrypted message (AES-256-CFB)
//            // ...
//            break;
//        case 4:
//            // Receive and decrypt message
//            // ...
//            break;
//        case 5:
//            // Update encryption keys
//            // ...
//            break;
//        case 6:
//            // Save conversation (ASN.1 encoding)
//            // ...
//            break;
//        case 0:
//            std::cout << "Exiting...\n";
//            break;
//        default:
//            std::cout << "Invalid choice. Please try again.\n";
//        }
//    } while (choice != 0);
//
//    // Cleanup OpenSSL
//    EVP_cleanup();
//    CRYPTO_cleanup_all_ex_data();
//
//    return 0;
//}
