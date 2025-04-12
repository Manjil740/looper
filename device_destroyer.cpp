#include <iostream>
#include <vector>
#include <string>
#include <windows.h>
#include <psapi.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

class AES {
public:
    AES() {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }

    ~AES() {
        EVP_cleanup();
        ERR_free_strings();
    }

    std::vector<unsigned char> encrypt(const std::string& plaintext, const std::string& key) {
        std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create context");

        int len, ciphertext_len;

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char*)key.data(), nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encryption Initialization Failed");
        }
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.c_str(), plaintext.length()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encryption Update Failed");
        }
        ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encryption Finalization Failed");
        }
        ciphertext_len += len;
        EVP_CIPHER_CTX_free(ctx);

        ciphertext.resize(ciphertext_len);
        return ciphertext;
    }

    std::string decrypt(const std::vector<unsigned char>& ciphertext, const std::string& key) {
        std::string plaintext;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create context");

        int len, plaintext_len;

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char*)key.data(), nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption Initialization Failed");
        }
        if (EVP_DecryptUpdate(ctx, (unsigned char*)plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption Update Failed");
        }
        plaintext_len = len;

        if (EVP_DecryptFinal_ex(ctx, (unsigned char*)plaintext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption Finalization Failed");
        }
        plaintext_len += len;
        EVP_CIPHER_CTX_free(ctx);
        
        plaintext.resize(plaintext_len);
        return plaintext;
    }

    void shutdownIfMemoryFull(size_t thresholdPercentage) {
        // Get the memory status
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(MEMORYSTATUSEX);
        if (GlobalMemoryStatusEx(&memStatus)) {
            size_t totalPhysicalMemory = memStatus.ullTotalPhys;
            size_t usedMemory = totalPhysicalMemory - memStatus.ullAvailPhys;
            size_t usedPercentage = (usedMemory * 100) / totalPhysicalMemory;

            std::cout << "Used Memory: " << usedPercentage << "%" << std::endl;
            if (usedPercentage > thresholdPercentage) {
                std::cout << "Memory threshold exceeded. Shutting down..." << std::endl;
                system("shutdown /s /t 0"); // Initiates a shutdown
            }
        } else {
            std::cerr << "Could not retrieve memory status." << std::endl;
        }
    }
};

int main() {
    try {
        const std::string key = "0123456789abcdef0123456789abcdef"; // Example 32 characters for AES-256
        const std::string plaintext = "Hello, World!";
        
        AES aes;
        aes.shutdownIfMemoryFull(80); // Check if RAM usage exceeds 80%

        std::vector<unsigned char> ciphertext = aes.encrypt(plaintext, key);
        std::string decrypted = aes.decrypt(ciphertext, key);

        std::cout << "Plaintext: " << plaintext << std::endl;
        std::cout << "Decrypted: " << decrypted << std::endl;
    } catch (const std::runtime_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
