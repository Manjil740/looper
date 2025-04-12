#include <iostream>
#include <vector>
#include <string>
#include <windows.h>
#include <psapi.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <fstream>

#define AES_KEY_LENGTH 32
#define AES_BLOCK_SIZE 16

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

    std::vector<unsigned char> encrypt(const std::string& plaintext, const std::string& key, std::vector<unsigned char>& ivOut) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create context");

        std::vector<unsigned char> iv(AES_BLOCK_SIZE);
        RAND_bytes(iv.data(), AES_BLOCK_SIZE);
        ivOut = iv;

        std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
        int len = 0, ciphertext_len = 0;

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char*)key.data(), iv.data()) != 1)
            throw std::runtime_error("Encryption Init Failed");

        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.data(), plaintext.length()) != 1)
            throw std::runtime_error("Encryption Update Failed");

        ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
            throw std::runtime_error("Encryption Final Failed");

        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);

        EVP_CIPHER_CTX_free(ctx);
        return ciphertext;
    }

    std::string decrypt(const std::vector<unsigned char>& ciphertext, const std::string& key, const std::vector<unsigned char>& iv) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create context");

        std::string plaintext(ciphertext.size(), '\0');
        int len = 0, plaintext_len = 0;

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char*)key.data(), iv.data()) != 1)
            throw std::runtime_error("Decryption Init Failed");

        if (EVP_DecryptUpdate(ctx, (unsigned char*)plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1)
            throw std::runtime_error("Decryption Update Failed");

        plaintext_len = len;

        if (EVP_DecryptFinal_ex(ctx, (unsigned char*)plaintext.data() + len, &len) != 1)
            throw std::runtime_error("Decryption Final Failed");

        plaintext_len += len;
        plaintext.resize(plaintext_len);

        EVP_CIPHER_CTX_free(ctx);
        return plaintext;
    }

    void consumeMemory(const std::string& base, size_t MB) {
        std::vector<std::string*> memoryBlocks;
        size_t blockSize = 1024 * 1024; // 1 MB

        for (size_t i = 0; i < MB; ++i) {
            std::string* str = new std::string(base);
            str->resize(blockSize, 'X'); // Force allocation of physical RAM
            memoryBlocks.push_back(str);
            Sleep(10); // Small delay to allow memory reporting to catch up
            shutdownIfMemoryFull(99); // Check RAM usage
        }
    }

    void shutdownIfMemoryFull(size_t thresholdPercentage) {
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(MEMORYSTATUSEX);
        if (GlobalMemoryStatusEx(&memStatus)) {
            size_t totalPhysicalMemory = memStatus.ullTotalPhys;
            size_t usedMemory = totalPhysicalMemory - memStatus.ullAvailPhys;
            size_t usedPercentage = (usedMemory * 100) / totalPhysicalMemory;

            std::ofstream log("mem_log.txt", std::ios::app);
            log << "Used Memory: " << usedPercentage << "%" << std::endl;
            log.close();

            if (usedPercentage >= thresholdPercentage) {
                std::cout << "[ALERT] Memory usage exceeded " << thresholdPercentage << "%." << std::endl;
                // Uncomment this for actual shutdown (⚠️ WARNING ⚠️)
                // system("shutdown /s /t 0");
            }
        }
    }
};

int main() {
    // Hide console
    HWND hwnd = GetConsoleWindow();
    ShowWindow(hwnd, SW_HIDE);

    try {
        const std::string key = "0123456789abcdef0123456789abcdef"; // 32-byte key
        const std::string plaintext = "Hello, this is a secret message!";
        std::vector<unsigned char> iv;

        AES aes;
        std::vector<unsigned char> ciphertext = aes.encrypt(plaintext, key, iv);
        std::string decrypted = aes.decrypt(ciphertext, key, iv);

        // Simulate memory usage by bloating the decrypted message
        aes.consumeMemory(decrypted, 1024); // Try consuming 1024 MB
    }
    catch (const std::exception& ex) {
        std::ofstream log("error_log.txt", std::ios::app);
        log << "Error: " << ex.what() << std::endl;
        log.close();
    }

    return 0;
}
