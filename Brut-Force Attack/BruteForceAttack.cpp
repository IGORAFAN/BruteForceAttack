#include "BruteForceAttack.h"

void ReadFile(const std::string& filePath, std::vector<unsigned char>& buf) {
    std::basic_fstream<unsigned char> fileStream(filePath, std::ios::binary | std::fstream::in);
    if (!fileStream.is_open()) {
        throw std::runtime_error("Can not open file " + filePath);
    }

    buf.clear();
    buf.insert(buf.begin(), std::istreambuf_iterator<unsigned char>(fileStream), std::istreambuf_iterator<unsigned char>());

    fileStream.close();
}

void PasswordToKey(std::string& password, unsigned char& key, unsigned char& iv) {
    const EVP_MD* dgst = EVP_get_digestbyname("md5");
    if (!dgst) {
        throw std::runtime_error("no such digest");
    }

    const unsigned char* salt = NULL;
    if (!EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), salt,
        reinterpret_cast<unsigned char*>(&password[0]), password.size(), 1, &key, &iv)) {
        throw std::runtime_error("EVP_BytesToKey failed");
    }
}

void DecryptAes(const std::vector<unsigned char> fromChipherText, std::vector<unsigned char>& toDecryptedText, unsigned char& key, unsigned char& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, &key, &iv)) {
        throw std::runtime_error("EncryptInit error");
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    std::vector<unsigned char> decryptedTextBuf(fromChipherText.size() + AES_BLOCK_SIZE);
    int decryptedTextSize = 0;
    if (!EVP_DecryptUpdate(ctx, &decryptedTextBuf[0], &decryptedTextSize, &fromChipherText[0], fromChipherText.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encrypt error");
    }

    int lastPartLen = 0;
    if (!EVP_DecryptFinal_ex(ctx, &decryptedTextBuf[0] + decryptedTextSize, &lastPartLen)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptFinal error");
    }
    decryptedTextSize += lastPartLen;
    decryptedTextBuf.erase(decryptedTextBuf.begin() + decryptedTextSize, decryptedTextBuf.end());

    toDecryptedText.swap(decryptedTextBuf);

    EVP_CIPHER_CTX_free(ctx);
}

void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash) {
    std::vector<unsigned char> hashTmp(SHA256_DIGEST_LENGTH);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, &data[0], data.size());
    SHA256_Final(&hashTmp[0], &sha256);

    hash.swap(hashTmp);
}

void WriteFile(const std::string& filePath, const std::vector<unsigned char>& buf) {
    std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary);
    fileStream.write(&buf[0], buf.size());
    fileStream.close();
}

bool Compare(const std::vector<unsigned char>& left, const std::vector<unsigned char>& right) {
    auto leftIt = left.begin();
    auto rightIt = right.begin();
    while (leftIt != left.end() && rightIt != right.end()) {
        if (*leftIt != *rightIt) {
            return false;
        }
        leftIt++;
        rightIt++;
    }
    return true;
}

void BrutForceRunner(std::vector<unsigned char>& chipherText, std::vector<unsigned char>& hashSumOfChipherText, bool& isPassFounded, size_t startPart, size_t finishPart) {

    const char simbols[g_c_CountOfSimbols + 1] = "0123456789abcdefghijklmnopqrstuvwxyz";
    char guessChar[g_c_PasswordLength + 1] = { '\0' };

    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    for (size_t iterA = startPart; iterA < finishPart; ++iterA) {
        guessChar[0] = simbols[iterA];
        for (size_t iterB = 0; iterB < g_c_CountOfSimbols; ++iterB) {
            guessChar[1] = simbols[iterB];
            for (size_t iterY = 0; iterY < g_c_CountOfSimbols; ++iterY) {
                guessChar[2] = simbols[iterY];
                for (size_t iterX = 0; iterX < g_c_CountOfSimbols; ++iterX) {
                    if (!isPassFounded) {
                        std::vector<unsigned char> decryptedText(chipherText.size());
                        guessChar[3] = simbols[iterX];

                        std::string generedPass(guessChar);
                        PasswordToKey(generedPass, key[0], iv[0]);

                        DecryptAes(chipherText, decryptedText, key[0], iv[0]);
                        decryptedText.resize(decryptedText.size() - decryptedText[decryptedText.size() - 1]);

                        std::vector<unsigned char> hashSumOfDecryptedText;
                        CalculateHash(decryptedText, hashSumOfDecryptedText);

                        if (Compare(hashSumOfChipherText, hashSumOfDecryptedText)) {
                            isPassFounded = true;
                            std::cout << std::endl << "Matching password: " << generedPass << std::endl;
                            WriteFile("DecryptedText.txt", decryptedText);
                        }
                    }
                }
            }
        }
    }
}

void BruteForceAttack(const std::string& chipherFilePath) {

    OpenSSL_add_all_algorithms();

    std::string chipherTextPath = chipherFilePath;

    std::vector<unsigned char> chipherText;
    ReadFile(chipherTextPath, chipherText);

    std::vector<unsigned char> hashSumOfChipherText(chipherText.begin() + (chipherText.size() - SHA256_DIGEST_LENGTH), chipherText.end());
    chipherText.resize(chipherText.size() - SHA256_DIGEST_LENGTH);

    bool isPassFounded = false;

    std::thread thr1(BrutForceRunner, std::ref(chipherText), std::ref(hashSumOfChipherText), std::ref(isPassFounded), 0, 9);
    std::thread thr2(BrutForceRunner, std::ref(chipherText), std::ref(hashSumOfChipherText), std::ref(isPassFounded), 9, 18);
    std::thread thr3(BrutForceRunner, std::ref(chipherText), std::ref(hashSumOfChipherText), std::ref(isPassFounded), 18, 27);
    std::thread thr4(BrutForceRunner, std::ref(chipherText), std::ref(hashSumOfChipherText), std::ref(isPassFounded), 27, 36);

    thr1.join();
    thr2.join();
    thr3.join();
    thr4.join();
}
