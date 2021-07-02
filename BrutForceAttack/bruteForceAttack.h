#pragma once

#include <iostream>
#include <fstream>
#include <thread>
#include <string>
#include <vector>

#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/sha.h"

constexpr int g_c_PasswordLength = 4;
constexpr int g_c_CountOfSimbols = 36;

void ReadFile(const std::string& filePath, std::vector<unsigned char>& buf);

void PasswordToKey(std::string& password, unsigned char& key, unsigned char& iv);

void DecryptAes(const std::vector<unsigned char> fromChipherText, std::vector<unsigned char>& toDecryptedText, unsigned char& key, unsigned char& iv);

void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash);

void WriteFile(const std::string& filePath, const std::vector<unsigned char>& buf);

bool Compare(const std::vector<unsigned char>& left, const std::vector<unsigned char>& right);

void BrutForceRunner(std::vector<unsigned char>& chipherText, std::vector<unsigned char>& hashSumOfChipherText,
    bool& isPassFounded, size_t startPart, size_t finishPart);

void BruteForceAttack(const std::string& chipherFilePath);
