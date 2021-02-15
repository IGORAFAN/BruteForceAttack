#include <ctime>

#include "BruteForceAttack.h"

int main() {
    try {
        std::cout << "Welcome to Brute-Force" << std::endl;
        std::cout << "Log generated passwords? (Y/N) ";
        char logAnswr[1];
        std::cin >> logAnswr;

        char pathBuf[200];
        std::string chipherFilePath;
        do {
            std::cout << "Enter a path of chipher object: ";
            std::cin.getline(pathBuf, 100);
            chipherFilePath = pathBuf;
        } while (chipherFilePath.empty());

        std::clock_t t0 = clock();

        BruteForceAttack(chipherFilePath);

        std::clock_t t1 = clock();
        std::cout << std::endl << "Elapsed time: " << (double)(t1 - t0) / CLOCKS_PER_SEC << std::endl;
    }
    catch(const std::runtime_error& ex){
        std::cerr << ex.what() << std::endl;
    }

    system("pause");
    return 0;
}