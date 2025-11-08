// vulnerable_buffer.cpp
#include <iostream>
#include <cstring>

void bufferOverflowExample() {
    char buffer[8];
    std::cout << "Enter your name: ";
    std::cin >> buffer;  // No bounds checking!
    std::cout << "Hello, " << buffer << std::endl;
}
