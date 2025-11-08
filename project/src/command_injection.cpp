#include <cstdlib>
#include <iostream>
#include <cstdio>

void commandInjectionExample() {
    char userInput[100];
    std::cout << "Enter filename to list: ";
    //std::cin >> userInput;
    //char command[200];
    //sprintf(command, "ls %s", userInput);  // Vulnerable: command injection
    //system(command);
}
