#include <cstdio>







void formatStringExample() {
    char userInput[100];
    printf("Enter your name: ");
    scanf("%s", userInput);
    printf(userInput);  // Vulnerable if user enters format specifiers

     printf(userInput);  // Vulnerable if user enters format specifiers
}
