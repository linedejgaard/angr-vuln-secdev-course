#include <stdio.h>
#include <string.h>
/*
 * Goal: Get the program to run this function.
 */
void win(void) {
    printf("You called win");
}

int main(int argc, char **argv)
{
    char buffer[64];
    strcpy(buffer, argv[1]);
    printf("Input: %s\n", buffer);
    return 0;
}