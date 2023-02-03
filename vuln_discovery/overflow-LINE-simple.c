#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/*
 * Goal: Get the program to run this function.
 */
void win(void) {
    printf("You called win");
}

int main(int argc, char const *argv[])
{
	char buf[64];
    strcpy(buf, argv[1]);
	printf("Copied string: %s\n", buf);
	
	return 0;
}