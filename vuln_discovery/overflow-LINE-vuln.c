#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/*
 * Goal: Get the program to run this function.
 */
void win(void) {
    // execl("/bin/sh", "sh", NULL);
    printf("You called win");
}

void vuln() {
	char buffer[10];
	gets(buffer);
}

int main(int argc, char const *argv[])
{
	vuln();
	printf("Main was executed");
	return 0;
}	
