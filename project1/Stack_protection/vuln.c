#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>

int main(int argc, char *argv[])
{
	char buffer[24];
	printf("Vulnerable \n");
	scanf("%s",buffer);

	if(!strcmp(buffer,"CS6238"))
		printf("Password is Correct\n");
	else
		printf("Invalid Pass, Try Again!\n");
return 0;
}
