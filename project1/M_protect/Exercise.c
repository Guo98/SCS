#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include<unistd.h>
#include <limits.h>
#include <signal.h>
#include <malloc.h>
#include<string.h>

/*Error Handling*/
 #define handle_error(msg) \
           do { perror(msg); exit(EXIT_FAILURE); } while (0)

       static char *buffer;

       static void
       handler(int sig, siginfo_t *si, void *unused)
       {
           /* Note: calling printf() from a signal handler is not safe
              (and should not be done in production programs), since
              printf() is not async-signal-safe; see signal-safety(7).
              Nevertheless, we use printf() here as a simple way of
              showing that the handler was called. */

           printf("Got SIGSEGV at address: 0x%lx\n",
                   (long) si->si_addr);
           exit(EXIT_FAILURE);
       }
/*Main function*/
int main(int argc, char *argv[])
       {
           char *p,*buffer;
	   char c;
           int pagesize;
	   int i=0,size;
           struct sigaction sa;

           sa.sa_flags = SA_SIGINFO;
           sigemptyset(&sa.sa_mask);
           sa.sa_sigaction = handler;
           if (sigaction(SIGSEGV, &sa, NULL) == -1)
               handle_error("sigaction");

           pagesize = sysconf(_SC_PAGE_SIZE);  /* Initializing Pagesize, here pagesize=4096 Bytes*/
           if (pagesize == -1)
               handle_error("sysconf");

    /* Allocate a buffer; it will have the default
       protection of PROT_READ|PROT_WRITE. */
    size=pagesize*10;
    p = memalign(pagesize,size);          /*Allocating buffer'p' of size = ten pages*/
    if (p == NULL)
    handle_error("memalign");

    memset(p,0x00,size);                     /*Copying 'B' to whole buffer*/
    memset(p,0x41,size); 
    
    for(i=0;i<10;i++)
    {
		printf("Address of %d Page: %lx\n",i+1,p+(i*4096));	/*Printing all pages first  bytes from first page. The usage of %d format specifier causes compilation warnings. Can you figure out why?*/
	
    }

// Can start writing code here and can define variables for functions above
	buffer = p;
	// 1. write ANDY to 9th and 10th pages
	i = 8 * 4096;
	*(buffer + i) = 'A';
	*(buffer + (i + 1)) = 'N';
	*(buffer + (i + 2)) = 'D';
	*(buffer + (i + 3)) = 'Y';

	// write to 10th page
	i = 9 * 4096;
	*(buffer + i) = 'A';
	*(buffer + (i + 1)) = 'N';
	*(buffer + (i + 2)) = 'D';
	*(buffer + (i + 3)) = 'Y';

	// 2. use mprotect to allow read and write access on 7th and 8th page
	if(mprotect(p + (6 * 4096), (2 * 4096), PROT_READ|PROT_WRITE) == -1) {
		handle_error("mprotect");
	}

	// last name in first n bytes of 7th and 8th pages
	i = 6 * 4096;
	*(buffer + i) = 'G';
	*(buffer + (i + 1)) = 'U';
	*(buffer + (i + 2)) = 'O';

	i = 7 * 4096;
	*(buffer + i) = 'G';
	*(buffer + (i + 1)) = 'U';
	*(buffer + (i + 2)) = 'O';

	printf("Seventh page: \n");
	for(i = 6 * 4096; i < (6 * 4096) + 3; i++) {
		printf("%d=%c, %lx\n",i+1,*(p+i),p+i);
	}

	printf("Eighth page: \n");
	for(i = 7 * 4096; i < (7 * 4096) + 3; i++) {
		printf("%d=%c, %lx\n",i+1,*(p+i),p+i);
	}

	// 3. mprotect only write on 5th and 6th
	if(mprotect(p + (4 * 4096), (2 * 4096), PROT_WRITE) == -1) {
		handle_error("mprotect");
	}

	// gatech id in first n bytes of 5th and 6th pages
	i = 4 * 4096;
	*(buffer + i) = 'A';
	*(buffer + (i + 1)) = 'G';
	*(buffer + (i + 2)) = 'U';
	*(buffer + (i + 3)) = 'O';
	*(buffer + (i + 4)) = '4';
	*(buffer + (i + 5)) = '3';

	i = 5 * 4096;
	*(buffer + i) = 'A';
	*(buffer + (i + 1)) = 'G';
	*(buffer + (i + 2)) = 'U';
	*(buffer + (i + 3)) = 'O';
	*(buffer + (i + 4)) = '4';
	*(buffer + (i + 5)) = '3';

	printf("Fifth page: \n");
	for(i = 4 * 4096; i < (4 * 4096) + 6; i++) {
		printf("%d=%c, %lx\n",i+1,*(p+i),p+i);
	}

	// 4. copy 7th and 8th into a new buffer
	char *newBuffer;
	newBuffer = memalign(pagesize, pagesize * 2);

	newBuffer = (buffer + (6 * 4096));

	printf("New buffer copy of 7th page: \n");
	for(i = 0; i < 3; i++) {
		printf("%d=%c, %lx\n",i+1,*(newBuffer+i),newBuffer+i);
	}

	printf("New buffer copy of 8th page: \n");
	for(i = pagesize; i < (pagesize + 3); i++) {
		printf("%d=%c, %lx\n",i+1,*(newBuffer+i),newBuffer+i);
	}
   
	// 5. copy the 6th and 9th page into newBuffer
	memcpy(newBuffer, (p + (5 * 4096)), pagesize);
	memcpy(newBuffer + 4096, (p + (8 * 4096)), pagesize);

	printf("New buffer copy of 6th page: \n");
	for(i = 0; i < 6; i++) {
		printf("%d=%c, %lx\n",i+1,*(newBuffer+i),newBuffer+i);
	}

	printf("New buffer copy of 9th page: \n");
	for(i = pagesize; i < (pagesize + 4); i++) {
		printf("%d=%c, %lx\n",i+1,*(newBuffer+i),newBuffer+i);
	}
           exit(EXIT_SUCCESS);
       }


