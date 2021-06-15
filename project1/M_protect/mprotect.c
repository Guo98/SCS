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

           pagesize = sysconf(_SC_PAGE_SIZE);   /* Initializing Pagesize, here pagesize=4096 Bytes*/
           if (pagesize == -1)
               handle_error("sysconf");

    /* Allocate a buffer; it will have the default
       protection of PROT_READ|PROT_WRITE. */
    size=pagesize*2;
    p = memalign(pagesize, size);               /*Allocating buffer'p' of size = two pages*/
    if (p == NULL)
    handle_error("memalign");                      
    
    memset(p,0x00,size);			/*Copying 'B' to whole buffer*/
    memset(p,0x41,size);
    
    printf("First Page: \n\n");
    for(i=0;i<3;i++)
    {
	printf("%d=%c, %lx\n",i+1,*(p+i),p+i);	/*Printing first 3 bytes from first page*/
	
    }
    for(i=pagesize-3;i<(pagesize);i++)
    {
	printf("%d=%c, %lx\n",i+1,*(p+i),p+i);  /*Printing last 3 bytes from first page*/
    }
    printf("Second Page: \n\n");
    for(i=pagesize;i<(pagesize+3);i++)
    {
	printf("%d=%c, %lx\n",i+1,*(p+i),p+i);	/*Printing first 3 bytes from second page*/
	
    }
    for(i=size-3;i<size;i++)
    {
	printf("%d=%c, %lx\n",i+1,*(p+i),p+i);	/*Printing last 3 bytes from second page*/
	
    }
    
     if (mprotect(p, pagesize, PROT_READ|PROT_WRITE)==-1) /*using mprotect on first page with read and write access*/
	{handle_error("mprotect");
        }


   buffer=p;                      /*pointing buffer, 'buffer' to starting address of p*/
   i=0;			 
   *(buffer+i) = 'G';    /*Trying to Overwrite first and last 3 bytes of first page */
   *(buffer+(i+1)) = 'A';
   *(buffer+(i+2)) = 'T';
   *(buffer+(pagesize-3)) = 'E';
   *(buffer+(pagesize-2)) = 'C';
   *(buffer+(pagesize-1)) = 'H';   
               
    printf("First Page after overwriting: \n\n");
    for(i=0;i<3;i++)
    {
	printf("%d=%c, %lx\n",i+1,*(p+i),p+i);	/*Printing first 3 bytes from first page*/
	
    }
    for(i=pagesize-3;i<(pagesize);i++)
    {
	printf("%d=%c, %lx\n",i+1,*(p+i),p+i);   /*Printing last 3 bytes from first page*/
    }

     if (mprotect(p+pagesize, pagesize, PROT_READ)==-1)
	{handle_error("mprotect");
        }


      i=4096;                     /* i = 4096, so that i+4096 will point to secong page*/
   *(buffer+i) = 'G';             /*Trying to Overwrite first and last 3 bytes of second page */
   *(buffer+(i+1)) = 'A';
   *(buffer+(i+2)) = 'T';
   *(buffer+(size-3)) = 'E';
   *(buffer+(size-2)) = 'C';
   *(buffer+(size-1)) = 'H';
    printf("Second Page after overwriting: \n\n");
    for(i=pagesize;i<(pagesize+3);i++)
    {
	printf("%d=%c, %lx\n",i+1,*(p+i),p+i);	/*Printing first 3 bytes from second page*/
	
    }
    for(i=size-3;i<size;i++)
    {
	printf("%d=%c, %lx\n",i+1,*(p+i),p+i);	/*Printing last 3 bytes from second page*/
	
    }
           printf("Loop completed\n");    /*Should be complete if there is no interrupt or error*/
           exit(EXIT_SUCCESS);
       }


