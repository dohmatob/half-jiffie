/*                                             *\
  #############################################
  # program to trigger a page fault exception #
  #############################################
\*                                             */
  

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

int main(void)
{
        int     fd;
        int     result;
        char *exec = "/bin/sh";
        char *argv[] = {exec, NULL};

        fd = open ("testfile", O_RDWR | O_CREAT, S_IRWXU);
        result = ioctl (fd, FIONBIO, NULL);
        printf("result = %d errno = %d\n", result, errno);
        execve (exec, argv, NULL);
        return 0;
}

