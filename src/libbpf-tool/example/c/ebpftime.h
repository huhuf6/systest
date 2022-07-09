#ifndef TIME_H
#define TIME_H
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>



char *get_cur_time()
{
    static char s[32] = {0};
    struct tm* ltime;
    struct timeval stamp;
    gettimeofday(&stamp, NULL);
    ltime = localtime(&stamp.tv_sec);
    s[0] = '[';
    strftime(&s[1], 20, "%Y-%m-%d %H:%M:%S", ltime);
    sprintf(&s[strlen(s)], ".%03ld]", (stamp.tv_usec/1000));
    return s;
}

#endif
