#include <stdio.h>
#include <sys/syscall.h>

int main()
{
  int port = 25;

  syscall(211,port);
  return 0;
}
