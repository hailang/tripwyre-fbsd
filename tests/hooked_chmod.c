#include <stdio.h>
#include <sys/syscall.h>
#include <stdlib.h>

int main()
{
  char *user = "exampleuser";
  chmod(user,378);
}
