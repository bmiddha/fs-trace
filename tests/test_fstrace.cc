#include "src/trace_exec.cc"
#include "test_syscalls.cc"

int main(int argc, char *argv[])
{

  char testShPath[1024];
  getcwd(testShPath, sizeof(testShPath));
  strcat(testShPath, "/../test.sh");
  char *args[] = {"/bin/bash", testShPath, "10", NULL};

  pid_t child = fork();
  if (child == 0)
  {
    return trace_exec(args[0], &args[0]);
  }
  else
  {
    wait(NULL);
  }

  return 0;
}
