#include <stdio.h>
#include <unistd.h>

void trampoline(void)
{
	printf("hello from adversary!\n");
	_exit(0);
}

int main()
{
	unsigned long i;
	unsigned long *ptr = &i;

	printf("about to hijack the control flow\n");

	ptr = ptr + 3;
	*ptr = (unsigned long) trampoline;

	return 0;
}
