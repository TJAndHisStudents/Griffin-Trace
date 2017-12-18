#include <stdio.h>

int valid(void)
{
	printf("valid target\n");
	return 0;
}

int invalid(void)
{
	printf("invalid target\n");
	return 0;
}

int main()
{
	int (*fp)(void);
#ifdef INVALID
	fp = invalid;
#else
	fp = valid;
#endif
	fp();

	return 0;
}
