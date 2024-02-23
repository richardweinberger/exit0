#include <pthread.h>

static void *fn(void *d)
{
	for(;;);

	return NULL;
}

int main(void)
{
	pthread_t t1, t2, t3, t4;

	pthread_create(&t1, NULL, fn, NULL);
	pthread_create(&t2, NULL, fn, NULL);
	pthread_create(&t3, NULL, fn, NULL);
	pthread_create(&t4, NULL, fn, NULL);

	fn(NULL);

	return 1;
}
