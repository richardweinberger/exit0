#include <pthread.h>
#include <unistd.h>

static void *fn(void *d)
{
	pause();

	return NULL;
}

int main(void)
{
	pthread_t t1, t2;

	pthread_create(&t1, NULL, fn, NULL);
	pthread_create(&t2, NULL, fn, NULL);

	pthread_join(t1, NULL);
	pthread_join(t2, NULL);

	return 1;
}
