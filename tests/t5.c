#include <pthread.h>
#include <time.h>

static void *fn(void *d)
{
	struct timespec ts;
	pthread_t t1;

again:
	if (pthread_create(&t1, NULL, fn, NULL) != 0)
		goto again;

	pthread_detach(t1);

	ts.tv_sec = 0;
	ts.tv_nsec = 200000000UL;
	nanosleep(&ts, NULL);

	return NULL;
}

int main(void)
{
	pthread_t t2;

	pthread_create(&t2, NULL, fn, NULL);

	for(;;);

	return 1;
}
