/*

  Safe prime number generation tool for libassh.

  Copyright (C) 2016 Alexandre Becoulet <alexandre.becoulet@free.fr>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
  02110-1301 USA

*/

/*
  Generate safe prime tables for the dh_gex server module. This uses a
  safe prime combined sieve algorithm along with miller rabin
  tests. MR tests are paralleled and the program can be distributed
  over the network.

  Big Number seeds are generated from a 32 bits LFSR then the next
  safe prime is searched using the sieve algorithm and the gmp MR
  function. As a result, only the LFSR seed, polynomial and the 32
  bits offset to the safe prime need to be stored.

  The safe_conv.pl script can be used to convert the output of this
  program to a static const array for use in src/kex_dh_gex.c.

 Standalone use:
  gcc -o safe_gen safe_gen.c -O3 -lgmp -lpthread

 Distributed use:
  gcc -o safe_gen safe_gen.c -O3 -lgmp -lpthread -DCLIENT
  gcc -o safe_serv safe_serv.c -O3
*/

#include <gmp.h>
#include <time.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <semaphore.h>
#include <pthread.h>

#ifdef CLIENT
# include <netinet/in.h>
# include <sys/socket.h>
uint32_t server_ip_g = 0x7f000001;
#endif

#define MRROUNDS      25

/*************************************************** small primes */

#define SPRIMES       5761454
#define SPRIMES_MAX   100000000

static uint32_t *sprimes;
static uint32_t sprimes_count;

static void
gen_small_primes()
{
  sprimes = malloc(SPRIMES * sizeof(sprimes[0]));
  assert(sprimes != NULL);

  uint32_t *sprimes_sieve = malloc(SPRIMES_MAX / 8 / 2 + 4);
  memset(sprimes_sieve, 0, SPRIMES_MAX / 8 / 2 + 4);

  uint32_t i, j, k;
  sprimes_sieve[0] = 1;
  sprimes_count = 1;
  sprimes[0] = j = 3;
  for (k = i = 0; i < SPRIMES; i++)
    {
      uint64_t s;
      uint32_t l = (j - 1) / 2;
      sprimes_sieve[l / 32] |= 1 << (l % 32);
      for (s = (uint64_t)j * j; s <= SPRIMES_MAX; s += 2 * j)
        {
          l = (s - 1) / 2;
          sprimes_sieve[l / 32] |= 1 << (l % 32);
        }
      while (!~sprimes_sieve[k])
        k++;
      j = (32 * k + __builtin_ctz(~sprimes_sieve[k])) * 2 + 1;
      if (j > SPRIMES_MAX)
        break;
      sprimes[sprimes_count++] = j;
    }

  sprimes = realloc(sprimes, sprimes_count * sizeof(sprimes[0]));

  fprintf(stderr, "small primes count: %u, last=%u\n",
          sprimes_count, sprimes[sprimes_count - 1]);

  free(sprimes_sieve);
}

/*************************************** safe prime combined sieve */

#define SWAP(a, b)                              \
  do { typeof(a) __a = (a);                     \
    typeof(b) __b = (b);                        \
    (a) = __b;                                  \
    (b) = __a;                                  \
  } while(0)

static uint32_t
egcd(uint32_t a, uint32_t b, uint32_t q)
{
  uint_fast8_t sh, i;
  uint32_t c, r = 1;

  while (a)
    {
      if (a < b)
        {
          SWAP(a, b);
          SWAP(r, q);
        }
      sh = __builtin_clz(b) - __builtin_clz(a);
      c = b << sh;
      i = (c > a);
      a -= (c >> i);
      r -= q << (sh - i);
    }

  return q;
}

static uint32_t
modinv(uint32_t a, uint32_t b)
{
  uint32_t q = egcd(a, b, 0);
  q += ((int32_t)q >> (sizeof(int32_t) * 8 - 1)) & b;
  return q;
}

static uint32_t *
gen_sieve_offsets(mpz_t n, uint32_t step)
{
  uint32_t *t = malloc(SPRIMES * sizeof(uint32_t));
  uint32_t i;

  assert(t != NULL);

  for (i = 0; i < sprimes_count; i++)
    {
      uint32_t s = sprimes[i];
      uint32_t o = mpz_fdiv_ui(n, s);
      /* solve linear congruence */
      uint32_t m = step % s;
      uint64_t v = modinv(m, s);

      /* compute offset */
      o = (v * (s - o)) % s;

      /* keep offset + n odd */
      if (o & 1)
        o += s;

      t[i] = o;
    }

  return t;
}

struct worker_s
{
  short id;
  char busy;
  sem_t sem;
  pthread_t thread;
  mpz_t p;
  uint32_t offset;
};

static pthread_mutex_t lock;
static pthread_cond_t cond;
static uint32_t workers_result;
static size_t workers_count;
static struct worker_s *workers;

static void *worker_func(void *arg)
{
  struct worker_s *w = arg;
  mpz_t q;
  mpz_init(q);

  while (1)
    {
      /* wait for a candidate from the sieve algorithm */
      sem_wait(&w->sem);

      /* start with weak check on P so that we do not spend much time
         running a strong check on Q in case only Q is actually prime. */
      if (mpz_probab_prime_p(w->p, 1))
        {
          /* compute Q */
          mpz_sub_ui(q, w->p, 1);
          mpz_divexact_ui(q, q, 2);

          /* strong check on Q and P */
          if (mpz_probab_prime_p(q, MRROUNDS) &&
              mpz_probab_prime_p(w->p, MRROUNDS))
            {
              pthread_mutex_lock(&lock);

              /* keep the smallest offset when more than one thread
                 found a safe prime. */
              if (w->offset < workers_result)
                workers_result = w->offset;

              goto next;
            }
        }
      pthread_mutex_lock(&lock);

    next:
      /* advertise the worker thread as ready for a new job */
      w->busy = 0;
      pthread_mutex_unlock(&lock);
      pthread_cond_broadcast(&cond);
    }
}

static int worker_wake(mpz_t p, uint32_t offset)
{
  struct worker_s *w;
  int r, id;

  pthread_mutex_lock(&lock);
  r = workers_result;
  if (r != -1)
    {
      /* safe prime already found, do not start a new job */
      pthread_mutex_unlock(&lock);
      return 1;
    }

  /* find an idle worker thread */
  while (1)
    {
      for (id = 0; id < workers_count; id++)
        {
          w = workers + id;
          if (!w->busy)
            goto done;
        }
      pthread_cond_wait(&cond, &lock);
    }

 done:
  w->busy = 1;
  pthread_mutex_unlock(&lock);

  /* starts the worker thread */
  mpz_set(w->p, p);
  w->offset = offset;
  sem_post(&w->sem);

  return 0;
}

static void worker_wait()
{
  struct worker_s *w;
  int id;

  pthread_mutex_lock(&lock);

  /* wait for all worker threads to become idle */
  for (id = 0; id < workers_count; id++)
    {
      w = workers + id;
      if (w->busy)
        {
          pthread_cond_wait(&cond, &lock);
          id = 0;
        }
    }
  pthread_mutex_unlock(&lock);
}

static uint32_t gen_safe_prime(mpz_t p_)
{
  mpz_t q, p;
  mpz_init(p);
  mpz_init(q);

  /* adjust P so that P%12==11 */
  uint64_t r = 11 - mpz_fdiv_ui(p_, 12);
  mpz_add_ui(p, p_, r);

  /* set Q=(P-1)/2 */
  mpz_sub_ui(q, p, 1);
  mpz_divexact_ui(q, q, 2);

  /* generate sieve offset tables for P and Q */
  fprintf(stderr, "Computing sieve offsets for p...\n");
  uint32_t *tp = gen_sieve_offsets(p, 12);
  fprintf(stderr, "Computing sieve offsets for q...\n");
  uint32_t *tq = gen_sieve_offsets(q, 6);

  /* sieve bitmap */
  uint32_t sieve_bits[64];
  uint32_t k;
  uint32_t c = 0, m = 0;

  fprintf(stderr, "Searching for safe prime...");
  workers_result = -1;

  /* run combined sieve */
  for (k = 0; ; k += sizeof(sieve_bits) * 8)
    {
      uint32_t i;
      fprintf(stderr, "u");

      /* update sieve bitmap */
      memset(sieve_bits, 0, sizeof(sieve_bits));
      for (i = 1; i < sprimes_count; i++)
        {
          /* Q */
          uint32_t s = tp[i];
          while (s - k < sizeof(sieve_bits) * 8)
            {
              uint32_t x = s - k;
              sieve_bits[x / 32] |= 1 << (x % 32);
              s += sprimes[i];
            }
          tp[i] = s;

          /* P */
          s = tq[i];
          while (s - k < sizeof(sieve_bits) * 8)
            {
              uint32_t x = s - k;
              sieve_bits[x / 32] |= 1 << (x % 32);
              s += sprimes[i];
            }
          tq[i] = s;
        }

      /* feed worker threads with safe prime candidates */
      for (i = 0; i < sizeof(sieve_bits) / sizeof(sieve_bits[0]); i++)
        {
          uint32_t x;
          for (x = ~sieve_bits[i]; x; x &= (x - 1))
            {
              uint32_t o = k + (i * 32 + __builtin_ctz(x));
              mpz_add_ui(p, p, (o - m) * 12);
              mpz_add_ui(q, q, (o - m) * 6);
              m = o;
              c++;

              if (worker_wake(p, r + o * 12))
                {
                  /* found, wait for all workers to terminate */
                  worker_wait();

                  /* cleanup */
                  fprintf(stderr, "\nFound: %u tests, offset=%u\n", c, workers_result);
                  mpz_clear(q);
                  mpz_clear(p);
                  free(tp);
                  free(tq);
                  return workers_result;
                }
            }
        }
    }
}

/****************************************************/

static uint32_t lfsr_poly;

/* fill a big number buffer with the LFSR */
static void
lfsr_fill(uint8_t *data, size_t len, uint32_t seed)
{
  while (len--)
    {
      seed = (~((seed & 1) - 1) & lfsr_poly) ^ (seed >> 1);
      *data++ = seed ^ (seed >> 8) ^ (seed >> 16) ^ (seed >> 24);
    }
}

struct packet_push_s
{
  uint32_t bits;
  uint32_t poly;
  uint32_t seed;
  uint32_t offset;
};

struct packet_pull_s
{
  uint32_t bits;
  uint32_t poly;
  uint32_t seed;
};

int main(int argc, char *argv[])
{
  int i;

  uint32_t seed = 0;
#ifndef CLIENT
  fprintf(stderr, "usage: %s seed32 [first last step poly32]\n", argv[0]);

  seed = argc >= 2 ? strtoul(argv[1], NULL, 0) : time(NULL);
  uint32_t first = argc >= 3 ? atoi(argv[2]) : 1024;
  uint32_t last = argc >= 4 ? atoi(argv[3]) : 16384;
  uint32_t step = argc >= 5 ? atoi(argv[4]) : 8;
  lfsr_poly = argc >= 6 ? strtoul(argv[5], NULL, 0) : 0x8a523d7c;

  assert(seed && lfsr_poly);
  fprintf(stderr, "lfsr: seed=0x%08x, poly=0x%08x\n", seed, lfsr_poly);
#else
  int sock;
  struct sockaddr_in sin;
#endif

  (void)nice(10);
  workers_count = sysconf(_SC_NPROCESSORS_ONLN);

  fprintf(stderr, "Worker threads: %u\n", workers_count);
  workers = malloc(sizeof(struct worker_s) * workers_count);

  pthread_mutex_init(&lock, NULL);
  pthread_cond_init(&cond, NULL);
  for (i = 0; i < workers_count; i++)
    {
      struct worker_s *w = workers + i;
      w->id = i;
      w->busy = 0;
      sem_init(&w->sem, 0, 0);
      pthread_create(&w->thread, NULL, worker_func, workers + i);
    }

#ifndef CLIENT
  FILE *f = fopen("safe_primes.txt", "a+");

#endif

  fprintf(stderr, "Generating small primes...\n");
  gen_small_primes();

  uint32_t o = 0;
  size_t s = 0;
  mpz_t p;
  mpz_init(p);

#ifndef CLIENT
  for (s = first; s <= last; s += step)
    {
#else
  while (1)
    {
      if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        {
          sleep(60);
          continue;
        }

      sin.sin_family = AF_INET;
      sin.sin_addr.s_addr = ntohl(server_ip_g);
      sin.sin_port = htons(65267);

      fprintf(stderr, "Connecting...\n");
      if (connect(sock, (struct sockaddr*)(&sin),
		  sizeof(struct sockaddr_in)) != 0)
        {
          close(sock);
          sleep(60);
          continue;
        }

      {
        struct packet_push_s p1 = {
          ntohl(s),
          ntohl(lfsr_poly),
          ntohl(seed),
          ntohl(o)
        };
        int r = send(sock, &p1, sizeof(p1), 0);
        if (r != sizeof(p1))
          {
            close(sock);
            sleep(60);
            continue;
          }

        struct packet_pull_s p2;
        r = recv(sock, &p2, sizeof(p2), MSG_WAITALL);
        if (r != sizeof(p2) || p2.bits == 0)
          {
            close(sock);
            sleep(60);
            continue;
          }
        s = ntohl(p2.bits);
        lfsr_poly = ntohl(p2.poly);
        seed = ntohl(p2.seed);
      }

      close(sock);

#endif
      uint8_t raw[s / 8];
      lfsr_fill(raw, s / 8, seed ^ s);
      raw[s / 8 - 1] |= 0x80;
      mpz_import(p, s / 8, -1, 1, 0, 0, raw);

      fprintf(stderr, "%u bits\n", s);

      o = gen_safe_prime(p);

      mpz_add_ui(p, p, o);
      mpz_out_str(stderr, 10, p);
      fprintf(stderr, "\n");

#ifndef CLIENT
      fprintf(f, "bits:%u poly:0x%08x seed:0x%08x offset:0x%08x\n",
              s, lfsr_poly, seed, o);
      fflush(f);
    }

  fclose(f);
#else
    }
#endif

  return 0;
}

