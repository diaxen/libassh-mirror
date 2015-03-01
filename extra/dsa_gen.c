
#include <gmp.h>
#include <assert.h>
#include <stdio.h>

int is_prime(mpz_t i) 
{
  return mpz_probab_prime_p(i, 64);
}

mpz_t q, p, pm, t, h, g;

int dsa_gen_q(int N)
{
  int qi = 0;

  /* find q */
  mpz_set_ui(q, 0);
  mpz_setbit(q, N);
  mpz_sub_ui(q, q, 1);
  qi++;

  while (!is_prime(q))
    {
      mpz_sub_ui(q, q, 2);
      qi += 2;
    }

#ifdef VERBOSE
  gmp_printf ("q = %Zd\n", q);
  printf("q = 2^%i-%i\n", N, qi);
#endif

  return qi;
}

int dsa_gen_p(int L)
{
  int pi = 0;

  /* find p */
  mpz_set_ui(p, 0);
  mpz_setbit(p, L);

  mpz_sub_ui(pm, p, 1);
  mpz_mod(t, pm, q);
  mpz_sub(pm, pm, t);

  mpz_add_ui(p, pm, 1);

  if (mpz_even_p(p))
    {
      mpz_sub(p, p, q);
      pi++;
    }

  while (!is_prime(p))
    {
      mpz_sub(p, p, q);
      mpz_sub(p, p, q);
      pi += 2;
    }

  mpz_sub_ui(pm, p, 1);

#ifdef VERBOSE
  gmp_printf ("p = %Zd\n", p);
  printf("p = 2^%i - (2^%i-1)%%q - q*%i\n", L, L, pi);
#endif

  return pi;
}

int dsa_gen_g()
{
  int hi;

  /* find g */
  mpz_tdiv_q(t, pm, q);
  mpz_set_ui(h, hi = 2);

  while (1)
    {
      mpz_powm(g, h, t, p);
      if (mpz_cmp_ui(g, 1))
	break;
      mpz_add_ui(h, h, 1);
      hi++;
    }

#ifdef VERBOSE
  gmp_printf ("g = %Zd\n", g);
  printf("h = %i\n", hi);
  printf("g = %i^((p-1)/q)\n", hi);
#endif

  return hi;
}

int main(int argc, char *argv[])
{
  mpz_init(q);
  mpz_init(p);
  mpz_init(pm);
  mpz_init(t);
  mpz_init(h);
  mpz_init(g);

  int i;

  for (i = 1024; i <= 4096; )
    {
      if (i == 1024)
	printf(" /* N = 160, %u */ ", dsa_gen_q(160));
      else if (i == 1024 + 8)
	printf(" /* N = 224, %u */ ", dsa_gen_q(224));
      else if (i == 2048)
	printf(" /* N = 256, %u */ ", dsa_gen_q(256));

      printf("%5u, ", dsa_gen_p(i));
      fflush(stdout);

      assert(dsa_gen_g() == 2);

#if 0
      if (i & (i >> 1))
	i = (i & ~(i >> 1)) << 1;
      else
	i = (i | (i >> 1));
#endif
      i += 8;
    }

  return 0;
}

