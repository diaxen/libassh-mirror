/*

  Safe prime number generation server for libassh.

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

#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

#define SAFED_PERR(msg)		{ fprintf(stderr, "error in %s:", __func__); \
				perror(msg); return -1; }
#define SAFED_ERR(lbl, msg...)	{ fprintf(stderr, "%s(): ", __func__); \
				fprintf(stderr, msg); goto lbl; }
#define SAFED_LOG(msg...)	{ fprintf(stderr, "%s(): ", __func__); \
				fprintf(stderr, msg); }

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

#define S 1024
#define M (16384 + 8)

uint8_t done[(M-S) / 8];
uint32_t seed;
uint32_t poly = 0x8a523d7c;

int main()
{
  memset(done, 0, sizeof(done));
  seed = time(NULL);

  /* create socket */
  int soc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (soc < 0)
    SAFED_PERR("socket creation failed");

  {
    int		tmp = 1;
    setsockopt(soc, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp));
  }

  /* socket bind & listen */
  {
    struct sockaddr_in	addr =
      {
	.sin_port = htons(65267),
	.sin_family = AF_INET,
      };

    if (bind(soc, (struct sockaddr*)&addr, sizeof (struct sockaddr_in)) < 0)
      SAFED_PERR("socket bind failed");
  }

  if (listen(soc, 8) < 0)
    SAFED_PERR("socket listen failed");

  signal(SIGCLD, SIG_IGN);
  unsigned next = 0;
  FILE *f = fopen("safe_primes.txt", "a+");

  while (1)
    {
      struct sockaddr_in	con_addr;
      int			addr_size = sizeof(con_addr);
      int			con;

      con = accept(soc, (struct sockaddr*)&con_addr, &addr_size);

      struct packet_push_s p1;
      int r = recv(con, &p1, sizeof(p1), MSG_WAITALL);
      if (r != sizeof(p1))
	{
	  close(con);
	  continue;
	}

      size_t bits = ntohl(p1.bits);
      if (bits >= S && bits <= M)
	{
	  fprintf(f, "bits:%u poly:0x%08x seed:0x%08x offset:0x%08x\n",
		  bits, ntohl(p1.poly), ntohl(p1.seed), ntohl(p1.offset));
	  fflush(f);
	  fprintf(stderr, "!%u", bits);
	  if (ntohl(p1.seed) == seed &&
	      ntohl(p1.poly) == poly)
	    done[(bits - S) / 8] = 1;
	}

      unsigned n = next;
      while (1)
	{
	  next++;
	  if (S + next * 8 == M)
	    next = 0;
	  if (!done[next])
	    break;
	  if (next == n)
	    {
	      bits = 0;
	      printf("end\n");
	      goto end;
	    }
	}
      bits = S + next * 8;
    end:;

      struct packet_pull_s p2 = {
	ntohl(bits),
	ntohl(poly),
	ntohl(seed),
      };
      send(con, &p2, sizeof(p2), 0);
      fprintf(stderr, "?%u", bits);

      close(con);
    }

}

