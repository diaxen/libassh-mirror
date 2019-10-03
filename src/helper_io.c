/*

  libassh - asynchronous ssh2 client/server library.

  Copyright (C) 2013 Alexandre Becoulet <alexandre.becoulet@free.fr>

  This library is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
  02110-1301 USA

*/

#include <assh/helper_io.h>

#include <unistd.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <poll.h>

#include <assh/assh_session.h>
#include <assh/assh_transport.h>
#include <assh/assh_alloc.h>
#include <assh/assh_kex.h>
#include <assh/assh_key.h>
#include <assh/assh_event.h>
#include <assh/assh_cipher.h>
#include <assh/assh_compress.h>
#include <assh/assh_mac.h>

#include <termios.h>

ASSH_WARN_UNUSED_RESULT assh_status_t
asshh_fd_get_password(struct assh_context_s *c, const char **pass,
		     size_t max_len, int fd, assh_bool_t echo)
{
  struct termios t;
  assh_status_t err;
  char *p;
  int_fast8_t i = 0;

  ASSH_RET_IF_TRUE(!isatty(fd), ASSH_ERR_IO);

  ASSH_RET_ON_ERR(assh_alloc(c, max_len, ASSH_ALLOC_SECUR, (void**)&p));
  *pass = p;

  if (!echo)
    {
      tcgetattr(fd, &t);
      t.c_lflag &= ~ECHO;
      tcsetattr(fd, 0, &t);
    }

  while (1)
    {
      char c;
      ssize_t r = read(fd, &c, 1);

      ASSH_JMP_IF_TRUE(r != 1, ASSH_ERR_IO, err_);

      switch (c)
        {
        case '\n':
        case '\r':
          p[i] = 0;
	  err = ASSH_OK;
	  goto done;
        default:
          if (i + 1 < max_len)
            p[i++] = c;
        }
    }

 err_:
  assh_free(c, p);
 done:
  if (!echo)
    {
      t.c_lflag |= ECHO;
      tcsetattr(fd, 0, &t);
    }
  return err;
}

size_t
asshh_fd_event(struct assh_session_s *s,
              struct assh_event_s *e, int fd)
{
  assh_status_t err = ASSH_OK;
  ssize_t r;

  switch (e->id)
    {
    case ASSH_EVENT_READ: {
      struct assh_event_transport_read_s *te = &e->transport.read;
      r = read(fd, te->buf.data, te->buf.size);
      switch (r)
        {
        case -1:
          r = 0;
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;
        case 0:
          err = ASSH_ERR_IO;
          goto err_;
        default:
          te->transferred = r;
          break;
        }
      break;
    }

    case ASSH_EVENT_WRITE: {
      struct assh_event_transport_write_s *te = &e->transport.write;
      r = write(fd, te->buf.data, te->buf.size);
      switch (r)
        {
        case -1:
          r = 0;
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;
        case 0:
          err = ASSH_ERR_IO;
          goto err_;
        default:
          te->transferred = r;
          break;
        }
      break;
    }

    default:
      ASSH_UNREACHABLE();
    }

 err_:
  assh_event_done(s, e, err);
  return r;
}

void
asshh_print_string(FILE *out, const struct assh_cbuffer_s *str)
{
  size_t i;

  /* print string, skipping any terminal control characters */
  for (i = 0; i < str->len; i++)
    {
      char c = str->str[i];

      if ((c >= ' ' && c <= 127) || c == '\n' || c == '\t')
	fputc(c, out);
    }
}

void
asshh_print_kex_details(struct assh_session_s *s, FILE *out,
			      const struct assh_event_s *event)
{
  const struct assh_event_kex_done_s *ev = &event->kex.done;

  assert(event->id == ASSH_EVENT_KEX_DONE);
  const struct assh_algo_kex_s *kex = ev->algo_kex;

  fprintf(out,
	  "Key exchange details:\n"
	  "  remote software   : ");
  asshh_print_string(out, &ev->ident);

  fprintf(out, "\n"
	  "  key exchange      : %-38s safety %u%% (%s)\n",
	  assh_algo_name(&kex->algo),
	  assh_algo_safety(&kex->algo),
	  assh_algo_safety_name(&kex->algo)
	  );

  if (ev->host_key)
    fprintf(out,
	  "  host key          : %-38s safety %u%% (%s)\n",
	  assh_key_type_name(ev->host_key),
	  assh_key_safety(ev->host_key),
	  assh_key_safety_name(ev->host_key)
	  );

  const struct assh_algo_cipher_s *cipher_in = ev->algos_in->cipher;
  const struct assh_algo_cipher_s *cipher_out = ev->algos_out->cipher;

  fprintf(out,
	  "  input cipher      : %-38s safety %u%% (%s)\n"
	  "  output cipher     : %-38s safety %u%% (%s)\n",
	  assh_algo_name(&cipher_in->algo),
	  assh_algo_safety(&cipher_in->algo),
	  assh_algo_safety_name(&cipher_in->algo),
	  assh_algo_name(&cipher_out->algo),
	  assh_algo_safety(&cipher_out->algo),
	  assh_algo_safety_name(&cipher_out->algo)
	  );

  const struct assh_algo_mac_s *mac_in = ev->algos_in->mac;
  const struct assh_algo_mac_s *mac_out = ev->algos_out->mac;

  if (!cipher_in->auth_size)
    fprintf(out,
	  "  input mac         : %-38s safety %u%% (%s)\n",
	  assh_algo_name(&mac_in->algo),
	  assh_algo_safety(&mac_in->algo),
          assh_algo_safety_name(&mac_in->algo)
	    );

  if (!cipher_out->auth_size)
    fprintf(out,
	  "  output mac        : %-38s safety %u%% (%s)\n",
	  assh_algo_name(&mac_out->algo),
	  assh_algo_safety(&mac_out->algo),
	  assh_algo_safety_name(&mac_out->algo)
	    );

  if (ev->algos_in->cmp != &assh_compress_none)
    fprintf(out,
	  "  input compression : %-38s safety %u%% (%s)\n",
	  assh_algo_name(&ev->algos_in->cmp->algo),
	  assh_algo_safety(&ev->algos_in->cmp->algo),
	  assh_algo_safety_name(&ev->algos_in->cmp->algo)
	  );

  if (ev->algos_out->cmp != &assh_compress_none)
    fprintf(out,
	  "  output compression: %-38s safety %u%% (%s)\n",
	  assh_algo_name(&ev->algos_out->cmp->algo),
	  assh_algo_safety(&ev->algos_out->cmp->algo),
	  assh_algo_safety_name(&ev->algos_out->cmp->algo)
	  );
}
