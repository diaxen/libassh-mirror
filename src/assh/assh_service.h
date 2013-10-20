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

#ifndef ASSH_SERVICE_H_
#define ASSH_SERVICE_H_

#include "assh.h"

#define ASSH_SERVICE_INIT_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(struct assh_session_s *s)
typedef ASSH_SERVICE_INIT_FCN(assh_service_init_t);

#define ASSH_SERVICE_CLEANUP_FCN(n) \
  void (n)(struct assh_session_s *s)
typedef ASSH_SERVICE_CLEANUP_FCN(assh_service_cleanup_t);

struct assh_service_s
{
  const char *name;
  assh_service_init_t *f_init;
  assh_service_cleanup_t *f_cleanup;
  assh_process_t *f_process;
};

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_service_register(struct assh_context_s *c,
		      struct assh_service_s *srv);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_service_register_va(struct assh_context_s *c, ...);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_service_got_request(struct assh_session_s *s,
                         struct assh_packet_s *p);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_service_got_accept(struct assh_session_s *s,
                        struct assh_packet_s *p);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_service_send_request(struct assh_session_s *s);

extern const struct assh_service_s assh_service_ssh_userauth;
extern const struct assh_service_s assh_service_ssh_connection;

#endif

