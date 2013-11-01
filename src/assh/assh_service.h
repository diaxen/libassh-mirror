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

#include "assh_context.h"

/** @internal @This defines the prototype of the initialization
    function of an ssh service. This function is called when a service
    requested is successful. This function must set the @ref
    assh_session_s::srv field and may set the @ref
    assh_session_s::srv_pv field. */
#define ASSH_SERVICE_INIT_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(struct assh_session_s *s)
typedef ASSH_SERVICE_INIT_FCN(assh_service_init_t);

/** @internal @This defines the prototype of the cleanup function of
    the ssh service. This function is called when the service ends or
    when the session cleanup occurs if a service has been initialized
    previously. It must free the resources allocated by the associated
    initialization function and set the @ref assh_session_s::srv and
    assh_session_s::srv_pv fields to @tt {NULL}. */
#define ASSH_SERVICE_CLEANUP_FCN(n) \
  void (n)(struct assh_session_s *s)
typedef ASSH_SERVICE_CLEANUP_FCN(assh_service_cleanup_t);

/** @This describes the implementation of an ssh service. */
struct assh_service_s
{
  const char *name;
  enum assh_context_type_e side;
  assh_service_init_t *f_init;
  assh_service_cleanup_t *f_cleanup;
  assh_process_t *f_process;
};

/** @This function registers a single @ref assh_service_s for use by
    the given context. @see assh_service_register_va */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_service_register(struct assh_context_s *c,
		      struct assh_service_s *srv);

/** @This function registers one or more @ref assh_service_s for use
    by the given context.

    When registering services onto a client context, the registration
    order determines the order in which the services will be
    requested. @see assh_service_register */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_service_register_va(struct assh_context_s *c, ...);

/** @This function registers the standard @tt ssh-userauth and @tt
    ssh-connection services. The appropriate client or server services
    are used depending on the context type. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_service_register_default(struct assh_context_s *c);

/** @internal */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_service_got_request(struct assh_session_s *s,
                         struct assh_packet_s *p);

/** @internal */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_service_got_accept(struct assh_session_s *s,
                        struct assh_packet_s *p);

/** @internal */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_service_send_request(struct assh_session_s *s);

/** @This lookup a registered service. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_service_by_name(struct assh_context_s *c,
                     size_t name_len, const char *name,
                     const struct assh_service_s **srv_);

#ifdef CONFIG_ASSH_SERVER
/** @This provides the standard server side @tt ssh-userauth service. */
extern const struct assh_service_s assh_service_userauth_server;
/** @This provides the standard server side @tt ssh-connection service. */
extern const struct assh_service_s assh_service_connection_server;
#endif

#ifdef CONFIG_ASSH_CLIENT
/** @This provides the standard client side @tt ssh-userauth service. */
extern const struct assh_service_s assh_service_userauth_client;
/** @This provides the standard client side @tt ssh-connection service. */
extern const struct assh_service_s assh_service_connection_client;
#endif

#endif

