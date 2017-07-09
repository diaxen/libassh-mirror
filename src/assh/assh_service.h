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

/**
   @file
   @short SSH service module interface
*/

#ifndef ASSH_SERVICE_H_
#define ASSH_SERVICE_H_

#ifdef ASSH_EVENT_H_
# warning The assh/assh_event.h header should be included after assh_service.h
#endif

#include "assh_context.h"

/** @internal */
enum assh_service_state_e
{
  ASSH_SRV_NONE,
  ASSH_SRV_REQUESTED,
  ASSH_SRV_INIT,
  ASSH_SRV_INIT_EVENT,
  ASSH_SRV_RUNNING,
};

/** @internal @see assh_service_init_t */
#define ASSH_SERVICE_INIT_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(struct assh_session_s *s)

/** @internal @This defines the function type for the initialization
    operation of the ssh service module interface. This function is
    called when a service request is successful. This function must
    set the @ref assh_session_s::srv field and may set the @ref
    assh_session_s::srv_pv field as well to store its private data. */
typedef ASSH_SERVICE_INIT_FCN(assh_service_init_t);

/** @internal @see assh_service_cleanup_t */
#define ASSH_SERVICE_CLEANUP_FCN(n) \
  void (n)(struct assh_session_s *s)

/** @internal @This defines the function type for the cleanup
    operation of the ssh service module interface. This function is
    called when the service terminates or when the session cleanup
    occurs. It has to free the resources allocated by the service
    initialization function and set the @ref assh_session_s::srv and
    assh_session_s::srv_pv fields to @tt {NULL}. */
typedef ASSH_SERVICE_CLEANUP_FCN(assh_service_cleanup_t);

/** @internal @see assh_service_process_t */
#define ASSH_SERVICE_PROCESS_FCN(n) assh_error_t (n)(struct assh_session_s *s, \
                                                     struct assh_packet_s *p, \
                                                     struct assh_event_s *e)

/** @internal @This defines the function type for event processing of
    the ssh service module interface. This function is called from the
    @ref assh_transport_dispatch function when the current state of
    the transport layer is @ref ASSH_TR_SERVICE, @ref
    ASSH_TR_SERVICE_KEX, @ref ASSH_TR_DISCONNECT or @ref ASSH_TR_FIN.
    It must update the @ref assh_session_s::deadline field when the
    state is less than @ref ASSH_TR_DISCONNECT.

    A packet may be passed to the function for processing by the
    running service. This function must be able to handle some @ref
    SSH_MSG_UNIMPLEMENTED packets as well as packets with a message
    id greater or equal to @ref SSH_MSG_SERVICE_FIRST. If no new
    received packet is available, the parameter is @tt NULL.

    The function may initialize the passed event object, in this case
    the event will be reported to the caller of the @ref
    assh_event_get function.

    The function can return the @ref ASSH_NO_DATA value to indicate
    that the provided packet has not been processed and must be
    provided again on the next call. If no event is reported and @ref
    ASSH_NO_DATA is returned, the function is called again
    immediately.

    This function should check the current state of the transport
    layer and report any termination related events when the state is
    @ref ASSH_TR_FIN. If the function reports no event and return
    @ref ASSH_OK when the state is @ref ASSH_TR_FIN, the state will
    change to ASSH_TR_CLOSED and the function will not be called any more. */
typedef ASSH_SERVICE_PROCESS_FCN(assh_service_process_t);

/** @This describes the implementation of an ssh service. */
struct assh_service_s
{
  const char *name;
  assh_service_init_t *f_init;
  assh_service_cleanup_t *f_cleanup;
  assh_service_process_t *f_process;
  enum assh_context_type_e side:2;
  assh_bool_t no_user_auth:1;
};

/**
   The @ref ASSH_EVENT_SERVICE_START event is reported when a
   service has started.
*/
struct assh_event_service_start_s
{
  const struct assh_service_s * ASSH_EV_CONST srv;
};

/** @internal */
union assh_event_service_u
{
  struct assh_event_service_start_s start;
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
assh_service_loop(struct assh_session_s *s,
                  struct assh_packet_s *p,
                  struct assh_event_s *e);

/** @This lookup a registered service. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_service_by_name(struct assh_context_s *c,
                     size_t name_len, const char *name,
                     const struct assh_service_s **srv_);

/** @internal @This returns the next service which must be started for
    the current client session. Designed for use by service
    implementations. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_service_next(struct assh_session_s *s,
                  const struct assh_service_s **srv);

/** @internal @This stops the currently running service if any.
    Designed for use by service implementations. */
void assh_service_stop(struct assh_session_s *s);

/** @internal @This stops the currently running service if any and
    schedules execution of the specified service. Designed for use by
    service implementations. */
void assh_service_start(struct assh_session_s *s,
                        const struct assh_service_s *next);

#endif

