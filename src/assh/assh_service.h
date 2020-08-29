/*

  libassh - asynchronous ssh2 client/server library.

  Copyright (C) 2013-2020 Alexandre Becoulet <alexandre.becoulet@free.fr>

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

   This header file provides declarations related to the
   @hl service module interface. Functions are provided to register
   @hl services on a library @ref assh_context_s object.

   @xsee {coremod}
   @xsee {srvlayer}
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
  ASSH_SRV_RUNNING,
};

/** @internal @see assh_service_init_t */
#define ASSH_SERVICE_INIT_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_status_t (n)(struct assh_session_s *s)

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
#define ASSH_SERVICE_PROCESS_FCN(n) assh_status_t (n)(struct assh_session_s *s, \
                                                     struct assh_packet_s *p, \
                                                     struct assh_event_s *e)

/** @internal @This defines the function type for event processing of
    the ssh service module interface. This function is called from the
    @ref assh_transport_dispatch function when the current state of
    the transport layer is @ref ASSH_TR_SERVICE, @ref
    ASSH_TR_SERVICE_KEX or @ref ASSH_TR_DISCONNECT.
    It must update the @ref assh_session_s::srv_deadline field when the
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
    @ref ASSH_TR_DISCONNECT. If the function reports no event and return
    @ref ASSH_OK when the state is @ref ASSH_TR_DISCONNECT, the state will
    change to ASSH_TR_CLOSED and the function will not be called any more. */
typedef ASSH_SERVICE_PROCESS_FCN(assh_service_process_t);

/** @internalmembers @This is the @hl service module descriptor.
    It can be registered on a @ref assh_context_s instance for use
    by all associated @hl sessions.
    @xsee{coremod} @see assh_service_register */
struct assh_service_s
{
  ASSH_PV const char *name;
  ASSH_PV assh_service_init_t *f_init;
  ASSH_PV assh_service_cleanup_t *f_cleanup;
  ASSH_PV assh_service_process_t *f_process;
  ASSH_PV enum assh_context_type_e side:2;
  ASSH_PV assh_bool_t no_user_auth:1;
};

/**
   The @ref ASSH_EVENT_SERVICE_START event is reported when a
   service has started.
*/
struct assh_event_service_start_s
{
  /** A pointer to the module descriptor of the starting @hl service. (ro) */
  const struct assh_service_s * ASSH_EV_CONST srv;
};

/** @This contains all @hl service related event structures. */
union assh_event_service_u
{
  struct assh_event_service_start_s start;
};

/** @This registers a single @ref assh_service_s for use by
    the given context. @see assh_service_register_va */
ASSH_WARN_UNUSED_RESULT assh_status_t
assh_service_register(struct assh_context_s *c,
		      struct assh_service_s *srv);

/** @This registers one or more @ref assh_service_s for use
    by the given context.

    When registering @hl service modules onto a client context, the
    registration order determines the order used to request execution
    of the @hl services.  @see assh_service_register */
ASSH_WARN_UNUSED_RESULT assh_status_t
assh_service_register_va(struct assh_context_s *c, ...);

/** @This registers the standard @tt ssh-userauth and @tt
    ssh-connection services. The appropriate client or server @hl
    services are used depending on the context type. */
ASSH_WARN_UNUSED_RESULT assh_status_t
assh_service_register_default(struct assh_context_s *c);

/** @internal */
ASSH_PV ASSH_WARN_UNUSED_RESULT assh_status_t
assh_service_loop(struct assh_session_s *s,
                  struct assh_packet_s *p,
                  struct assh_event_s *e);

/** @This lookup a registered service by name. */
ASSH_WARN_UNUSED_RESULT assh_status_t
assh_service_by_name(struct assh_context_s *c,
                     size_t name_len, const char *name,
                     const struct assh_service_s **srv_);

/** @internal @This returns the next @hl service which must be started
    for the current client session. Designed for use by @hl service
    implementations. */
ASSH_PV ASSH_WARN_UNUSED_RESULT assh_status_t
assh_service_next(struct assh_session_s *s,
                  const struct assh_service_s **srv);

/** @internal @This stops the currently running @hl service.
    Designed for use by client service implementations. This will make
    assh send a @ref SSH_MSG_SERVICE_REQUEST message to the server in
    order to start the next service. */
ASSH_PV void assh_service_stop(struct assh_session_s *s);

/** @internal @This stops the currently running @hl service and
    schedules execution of the specified service. Designed for use by
    service implementations. */
ASSH_PV void assh_service_start(struct assh_session_s *s,
                        const struct assh_service_s *next);

#endif

