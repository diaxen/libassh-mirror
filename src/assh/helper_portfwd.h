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
   @short SSH port forwarding helpers (rfc4254 port forwarding)

   This headers file provides some @hl helper functions able load
   and store data embedded in standard @hl requests and
   @hl channels open messages related to the @hl{port forwarding}
   features of @em {ssh2}.

   @xsee {connmap}
   @see @assh/assh_connection.h
*/

#ifndef ASSH_HELPER_PORTFWD_H_
#define ASSH_HELPER_PORTFWD_H_

#include "assh.h"
#include "assh_buffer.h"

/** @This specifies the port forwarding request object. */
struct asshh_portfwd_tcpip_forward_s
{
  struct assh_cbuffer_s            addr;
  uint32_t                         port;
};

#ifdef CONFIG_ASSH_CLIENT

/** @This initializes a port forwarding request object.
    Any buffer passed to the function is not copied and
    must remain valid. */
void
asshh_portfwd_init_tcpip_forward(struct asshh_portfwd_tcpip_forward_s *i,
                              const char * addr,
                              uint32_t port);

/** @This returns the size of the buffer required to encode a
    port forwarding request object. */
size_t
asshh_portfwd_size_tcpip_forward(const struct asshh_portfwd_tcpip_forward_s *i);

/** @This encodes the port forwarding request object in a
    buffer suitable for calling the @ref assh_request function. This
    function fails when the provided buffer is not large enough. */
ASSH_WARN_UNUSED_RESULT assh_error_t
asshh_portfwd_encode_tcpip_forward(uint8_t *data, size_t size,
                                const struct asshh_portfwd_tcpip_forward_s *i);

/** @This encodes and sends a port forwarding request
    @csee asshh_portfwd_encode_tcpip_forward
    @see assh_request */
ASSH_WARN_UNUSED_RESULT assh_error_t
asshh_portfwd_send_tcpip_forward(struct assh_session_s *s,
                              struct assh_request_s **rq,
                              const struct asshh_portfwd_tcpip_forward_s *i);
#endif

#ifdef CONFIG_ASSH_SERVER

/** @This decodes the port forwarding request object from the
    passed buffer. The @tt data buffer must remain valid because
    string buffers are not copied. This function fails when the buffer
    contains invalid data. */
ASSH_WARN_UNUSED_RESULT assh_error_t
asshh_portfwd_decode_tcpip_forward(struct asshh_portfwd_tcpip_forward_s *i,
                                const uint8_t *data, size_t size);
#endif

/** @This specifies the port forwarding request reply object. */
struct asshh_portfwd_tcpip_forward_reply_s
{
  uint32_t                         port;
};

/** @This initializes a port forwarding request reply object.
    Any buffer passed to the function is not copied and
    must remain valid. */
void
asshh_portfwd_init_tcpip_forward_reply(struct asshh_portfwd_tcpip_forward_reply_s *i,
                                    uint32_t port);

/** @This returns the size of the buffer required to encode a
    port forwarding request reply object. */
size_t
asshh_portfwd_size_tcpip_forward_reply(const struct asshh_portfwd_tcpip_forward_reply_s *i);

/** @This encodes the port forwarding request reply object in
    a buffer suitable for calling the @ref assh_request function. This
    function fails when the provided buffer is not large enough. */
ASSH_WARN_UNUSED_RESULT assh_error_t
asshh_portfwd_encode_tcpip_forward_reply(uint8_t *data, size_t size,
                                      const struct asshh_portfwd_tcpip_forward_reply_s *i);

/** @This decodes the port forwarding request reply object
    from the passed buffer. The @tt data buffer must remain valid
    because string buffers are not copied. This function fails when
    the buffer contains invalid data. */
ASSH_WARN_UNUSED_RESULT assh_error_t
asshh_portfwd_decode_tcpip_forward_reply(struct asshh_portfwd_tcpip_forward_reply_s *i,
                                      const uint8_t *data, size_t size);

/** @This specifies the port forwarding cancel object. */
struct asshh_portfwd_cancel_tcpip_forward_s
{
  struct assh_cbuffer_s            addr;
  uint32_t                         port;
};

#ifdef CONFIG_ASSH_CLIENT

/** @This initializes a port forwarding cancel object.
    Any buffer passed to the function is not copied and
    must remain valid. */
void
asshh_portfwd_init_cancel_tcpip_forward(struct asshh_portfwd_cancel_tcpip_forward_s *i,
                                     const char * addr,
                                     uint32_t port);

/** @This returns the size of the buffer required to encode a
    port forwarding cancel object. */
size_t
asshh_portfwd_size_cancel_tcpip_forward(const struct asshh_portfwd_cancel_tcpip_forward_s *i);

/** @This encodes the port forwarding cancel object in a
    buffer suitable for calling the @ref assh_request function. This
    function fails when the provided buffer is not large enough. */
ASSH_WARN_UNUSED_RESULT assh_error_t
asshh_portfwd_encode_cancel_tcpip_forward(uint8_t *data, size_t size,
                                       const struct asshh_portfwd_cancel_tcpip_forward_s *i);

/** @This encodes and sends a port forwarding cancel
    @csee asshh_portfwd_encode_cancel_tcpip_forward
    @see assh_request */
ASSH_WARN_UNUSED_RESULT assh_error_t
asshh_portfwd_send_cancel_tcpip_forward(struct assh_session_s *s,
                                     struct assh_request_s **rq,
                                     const struct asshh_portfwd_cancel_tcpip_forward_s *i);
#endif

#ifdef CONFIG_ASSH_SERVER

/** @This decodes the port forwarding cancel object from the
    passed buffer. The @tt data buffer must remain valid because
    string buffers are not copied. This function fails when the buffer
    contains invalid data. */
ASSH_WARN_UNUSED_RESULT assh_error_t
asshh_portfwd_decode_cancel_tcpip_forward(struct asshh_portfwd_cancel_tcpip_forward_s *i,
                                       const uint8_t *data, size_t size);
#endif

/** @This specifies the incoming forwarded connection channel object. */
struct asshh_portfwd_forwarded_tcpip_s
{
  struct assh_cbuffer_s            conn_addr;
  uint32_t                         conn_port;
  struct assh_cbuffer_s            orig_addr;
  uint32_t                         orig_port;
};

/** @This initializes a incoming forwarded connection channel object.
    Any buffer passed to the function is not copied and
    must remain valid. */
void
asshh_portfwd_init_forwarded_tcpip(struct asshh_portfwd_forwarded_tcpip_s *i,
                                const char * conn_addr,
                                uint32_t conn_port,
                                const char * orig_addr,
                                uint32_t orig_port);

/** @This returns the size of the buffer required to encode a
    incoming forwarded connection channel object. */
size_t
asshh_portfwd_size_forwarded_tcpip(const struct asshh_portfwd_forwarded_tcpip_s *i);

/** @This encodes the incoming forwarded connection channel
    object in a buffer suitable for calling the @ref assh_request
    function. This function fails when the provided buffer is not
    large enough. */
ASSH_WARN_UNUSED_RESULT assh_error_t
asshh_portfwd_encode_forwarded_tcpip(uint8_t *data, size_t size,
                                  const struct asshh_portfwd_forwarded_tcpip_s *i);

/** @This requests a incoming forwarded connection channel open.
    @csee asshh_portfwd_encode_forwarded_tcpip
    @see assh_channel_open */
ASSH_WARN_UNUSED_RESULT assh_error_t
asshh_portfwd_open_forwarded_tcpip(struct assh_session_s *s,
                                struct assh_channel_s **ch,
                                const struct asshh_portfwd_forwarded_tcpip_s *i);

/** @This decodes the incoming forwarded connection channel
    object from the passed buffer. The @tt data buffer must remain
    valid because string buffers are not copied. This function fails
    when the buffer contains invalid data. */
ASSH_WARN_UNUSED_RESULT assh_error_t
asshh_portfwd_decode_forwarded_tcpip(struct asshh_portfwd_forwarded_tcpip_s *i,
                                  const uint8_t *data, size_t size);

/** @This specifies the direct tcp/ip forwarding channel object. */
struct asshh_portfwd_direct_tcpip_s
{
  struct assh_cbuffer_s            conn_addr;
  uint32_t                         conn_port;
  struct assh_cbuffer_s            orig_addr;
  uint32_t                         orig_port;
};

#ifdef CONFIG_ASSH_CLIENT

/** @This initializes a direct tcp/ip forwarding channel object.
    Any buffer passed to the function is not copied and
    must remain valid. */
void
asshh_portfwd_init_direct_tcpip(struct asshh_portfwd_direct_tcpip_s *i,
                             const char * conn_addr,
                             uint32_t conn_port,
                             const char * orig_addr,
                             uint32_t orig_port);

/** @This returns the size of the buffer required to encode a
    direct tcp/ip forwarding channel object. */
size_t
asshh_portfwd_size_direct_tcpip(const struct asshh_portfwd_direct_tcpip_s *i);

/** @This encodes the direct tcp/ip forwarding channel object
    in a buffer suitable for calling the @ref assh_request
    function. This function fails when the provided buffer is not
    large enough. */
ASSH_WARN_UNUSED_RESULT assh_error_t
asshh_portfwd_encode_direct_tcpip(uint8_t *data, size_t size,
                               const struct asshh_portfwd_direct_tcpip_s *i);

/** @This requests a direct tcp/ip forwarding channel open.
    @csee asshh_portfwd_encode_direct_tcpip
    @see assh_channel_open */
ASSH_WARN_UNUSED_RESULT assh_error_t
asshh_portfwd_open_direct_tcpip(struct assh_session_s *s,
                             struct assh_channel_s **ch,
                             const struct asshh_portfwd_direct_tcpip_s *i);
#endif

#ifdef CONFIG_ASSH_SERVER

/** @This decodes the direct tcp/ip forwarding channel object
    from the passed buffer. The @tt data buffer must remain valid
    because string buffers are not copied. This function fails when
    the buffer contains invalid data. */
ASSH_WARN_UNUSED_RESULT assh_error_t
asshh_portfwd_decode_direct_tcpip(struct asshh_portfwd_direct_tcpip_s *i,
                               const uint8_t *data, size_t size);
#endif

#endif
