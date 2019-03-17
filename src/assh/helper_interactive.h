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
   @short SSH interactive session helpers (rfc4254 interactive sessions)

   This headers file provides some @hl{helper functions} able load
   and store data embedded in standard @hl requests and
   @hl channels open messages related to the @hl{interactive
   sessions} features of @em {ssh2}.

   @xsee {connapi}
   @see @assh/assh_connection.h
*/

#ifndef ASSH_HELPER_INTERACTIVE_H_
#define ASSH_HELPER_INTERACTIVE_H_

#include "assh.h"
#include "assh_buffer.h"

#ifdef CONFIG_ASSH_CLIENT

/** @This requests a interactive session start open.
    @see assh_channel_open */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_open_session(struct assh_session_s *s,
                        struct assh_channel_s **ch);
#endif

/** @This specifies the pty request object. */
struct assh_inter_pty_req_s
{
  struct assh_cbuffer_s            termenv;
  uint32_t                         char_width;
  uint32_t                         char_height;
  uint32_t                         pix_width;
  uint32_t                         pix_height;
  struct assh_cbuffer_s            modes;
};

#ifdef CONFIG_ASSH_CLIENT

/** @This initializes a pty request object.
    Any buffer passed to the function is not copied and
    must remain valid. */
void
assh_inter_init_pty_req(struct assh_inter_pty_req_s *i,
                        const char * termenv,
                        uint32_t char_width,
                        uint32_t char_height,
                        uint32_t pix_width,
                        uint32_t pix_height,
                        const uint8_t * modes);

/** @This returns the size of the buffer required to encode a
    pty request object. */
size_t
assh_inter_size_pty_req(const struct assh_inter_pty_req_s *i);

/** @This encodes the pty request object in a buffer suitable
    for calling the @ref assh_request function. This function fails
    when the provided buffer is not large enough. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_encode_pty_req(uint8_t *data, size_t size,
                          const struct assh_inter_pty_req_s *i);

/** @This encodes and sends a pty request
    @csee assh_inter_encode_pty_req
    @see assh_request */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_send_pty_req(struct assh_session_s *s,
                        struct assh_channel_s *ch,
                        struct assh_request_s **rq,
                        const struct assh_inter_pty_req_s *i);
#endif

#ifdef CONFIG_ASSH_SERVER

/** @This decodes the pty request object from the passed
    buffer. The @tt data buffer must remain valid because string
    buffers are not copied. This function fails when the buffer contains
    invalid data. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_decode_pty_req(struct assh_inter_pty_req_s *i,
                          const uint8_t *data, size_t size);
#endif

/** @This specifies the x11 forwarding request object. */
struct assh_inter_x11_req_s
{
  assh_bool_t                      single;
  struct assh_cbuffer_s            auth_protocol;
  struct assh_cbuffer_s            auth_cookie;
  uint32_t                         screen;
};

#ifdef CONFIG_ASSH_CLIENT

/** @This initializes a x11 forwarding request object.
    Any buffer passed to the function is not copied and
    must remain valid. */
void
assh_inter_init_x11_req(struct assh_inter_x11_req_s *i,
                        assh_bool_t single,
                        const char * auth_protocol,
                        const struct assh_cbuffer_s * auth_cookie,
                        uint32_t screen);

/** @This returns the size of the buffer required to encode a
    x11 forwarding request object. */
size_t
assh_inter_size_x11_req(const struct assh_inter_x11_req_s *i);

/** @This encodes the x11 forwarding request object in a
    buffer suitable for calling the @ref assh_request function. This
    function fails when the provided buffer is not large enough. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_encode_x11_req(uint8_t *data, size_t size,
                          const struct assh_inter_x11_req_s *i);

/** @This encodes and sends a x11 forwarding request
    @csee assh_inter_encode_x11_req
    @see assh_request */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_send_x11_req(struct assh_session_s *s,
                        struct assh_channel_s *ch,
                        struct assh_request_s **rq,
                        const struct assh_inter_x11_req_s *i);
#endif

#ifdef CONFIG_ASSH_SERVER

/** @This decodes the x11 forwarding request object from the
    passed buffer. The @tt data buffer must remain valid because
    string buffers are not copied. This function fails when the buffer
    contains invalid data. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_decode_x11_req(struct assh_inter_x11_req_s *i,
                          const uint8_t *data, size_t size);
#endif

/** @This specifies the x11 channel object. */
struct assh_inter_x11_s
{
  struct assh_cbuffer_s            orig_addr;
  uint32_t                         orig_port;
};

/** @This initializes a x11 channel object.
    Any buffer passed to the function is not copied and
    must remain valid. */
void
assh_inter_init_x11(struct assh_inter_x11_s *i,
                    const char * orig_addr,
                    uint32_t orig_port);

/** @This returns the size of the buffer required to encode a
    x11 channel object. */
size_t
assh_inter_size_x11(const struct assh_inter_x11_s *i);

/** @This encodes the x11 channel object in a buffer suitable
    for calling the @ref assh_request function. This function fails
    when the provided buffer is not large enough. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_encode_x11(uint8_t *data, size_t size,
                      const struct assh_inter_x11_s *i);

/** @This requests a x11 channel open.
    @csee assh_inter_encode_x11
    @see assh_channel_open */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_open_x11(struct assh_session_s *s,
                    struct assh_channel_s **ch,
                    const struct assh_inter_x11_s *i);

/** @This decodes the x11 channel object from the passed
    buffer. The @tt data buffer must remain valid because string
    buffers are not copied. This function fails when the buffer
    contains invalid data. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_decode_x11(struct assh_inter_x11_s *i,
                      const uint8_t *data, size_t size);

/** @This specifies the environment variable object. */
struct assh_inter_env_s
{
  struct assh_cbuffer_s            name;
  struct assh_cbuffer_s            value;
};

#ifdef CONFIG_ASSH_CLIENT

/** @This initializes a environment variable object.
    Any buffer passed to the function is not copied and
    must remain valid. */
void
assh_inter_init_env(struct assh_inter_env_s *i,
                    const char * name,
                    const char * value);

/** @This returns the size of the buffer required to encode a
    environment variable object. */
size_t
assh_inter_size_env(const struct assh_inter_env_s *i);

/** @This encodes the environment variable object in a buffer
    suitable for calling the @ref assh_request function. This function
    fails when the provided buffer is not large enough. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_encode_env(uint8_t *data, size_t size,
                      const struct assh_inter_env_s *i);

/** @This encodes and sends a environment variable
    @csee assh_inter_encode_env
    @see assh_request */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_send_env(struct assh_session_s *s,
                    struct assh_channel_s *ch,
                    struct assh_request_s **rq,
                    const struct assh_inter_env_s *i);
#endif

#ifdef CONFIG_ASSH_SERVER

/** @This decodes the environment variable object from the
    passed buffer. The @tt data buffer must remain valid because
    string buffers are not copied. This function fails when the buffer
    contains invalid data. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_decode_env(struct assh_inter_env_s *i,
                      const uint8_t *data, size_t size);
#endif

#ifdef CONFIG_ASSH_CLIENT

/** @This encodes and sends a shell execution
    @see assh_request */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_send_shell(struct assh_session_s *s,
                      struct assh_channel_s *ch,
                      struct assh_request_s **rq);
#endif

/** @This specifies the command execution object. */
struct assh_inter_exec_s
{
  struct assh_cbuffer_s            command;
};

#ifdef CONFIG_ASSH_CLIENT

/** @This initializes a command execution object.
    Any buffer passed to the function is not copied and
    must remain valid. */
void
assh_inter_init_exec(struct assh_inter_exec_s *i,
                     const char * command);

/** @This returns the size of the buffer required to encode a
    command execution object. */
size_t
assh_inter_size_exec(const struct assh_inter_exec_s *i);

/** @This encodes the command execution object in a buffer
    suitable for calling the @ref assh_request function. This function
    fails when the provided buffer is not large enough. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_encode_exec(uint8_t *data, size_t size,
                       const struct assh_inter_exec_s *i);

/** @This encodes and sends a command execution
    @csee assh_inter_encode_exec
    @see assh_request */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_send_exec(struct assh_session_s *s,
                     struct assh_channel_s *ch,
                     struct assh_request_s **rq,
                     const struct assh_inter_exec_s *i);
#endif

#ifdef CONFIG_ASSH_SERVER

/** @This decodes the command execution object from the
    passed buffer. The @tt data buffer must remain valid because
    string buffers are not copied. This function fails when the buffer
    contains invalid data. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_decode_exec(struct assh_inter_exec_s *i,
                       const uint8_t *data, size_t size);
#endif

/** @This specifies the subsystem execution object. */
struct assh_inter_subsystem_s
{
  struct assh_cbuffer_s            name;
};

#ifdef CONFIG_ASSH_CLIENT

/** @This initializes a subsystem execution object.
    Any buffer passed to the function is not copied and
    must remain valid. */
void
assh_inter_init_subsystem(struct assh_inter_subsystem_s *i,
                          const char * name);

/** @This returns the size of the buffer required to encode a
    subsystem execution object. */
size_t
assh_inter_size_subsystem(const struct assh_inter_subsystem_s *i);

/** @This encodes the subsystem execution object in a buffer
    suitable for calling the @ref assh_request function. This function
    fails when the provided buffer is not large enough. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_encode_subsystem(uint8_t *data, size_t size,
                            const struct assh_inter_subsystem_s *i);

/** @This encodes and sends a subsystem execution
    @csee assh_inter_encode_subsystem
    @see assh_request */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_send_subsystem(struct assh_session_s *s,
                          struct assh_channel_s *ch,
                          struct assh_request_s **rq,
                          const struct assh_inter_subsystem_s *i);
#endif

#ifdef CONFIG_ASSH_SERVER

/** @This decodes the subsystem execution object from the
    passed buffer. The @tt data buffer must remain valid because
    string buffers are not copied. This function fails when the buffer
    contains invalid data. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_decode_subsystem(struct assh_inter_subsystem_s *i,
                            const uint8_t *data, size_t size);
#endif

/** @This specifies the window size changed object. */
struct assh_inter_window_change_s
{
  uint32_t                         char_width;
  uint32_t                         char_height;
  uint32_t                         pix_width;
  uint32_t                         pix_height;
};

#ifdef CONFIG_ASSH_CLIENT

/** @This initializes a window size changed object.
    Any buffer passed to the function is not copied and
    must remain valid. */
void
assh_inter_init_window_change(struct assh_inter_window_change_s *i,
                              uint32_t char_width,
                              uint32_t char_height,
                              uint32_t pix_width,
                              uint32_t pix_height);

/** @This returns the size of the buffer required to encode a
    window size changed object. */
size_t
assh_inter_size_window_change(const struct assh_inter_window_change_s *i);

/** @This encodes the window size changed object in a buffer
    suitable for calling the @ref assh_request function. This function
    fails when the provided buffer is not large enough. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_encode_window_change(uint8_t *data, size_t size,
                                const struct assh_inter_window_change_s *i);

/** @This encodes and sends a window size changed
    @csee assh_inter_encode_window_change
    @see assh_request */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_send_window_change(struct assh_session_s *s,
                              struct assh_channel_s *ch,
                              const struct assh_inter_window_change_s *i);
#endif

#ifdef CONFIG_ASSH_SERVER

/** @This decodes the window size changed object from the
    passed buffer. The @tt data buffer must remain valid because
    string buffers are not copied. This function fails when the buffer
    contains invalid data. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_decode_window_change(struct assh_inter_window_change_s *i,
                                const uint8_t *data, size_t size);
#endif

/** @This specifies the client xon/xoff allowed object. */
struct assh_inter_xon_xoff_s
{
  assh_bool_t                      client_can_do;
};

/** @This initializes a client xon/xoff allowed object.
    Any buffer passed to the function is not copied and
    must remain valid. */
void
assh_inter_init_xon_xoff(struct assh_inter_xon_xoff_s *i,
                         assh_bool_t client_can_do);

/** @This returns the size of the buffer required to encode a
    client xon/xoff allowed object. */
size_t
assh_inter_size_xon_xoff(const struct assh_inter_xon_xoff_s *i);

/** @This encodes the client xon/xoff allowed object in a
    buffer suitable for calling the @ref assh_request function. This
    function fails when the provided buffer is not large enough. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_encode_xon_xoff(uint8_t *data, size_t size,
                           const struct assh_inter_xon_xoff_s *i);

/** @This encodes and sends a client xon/xoff allowed
    @csee assh_inter_encode_xon_xoff
    @see assh_request */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_send_xon_xoff(struct assh_session_s *s,
                         struct assh_channel_s *ch,
                         const struct assh_inter_xon_xoff_s *i);

/** @This decodes the client xon/xoff allowed object from the
    passed buffer. The @tt data buffer must remain valid because
    string buffers are not copied. This function fails when the buffer
    contains invalid data. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_decode_xon_xoff(struct assh_inter_xon_xoff_s *i,
                           const uint8_t *data, size_t size);

/** @This specifies the signal delivery object. */
struct assh_inter_signal_s
{
  struct assh_cbuffer_s            sig_name;
};

#ifdef CONFIG_ASSH_CLIENT

/** @This initializes a signal delivery object.
    Any buffer passed to the function is not copied and
    must remain valid. */
void
assh_inter_init_signal(struct assh_inter_signal_s *i,
                       const char * sig_name);

/** @This returns the size of the buffer required to encode a
    signal delivery object. */
size_t
assh_inter_size_signal(const struct assh_inter_signal_s *i);

/** @This encodes the signal delivery object in a buffer
    suitable for calling the @ref assh_request function. This function
    fails when the provided buffer is not large enough. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_encode_signal(uint8_t *data, size_t size,
                         const struct assh_inter_signal_s *i);

/** @This encodes and sends a signal delivery
    @csee assh_inter_encode_signal
    @see assh_request */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_send_signal(struct assh_session_s *s,
                       struct assh_channel_s *ch,
                       const struct assh_inter_signal_s *i);
#endif

#ifdef CONFIG_ASSH_SERVER

/** @This decodes the signal delivery object from the passed
    buffer. The @tt data buffer must remain valid because string
    buffers are not copied. This function fails when the buffer
    contains invalid data. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_decode_signal(struct assh_inter_signal_s *i,
                         const uint8_t *data, size_t size);
#endif

/** @This specifies the command exit status object. */
struct assh_inter_exit_status_s
{
  uint32_t                         status;
};

/** @This initializes a command exit status object.
    Any buffer passed to the function is not copied and
    must remain valid. */
void
assh_inter_init_exit_status(struct assh_inter_exit_status_s *i,
                            uint32_t status);

/** @This returns the size of the buffer required to encode a
    command exit status object. */
size_t
assh_inter_size_exit_status(const struct assh_inter_exit_status_s *i);

/** @This encodes the command exit status object in a buffer
    suitable for calling the @ref assh_request function. This function
    fails when the provided buffer is not large enough. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_encode_exit_status(uint8_t *data, size_t size,
                              const struct assh_inter_exit_status_s *i);

/** @This encodes and sends a command exit status
    @csee assh_inter_encode_exit_status
    @see assh_request */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_send_exit_status(struct assh_session_s *s,
                            struct assh_channel_s *ch,
                            const struct assh_inter_exit_status_s *i);

/** @This decodes the command exit status object from the
    passed buffer. The @tt data buffer must remain valid because
    string buffers are not copied. This function fails when the buffer
    contains invalid data. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_decode_exit_status(struct assh_inter_exit_status_s *i,
                              const uint8_t *data, size_t size);

/** @This specifies the command kill status object. */
struct assh_inter_exit_signal_s
{
  struct assh_cbuffer_s            sig_name;
  assh_bool_t                      core;
  struct assh_cbuffer_s            errmsg;
  struct assh_cbuffer_s            lang;
};

/** @This initializes a command kill status object.
    Any buffer passed to the function is not copied and
    must remain valid. */
void
assh_inter_init_exit_signal(struct assh_inter_exit_signal_s *i,
                            const char * sig_name,
                            assh_bool_t core,
                            const char * errmsg,
                            const char * lang);

/** @This returns the size of the buffer required to encode a
    command kill status object. */
size_t
assh_inter_size_exit_signal(const struct assh_inter_exit_signal_s *i);

/** @This encodes the command kill status object in a buffer
    suitable for calling the @ref assh_request function. This function
    fails when the provided buffer is not large enough. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_encode_exit_signal(uint8_t *data, size_t size,
                              const struct assh_inter_exit_signal_s *i);

/** @This encodes and sends a command kill status
    @csee assh_inter_encode_exit_signal
    @see assh_request */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_send_exit_signal(struct assh_session_s *s,
                            struct assh_channel_s *ch,
                            const struct assh_inter_exit_signal_s *i);

/** @This decodes the command kill status object from the passed
    buffer. The @tt data buffer must remain valid because string
    buffers are not copied. This function fails when the buffer contains
    invalid data. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_inter_decode_exit_signal(struct assh_inter_exit_signal_s *i,
                              const uint8_t *data, size_t size);


#endif
