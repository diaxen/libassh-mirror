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

#include <assh/helper_interactive.h>
#include <assh/assh_packet.h>
#include <assh/assh_connection.h>

#ifdef CONFIG_ASSH_CLIENT
assh_status_t
asshh_inter_open_session(struct assh_session_s *s,
                        struct assh_channel_s **ch)

{
  assh_status_t err;
  ASSH_RET_ON_ERR(assh_channel_open(s, "session", 7, NULL, 0, -1, -1, ch));

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_CLIENT

void
asshh_inter_init_pty_req(struct asshh_inter_pty_req_s *i,
                        const char * termenv,
                        uint32_t char_width,
                        uint32_t char_height,
                        uint32_t pix_width,
                        uint32_t pix_height,
                        const uint8_t * modes)
{
  if (!termenv)
    termenv = "vt100";

  i->termenv.str = termenv;
  i->termenv.len = strlen(termenv);
  i->char_width = char_width;
  i->char_height = char_height;
  i->pix_width = pix_width;
  i->pix_height = pix_height;

  if (!modes)
    modes = (const uint8_t *)"\x00\x00";
  size_t modes_len = 0;
  while (modes[modes_len])
    modes_len += 2;
  i->modes.data = modes;
  i->modes.len = modes_len;
}

size_t
asshh_inter_size_pty_req(const struct asshh_inter_pty_req_s *i)
{
  return 4 + i->termenv.size             /* termenv */
       + 4                               /* char_width */
       + 4                               /* char_height */
       + 4                               /* pix_width */
       + 4                               /* pix_height */
       + 4 + i->modes.size               /* modes */
       ;
}

assh_status_t
asshh_inter_encode_pty_req(uint8_t *data, size_t size,
				const struct asshh_inter_pty_req_s *i)

{
  assh_status_t err;

  ASSH_RET_IF_TRUE(asshh_inter_size_pty_req(i) > size,
	       ASSH_ERR_OUTPUT_OVERFLOW);

  uint8_t *d = data;

  size_t termenv_size = i->termenv.size;
  assh_store_u32(d, termenv_size);
  memcpy(d + 4, i->termenv.data, termenv_size);
  d += 4 + termenv_size;

  assh_store_u32(d, i->char_width);
  d += 4;

  assh_store_u32(d, i->char_height);
  d += 4;

  assh_store_u32(d, i->pix_width);
  d += 4;

  assh_store_u32(d, i->pix_height);
  d += 4;

  size_t modes_size = i->modes.size;
  assh_store_u32(d, modes_size);
  memcpy(d + 4, i->modes.data, modes_size);

  return ASSH_OK;
}
assh_status_t
asshh_inter_send_pty_req(struct assh_session_s *s,
                        struct assh_channel_s *ch,
                        struct assh_request_s **rq,
                        const struct asshh_inter_pty_req_s *i)

{
  assh_status_t err;

  size_t sz = asshh_inter_size_pty_req(i);
  uint8_t buf[sz];

  ASSH_ASSERT(asshh_inter_encode_pty_req(buf, sz, i));
  ASSH_RET_ON_ERR(assh_request(s, ch, "pty-req", 7, buf, sz, rq));

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_SERVER

assh_status_t
asshh_inter_decode_pty_req(struct asshh_inter_pty_req_s *i,
                          const uint8_t *data, size_t size)

{
  assh_status_t err;
  const uint8_t *n, *d = data;

  ASSH_RET_ON_ERR(assh_check_string(data, size, d, &n));
  i->termenv.data = d + 4;
  i->termenv.size = n - d - 4;
  d = n;

  ASSH_RET_ON_ERR(assh_check_array(data, size, d, 16, &n));

  i->char_width = assh_load_u32(d);
  d += 4;

  i->char_height = assh_load_u32(d);
  d += 4;

  i->pix_width = assh_load_u32(d);
  d += 4;

  i->pix_height = assh_load_u32(d);
  d += 4;

  ASSH_RET_ON_ERR(assh_check_string(data, size, d, &n));
  i->modes.data = d + 4;
  i->modes.size = n - d - 4;

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_CLIENT

void
asshh_inter_init_x11_req(struct asshh_inter_x11_req_s *i,
                        assh_bool_t single,
                        const char * auth_protocol,
                        const struct assh_cbuffer_s * auth_cookie,
                        uint32_t screen)
{
  i->single = single;
  i->auth_protocol.str = auth_protocol;
  i->auth_protocol.len = auth_protocol ? strlen(auth_protocol) : 0;
  i->auth_cookie = *auth_cookie;
  i->screen = screen;
}

size_t
asshh_inter_size_x11_req(const struct asshh_inter_x11_req_s *i)
{
  return 1                               /* single */
       + 4 + i->auth_protocol.size       /* auth_protocol */
       + 4 + i->auth_cookie.size         /* auth_cookie */
       + 4                               /* screen */
       ;
}

assh_status_t
asshh_inter_encode_x11_req(uint8_t *data, size_t size,
				const struct asshh_inter_x11_req_s *i)

{
  assh_status_t err;

  ASSH_RET_IF_TRUE(asshh_inter_size_x11_req(i) > size,
	       ASSH_ERR_OUTPUT_OVERFLOW);

  uint8_t *d = data;

  *d++ = i->single;

  size_t auth_protocol_size = i->auth_protocol.size;
  assh_store_u32(d, auth_protocol_size);
  memcpy(d + 4, i->auth_protocol.data, auth_protocol_size);
  d += 4 + auth_protocol_size;

  size_t auth_cookie_size = i->auth_cookie.size;
  assh_store_u32(d, auth_cookie_size);
  memcpy(d + 4, i->auth_cookie.data, auth_cookie_size);
  d += 4 + auth_cookie_size;

  assh_store_u32(d, i->screen);

  return ASSH_OK;
}
assh_status_t
asshh_inter_send_x11_req(struct assh_session_s *s,
                        struct assh_channel_s *ch,
                        struct assh_request_s **rq,
                        const struct asshh_inter_x11_req_s *i)

{
  assh_status_t err;

  size_t sz = asshh_inter_size_x11_req(i);
  uint8_t buf[sz];

  ASSH_ASSERT(asshh_inter_encode_x11_req(buf, sz, i));
  ASSH_RET_ON_ERR(assh_request(s, ch, "x11-req", 7, buf, sz, rq));

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_SERVER

assh_status_t
asshh_inter_decode_x11_req(struct asshh_inter_x11_req_s *i,
                          const uint8_t *data, size_t size)

{
  assh_status_t err;
  const uint8_t *n, *d = data;

  ASSH_RET_ON_ERR(assh_check_array(data, size, d, 1, &n));

  i->single = *d++;

  ASSH_RET_ON_ERR(assh_check_string(data, size, d, &n));
  i->auth_protocol.data = d + 4;
  i->auth_protocol.size = n - d - 4;
  d = n;

  ASSH_RET_ON_ERR(assh_check_string(data, size, d, &n));
  i->auth_cookie.data = d + 4;
  i->auth_cookie.size = n - d - 4;
  d = n;

  ASSH_RET_ON_ERR(assh_check_array(data, size, d, 4, &n));

  i->screen = assh_load_u32(d);

  return ASSH_OK;
}
#endif

void
asshh_inter_init_x11(struct asshh_inter_x11_s *i,
                    const char * orig_addr,
                    uint32_t orig_port)
{
  i->orig_addr.str = orig_addr;
  i->orig_addr.len = orig_addr ? strlen(orig_addr) : 0;
  i->orig_port = orig_port;
}

size_t
asshh_inter_size_x11(const struct asshh_inter_x11_s *i)
{
  return 4 + i->orig_addr.size           /* orig_addr */
       + 4                               /* orig_port */
       ;
}

assh_status_t
asshh_inter_encode_x11(uint8_t *data, size_t size,
				const struct asshh_inter_x11_s *i)

{
  assh_status_t err;

  ASSH_RET_IF_TRUE(asshh_inter_size_x11(i) > size,
	       ASSH_ERR_OUTPUT_OVERFLOW);

  uint8_t *d = data;

  size_t orig_addr_size = i->orig_addr.size;
  assh_store_u32(d, orig_addr_size);
  memcpy(d + 4, i->orig_addr.data, orig_addr_size);
  d += 4 + orig_addr_size;

  assh_store_u32(d, i->orig_port);

  return ASSH_OK;
}
assh_status_t
asshh_inter_open_x11(struct assh_session_s *s,
                    struct assh_channel_s **ch,
                    const struct asshh_inter_x11_s *i)

{
  assh_status_t err;

  size_t sz = asshh_inter_size_x11(i);
  uint8_t buf[sz];

  ASSH_ASSERT(asshh_inter_encode_x11(buf, sz, i));
  ASSH_RET_ON_ERR(assh_channel_open(s, "x11", 3, buf, sz, -1, -1, ch));

  return ASSH_OK;
}

assh_status_t
asshh_inter_decode_x11(struct asshh_inter_x11_s *i,
                      const uint8_t *data, size_t size)

{
  assh_status_t err;
  const uint8_t *n, *d = data;

  ASSH_RET_ON_ERR(assh_check_string(data, size, d, &n));
  i->orig_addr.data = d + 4;
  i->orig_addr.size = n - d - 4;
  d = n;

  ASSH_RET_ON_ERR(assh_check_array(data, size, d, 4, &n));

  i->orig_port = assh_load_u32(d);

  return ASSH_OK;
}

#ifdef CONFIG_ASSH_CLIENT

void
asshh_inter_init_env(struct asshh_inter_env_s *i,
                    const char * name,
                    const char * value)
{
  i->name.str = name;
  i->name.len = name ? strlen(name) : 0;
  i->value.str = value;
  i->value.len = value ? strlen(value) : 0;
}

size_t
asshh_inter_size_env(const struct asshh_inter_env_s *i)
{
  return 4 + i->name.size                /* name */
       + 4 + i->value.size               /* value */
       ;
}

assh_status_t
asshh_inter_encode_env(uint8_t *data, size_t size,
				const struct asshh_inter_env_s *i)

{
  assh_status_t err;

  ASSH_RET_IF_TRUE(asshh_inter_size_env(i) > size,
	       ASSH_ERR_OUTPUT_OVERFLOW);

  uint8_t *d = data;

  size_t name_size = i->name.size;
  assh_store_u32(d, name_size);
  memcpy(d + 4, i->name.data, name_size);
  d += 4 + name_size;

  size_t value_size = i->value.size;
  assh_store_u32(d, value_size);
  memcpy(d + 4, i->value.data, value_size);

  return ASSH_OK;
}
assh_status_t
asshh_inter_send_env(struct assh_session_s *s,
                    struct assh_channel_s *ch,
                    struct assh_request_s **rq,
                    const struct asshh_inter_env_s *i)

{
  assh_status_t err;

  size_t sz = asshh_inter_size_env(i);
  uint8_t buf[sz];

  ASSH_ASSERT(asshh_inter_encode_env(buf, sz, i));
  ASSH_RET_ON_ERR(assh_request(s, ch, "env", 3, buf, sz, rq));

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_SERVER

assh_status_t
asshh_inter_decode_env(struct asshh_inter_env_s *i,
                      const uint8_t *data, size_t size)

{
  assh_status_t err;
  const uint8_t *n, *d = data;

  ASSH_RET_ON_ERR(assh_check_string(data, size, d, &n));
  i->name.data = d + 4;
  i->name.size = n - d - 4;
  d = n;

  ASSH_RET_ON_ERR(assh_check_string(data, size, d, &n));
  i->value.data = d + 4;
  i->value.size = n - d - 4;

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_CLIENT
assh_status_t
asshh_inter_send_shell(struct assh_session_s *s,
                      struct assh_channel_s *ch,
                      struct assh_request_s **rq)

{
  assh_status_t err;
  ASSH_RET_ON_ERR(assh_request(s, ch, "shell", 5, NULL, 0, rq));

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_CLIENT

void
asshh_inter_init_exec(struct asshh_inter_exec_s *i,
                     const char * command)
{
  i->command.str = command;
  i->command.len = command ? strlen(command) : 0;
}

size_t
asshh_inter_size_exec(const struct asshh_inter_exec_s *i)
{
  return 4 + i->command.size             /* command */
       ;
}

assh_status_t
asshh_inter_encode_exec(uint8_t *data, size_t size,
				const struct asshh_inter_exec_s *i)

{
  assh_status_t err;

  ASSH_RET_IF_TRUE(asshh_inter_size_exec(i) > size,
	       ASSH_ERR_OUTPUT_OVERFLOW);

  uint8_t *d = data;

  size_t command_size = i->command.size;
  assh_store_u32(d, command_size);
  memcpy(d + 4, i->command.data, command_size);

  return ASSH_OK;
}
assh_status_t
asshh_inter_send_exec(struct assh_session_s *s,
                     struct assh_channel_s *ch,
                     struct assh_request_s **rq,
                     const struct asshh_inter_exec_s *i)

{
  assh_status_t err;

  size_t sz = asshh_inter_size_exec(i);
  uint8_t buf[sz];

  ASSH_ASSERT(asshh_inter_encode_exec(buf, sz, i));
  ASSH_RET_ON_ERR(assh_request(s, ch, "exec", 4, buf, sz, rq));

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_SERVER

assh_status_t
asshh_inter_decode_exec(struct asshh_inter_exec_s *i,
                       const uint8_t *data, size_t size)

{
  assh_status_t err;
  const uint8_t *n, *d = data;

  ASSH_RET_ON_ERR(assh_check_string(data, size, d, &n));
  i->command.data = d + 4;
  i->command.size = n - d - 4;

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_CLIENT

void
asshh_inter_init_subsystem(struct asshh_inter_subsystem_s *i,
                          const char * name)
{
  i->name.str = name;
  i->name.len = name ? strlen(name) : 0;
}

size_t
asshh_inter_size_subsystem(const struct asshh_inter_subsystem_s *i)
{
  return 4 + i->name.size                /* name */
       ;
}

assh_status_t
asshh_inter_encode_subsystem(uint8_t *data, size_t size,
				const struct asshh_inter_subsystem_s *i)

{
  assh_status_t err;

  ASSH_RET_IF_TRUE(asshh_inter_size_subsystem(i) > size,
	       ASSH_ERR_OUTPUT_OVERFLOW);

  uint8_t *d = data;

  size_t name_size = i->name.size;
  assh_store_u32(d, name_size);
  memcpy(d + 4, i->name.data, name_size);

  return ASSH_OK;
}
assh_status_t
asshh_inter_send_subsystem(struct assh_session_s *s,
                          struct assh_channel_s *ch,
                          struct assh_request_s **rq,
                          const struct asshh_inter_subsystem_s *i)

{
  assh_status_t err;

  size_t sz = asshh_inter_size_subsystem(i);
  uint8_t buf[sz];

  ASSH_ASSERT(asshh_inter_encode_subsystem(buf, sz, i));
  ASSH_RET_ON_ERR(assh_request(s, ch, "subsystem", 9, buf, sz, rq));

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_SERVER

assh_status_t
asshh_inter_decode_subsystem(struct asshh_inter_subsystem_s *i,
                            const uint8_t *data, size_t size)

{
  assh_status_t err;
  const uint8_t *n, *d = data;

  ASSH_RET_ON_ERR(assh_check_string(data, size, d, &n));
  i->name.data = d + 4;
  i->name.size = n - d - 4;

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_CLIENT

void
asshh_inter_init_window_change(struct asshh_inter_window_change_s *i,
                              uint32_t char_width,
                              uint32_t char_height,
                              uint32_t pix_width,
                              uint32_t pix_height)
{
  i->char_width = char_width;
  i->char_height = char_height;
  i->pix_width = pix_width;
  i->pix_height = pix_height;
}

size_t
asshh_inter_size_window_change(const struct asshh_inter_window_change_s *i)
{
  return 4                               /* char_width */
       + 4                               /* char_height */
       + 4                               /* pix_width */
       + 4                               /* pix_height */
       ;
}

assh_status_t
asshh_inter_encode_window_change(uint8_t *data, size_t size,
				const struct asshh_inter_window_change_s *i)

{
  assh_status_t err;

  ASSH_RET_IF_TRUE(asshh_inter_size_window_change(i) > size,
	       ASSH_ERR_OUTPUT_OVERFLOW);

  uint8_t *d = data;

  assh_store_u32(d, i->char_width);
  d += 4;

  assh_store_u32(d, i->char_height);
  d += 4;

  assh_store_u32(d, i->pix_width);
  d += 4;

  assh_store_u32(d, i->pix_height);

  return ASSH_OK;
}
assh_status_t
asshh_inter_send_window_change(struct assh_session_s *s,
                              struct assh_channel_s *ch,
                              const struct asshh_inter_window_change_s *i)

{
  assh_status_t err;

  size_t sz = asshh_inter_size_window_change(i);
  uint8_t buf[sz];

  ASSH_ASSERT(asshh_inter_encode_window_change(buf, sz, i));
  ASSH_RET_ON_ERR(assh_request(s, ch, "window-change", 13, buf, sz, NULL));

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_SERVER

assh_status_t
asshh_inter_decode_window_change(struct asshh_inter_window_change_s *i,
                                const uint8_t *data, size_t size)

{
  assh_status_t err;
  const uint8_t *n, *d = data;

  ASSH_RET_ON_ERR(assh_check_array(data, size, d, 16, &n));

  i->char_width = assh_load_u32(d);
  d += 4;

  i->char_height = assh_load_u32(d);
  d += 4;

  i->pix_width = assh_load_u32(d);
  d += 4;

  i->pix_height = assh_load_u32(d);

  return ASSH_OK;
}
#endif

void
asshh_inter_init_xon_xoff(struct asshh_inter_xon_xoff_s *i,
                         assh_bool_t client_can_do)
{
  i->client_can_do = client_can_do;
}

size_t
asshh_inter_size_xon_xoff(const struct asshh_inter_xon_xoff_s *i)
{
  return 1                               /* client_can_do */
       ;
}

assh_status_t
asshh_inter_encode_xon_xoff(uint8_t *data, size_t size,
				const struct asshh_inter_xon_xoff_s *i)

{
  assh_status_t err;

  ASSH_RET_IF_TRUE(asshh_inter_size_xon_xoff(i) > size,
	       ASSH_ERR_OUTPUT_OVERFLOW);

  uint8_t *d = data;

  *d++ = i->client_can_do;

  return ASSH_OK;
}
assh_status_t
asshh_inter_send_xon_xoff(struct assh_session_s *s,
                         struct assh_channel_s *ch,
                         const struct asshh_inter_xon_xoff_s *i)

{
  assh_status_t err;

  size_t sz = asshh_inter_size_xon_xoff(i);
  uint8_t buf[sz];

  ASSH_ASSERT(asshh_inter_encode_xon_xoff(buf, sz, i));
  ASSH_RET_ON_ERR(assh_request(s, ch, "xon-xoff", 8, buf, sz, NULL));

  return ASSH_OK;
}

assh_status_t
asshh_inter_decode_xon_xoff(struct asshh_inter_xon_xoff_s *i,
                           const uint8_t *data, size_t size)

{
  assh_status_t err;
  const uint8_t *n, *d = data;

  ASSH_RET_ON_ERR(assh_check_array(data, size, d, 1, &n));

  i->client_can_do = *d++;

  return ASSH_OK;
}

#ifdef CONFIG_ASSH_CLIENT

void
asshh_inter_init_signal(struct asshh_inter_signal_s *i,
                       const char * sig_name)
{
  i->sig_name.str = sig_name;
  i->sig_name.len = sig_name ? strlen(sig_name) : 0;
}

size_t
asshh_inter_size_signal(const struct asshh_inter_signal_s *i)
{
  return 4 + i->sig_name.size            /* sig_name */
       ;
}

assh_status_t
asshh_inter_encode_signal(uint8_t *data, size_t size,
				const struct asshh_inter_signal_s *i)

{
  assh_status_t err;

  ASSH_RET_IF_TRUE(asshh_inter_size_signal(i) > size,
	       ASSH_ERR_OUTPUT_OVERFLOW);

  uint8_t *d = data;

  size_t sig_name_size = i->sig_name.size;
  assh_store_u32(d, sig_name_size);
  memcpy(d + 4, i->sig_name.data, sig_name_size);

  return ASSH_OK;
}
assh_status_t
asshh_inter_send_signal(struct assh_session_s *s,
                       struct assh_channel_s *ch,
                       const struct asshh_inter_signal_s *i)

{
  assh_status_t err;

  size_t sz = asshh_inter_size_signal(i);
  uint8_t buf[sz];

  ASSH_ASSERT(asshh_inter_encode_signal(buf, sz, i));
  ASSH_RET_ON_ERR(assh_request(s, ch, "signal", 6, buf, sz, NULL));

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_SERVER

assh_status_t
asshh_inter_decode_signal(struct asshh_inter_signal_s *i,
                         const uint8_t *data, size_t size)

{
  assh_status_t err;
  const uint8_t *n, *d = data;

  ASSH_RET_ON_ERR(assh_check_string(data, size, d, &n));
  i->sig_name.data = d + 4;
  i->sig_name.size = n - d - 4;

  return ASSH_OK;
}
#endif

void
asshh_inter_init_exit_status(struct asshh_inter_exit_status_s *i,
                            uint32_t status)
{
  i->status = status;
}

size_t
asshh_inter_size_exit_status(const struct asshh_inter_exit_status_s *i)
{
  return 4                               /* status */
       ;
}

assh_status_t
asshh_inter_encode_exit_status(uint8_t *data, size_t size,
				const struct asshh_inter_exit_status_s *i)

{
  assh_status_t err;

  ASSH_RET_IF_TRUE(asshh_inter_size_exit_status(i) > size,
	       ASSH_ERR_OUTPUT_OVERFLOW);

  uint8_t *d = data;

  assh_store_u32(d, i->status);

  return ASSH_OK;
}
assh_status_t
asshh_inter_send_exit_status(struct assh_session_s *s,
                            struct assh_channel_s *ch,
                            const struct asshh_inter_exit_status_s *i)

{
  assh_status_t err;

  size_t sz = asshh_inter_size_exit_status(i);
  uint8_t buf[sz];

  ASSH_ASSERT(asshh_inter_encode_exit_status(buf, sz, i));
  ASSH_RET_ON_ERR(assh_request(s, ch, "exit-status", 11, buf, sz, NULL));

  return ASSH_OK;
}

assh_status_t
asshh_inter_decode_exit_status(struct asshh_inter_exit_status_s *i,
                              const uint8_t *data, size_t size)

{
  assh_status_t err;
  const uint8_t *n, *d = data;

  ASSH_RET_ON_ERR(assh_check_array(data, size, d, 4, &n));

  i->status = assh_load_u32(d);

  return ASSH_OK;
}

void
asshh_inter_init_exit_signal(struct asshh_inter_exit_signal_s *i,
                            const char * sig_name,
                            assh_bool_t core,
                            const char * errmsg,
                            const char * lang)
{
  i->sig_name.str = sig_name;
  i->sig_name.len = sig_name ? strlen(sig_name) : 0;
  i->core = core;
  i->errmsg.str = errmsg;
  i->errmsg.len = errmsg ? strlen(errmsg) : 0;
  i->lang.str = lang;
  i->lang.len = lang ? strlen(lang) : 0;
}

size_t
asshh_inter_size_exit_signal(const struct asshh_inter_exit_signal_s *i)
{
  return 4 + i->sig_name.size            /* sig_name */
       + 1                               /* core */
       + 4 + i->errmsg.size              /* errmsg */
       + 4 + i->lang.size                /* lang */
       ;
}

assh_status_t
asshh_inter_encode_exit_signal(uint8_t *data, size_t size,
				const struct asshh_inter_exit_signal_s *i)

{
  assh_status_t err;

  ASSH_RET_IF_TRUE(asshh_inter_size_exit_signal(i) > size,
	       ASSH_ERR_OUTPUT_OVERFLOW);

  uint8_t *d = data;

  size_t sig_name_size = i->sig_name.size;
  assh_store_u32(d, sig_name_size);
  memcpy(d + 4, i->sig_name.data, sig_name_size);
  d += 4 + sig_name_size;

  *d++ = i->core;

  size_t errmsg_size = i->errmsg.size;
  assh_store_u32(d, errmsg_size);
  memcpy(d + 4, i->errmsg.data, errmsg_size);
  d += 4 + errmsg_size;

  size_t lang_size = i->lang.size;
  assh_store_u32(d, lang_size);
  memcpy(d + 4, i->lang.data, lang_size);

  return ASSH_OK;
}
assh_status_t
asshh_inter_send_exit_signal(struct assh_session_s *s,
                            struct assh_channel_s *ch,
                            const struct asshh_inter_exit_signal_s *i)

{
  assh_status_t err;

  size_t sz = asshh_inter_size_exit_signal(i);
  uint8_t buf[sz];

  ASSH_ASSERT(asshh_inter_encode_exit_signal(buf, sz, i));
  ASSH_RET_ON_ERR(assh_request(s, ch, "exit-signal", 11, buf, sz, NULL));

  return ASSH_OK;
}

assh_status_t
asshh_inter_decode_exit_signal(struct asshh_inter_exit_signal_s *i,
                              const uint8_t *data, size_t size)

{
  assh_status_t err;
  const uint8_t *n, *d = data;

  ASSH_RET_ON_ERR(assh_check_string(data, size, d, &n));
  i->sig_name.data = d + 4;
  i->sig_name.size = n - d - 4;
  d = n;

  ASSH_RET_ON_ERR(assh_check_array(data, size, d, 1, &n));

  i->core = *d++;

  ASSH_RET_ON_ERR(assh_check_string(data, size, d, &n));
  i->errmsg.data = d + 4;
  i->errmsg.size = n - d - 4;
  d = n;

  ASSH_RET_ON_ERR(assh_check_string(data, size, d, &n));
  i->lang.data = d + 4;
  i->lang.size = n - d - 4;

  return ASSH_OK;
}

