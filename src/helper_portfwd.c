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

#include <assh/helper_portfwd.h>
#include <assh/assh_packet.h>
#include <assh/assh_connection.h>

#ifdef CONFIG_ASSH_CLIENT

void
assh_portfwd_init_tcpip_forward(struct assh_portfwd_tcpip_forward_s *i,
                              const char * addr,
                              uint32_t port)
{
  i->addr.str = addr;
  i->addr.len = addr ? strlen(addr) : 0;
  i->port = port;
}

size_t
assh_portfwd_size_tcpip_forward(const struct assh_portfwd_tcpip_forward_s *i)
{
  return 4 + i->addr.size                /* addr */
       + 4                               /* port */
       ;
}

assh_error_t
assh_portfwd_encode_tcpip_forward(uint8_t *data, size_t size,
				const struct assh_portfwd_tcpip_forward_s *i)

{
  assh_error_t err;

  ASSH_RET_IF_TRUE(assh_portfwd_size_tcpip_forward(i) > size,
	       ASSH_ERR_OUTPUT_OVERFLOW);

  uint8_t *d = data;

  size_t addr_size = i->addr.size;
  assh_store_u32(d, addr_size);
  memcpy(d + 4, i->addr.data, addr_size);
  d += 4 + addr_size;

  assh_store_u32(d, i->port);

  return ASSH_OK;
}
assh_error_t
assh_portfwd_send_tcpip_forward(struct assh_session_s *s,
                              struct assh_request_s **rq,
                              const struct assh_portfwd_tcpip_forward_s *i)

{
  assh_error_t err;

  size_t sz = assh_portfwd_size_tcpip_forward(i);
  uint8_t buf[sz];

  ASSH_ASSERT(assh_portfwd_encode_tcpip_forward(buf, sz, i));
  ASSH_RET_ON_ERR(assh_request(s, NULL, "tcpip-forward", 13, buf, sz, rq));

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_SERVER

assh_error_t
assh_portfwd_decode_tcpip_forward(struct assh_portfwd_tcpip_forward_s *i,
                                const uint8_t *data, size_t size)

{
  assh_error_t err;
  const uint8_t *n, *d = data;

  ASSH_RET_ON_ERR(assh_check_string(data, size, d, &n));
  i->addr.data = d + 4;
  i->addr.size = n - d - 4;
  d = n;

  ASSH_RET_ON_ERR(assh_check_array(data, size, d, 4, &n));

  i->port = assh_load_u32(d);

  return ASSH_OK;
}
#endif

void
assh_portfwd_init_tcpip_forward_reply(struct assh_portfwd_tcpip_forward_reply_s *i,
                                    uint32_t port)
{
  i->port = port;
}

size_t
assh_portfwd_size_tcpip_forward_reply(const struct assh_portfwd_tcpip_forward_reply_s *i)
{
  return 4                               /* port */
       ;
}

assh_error_t
assh_portfwd_encode_tcpip_forward_reply(uint8_t *data, size_t size,
				const struct assh_portfwd_tcpip_forward_reply_s *i)

{
  assh_error_t err;

  ASSH_RET_IF_TRUE(assh_portfwd_size_tcpip_forward_reply(i) > size,
	       ASSH_ERR_OUTPUT_OVERFLOW);

  uint8_t *d = data;

  assh_store_u32(d, i->port);

  return ASSH_OK;
}

assh_error_t
assh_portfwd_decode_tcpip_forward_reply(struct assh_portfwd_tcpip_forward_reply_s *i,
                                      const uint8_t *data, size_t size)

{
  assh_error_t err;
  const uint8_t *n, *d = data;

  ASSH_RET_ON_ERR(assh_check_array(data, size, d, 4, &n));

  i->port = assh_load_u32(d);

  return ASSH_OK;
}

#ifdef CONFIG_ASSH_CLIENT

void
assh_portfwd_init_cancel_tcpip_forward(struct assh_portfwd_cancel_tcpip_forward_s *i,
                                     const char * addr,
                                     uint32_t port)
{
  i->addr.str = addr;
  i->addr.len = addr ? strlen(addr) : 0;
  i->port = port;
}

size_t
assh_portfwd_size_cancel_tcpip_forward(const struct assh_portfwd_cancel_tcpip_forward_s *i)
{
  return 4 + i->addr.size                /* addr */
       + 4                               /* port */
       ;
}

assh_error_t
assh_portfwd_encode_cancel_tcpip_forward(uint8_t *data, size_t size,
				const struct assh_portfwd_cancel_tcpip_forward_s *i)

{
  assh_error_t err;

  ASSH_RET_IF_TRUE(assh_portfwd_size_cancel_tcpip_forward(i) > size,
	       ASSH_ERR_OUTPUT_OVERFLOW);

  uint8_t *d = data;

  size_t addr_size = i->addr.size;
  assh_store_u32(d, addr_size);
  memcpy(d + 4, i->addr.data, addr_size);
  d += 4 + addr_size;

  assh_store_u32(d, i->port);

  return ASSH_OK;
}
assh_error_t
assh_portfwd_send_cancel_tcpip_forward(struct assh_session_s *s,
                                     struct assh_request_s **rq,
                                     const struct assh_portfwd_cancel_tcpip_forward_s *i)

{
  assh_error_t err;

  size_t sz = assh_portfwd_size_cancel_tcpip_forward(i);
  uint8_t buf[sz];

  ASSH_ASSERT(assh_portfwd_encode_cancel_tcpip_forward(buf, sz, i));
  ASSH_RET_ON_ERR(assh_request(s, NULL, "cancel-tcpip-forward", 20, buf, sz, rq));

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_SERVER

assh_error_t
assh_portfwd_decode_cancel_tcpip_forward(struct assh_portfwd_cancel_tcpip_forward_s *i,
                                       const uint8_t *data, size_t size)

{
  assh_error_t err;
  const uint8_t *n, *d = data;

  ASSH_RET_ON_ERR(assh_check_string(data, size, d, &n));
  i->addr.data = d + 4;
  i->addr.size = n - d - 4;
  d = n;

  ASSH_RET_ON_ERR(assh_check_array(data, size, d, 4, &n));

  i->port = assh_load_u32(d);

  return ASSH_OK;
}
#endif

void
assh_portfwd_init_forwarded_tcpip(struct assh_portfwd_forwarded_tcpip_s *i,
                                const char * conn_addr,
                                uint32_t conn_port,
                                const char * orig_addr,
                                uint32_t orig_port)
{
  i->conn_addr.str = conn_addr;
  i->conn_addr.len = conn_addr ? strlen(conn_addr) : 0;
  i->conn_port = conn_port;
  i->orig_addr.str = orig_addr;
  i->orig_addr.len = orig_addr ? strlen(orig_addr) : 0;
  i->orig_port = orig_port;
}

size_t
assh_portfwd_size_forwarded_tcpip(const struct assh_portfwd_forwarded_tcpip_s *i)
{
  return 4 + i->conn_addr.size           /* conn_addr */
       + 4                               /* conn_port */
       + 4 + i->orig_addr.size            /* orig_addr */
       + 4                               /* orig_port */
       ;
}

assh_error_t
assh_portfwd_encode_forwarded_tcpip(uint8_t *data, size_t size,
				const struct assh_portfwd_forwarded_tcpip_s *i)

{
  assh_error_t err;

  ASSH_RET_IF_TRUE(assh_portfwd_size_forwarded_tcpip(i) > size,
	       ASSH_ERR_OUTPUT_OVERFLOW);

  uint8_t *d = data;

  size_t conn_addr_size = i->conn_addr.size;
  assh_store_u32(d, conn_addr_size);
  memcpy(d + 4, i->conn_addr.data, conn_addr_size);
  d += 4 + conn_addr_size;

  assh_store_u32(d, i->conn_port);
  d += 4;

  size_t orig_addr_size = i->orig_addr.size;
  assh_store_u32(d, orig_addr_size);
  memcpy(d + 4, i->orig_addr.data, orig_addr_size);
  d += 4 + orig_addr_size;

  assh_store_u32(d, i->orig_port);

  return ASSH_OK;
}
assh_error_t
assh_portfwd_open_forwarded_tcpip(struct assh_session_s *s,
                                struct assh_channel_s **ch,
                                const struct assh_portfwd_forwarded_tcpip_s *i)

{
  assh_error_t err;

  size_t sz = assh_portfwd_size_forwarded_tcpip(i);
  uint8_t buf[sz];

  ASSH_ASSERT(assh_portfwd_encode_forwarded_tcpip(buf, sz, i));
  ASSH_RET_ON_ERR(assh_channel_open(s, "forwarded-tcpip", 15, buf, sz, -1, -1, ch));

  return ASSH_OK;
}

assh_error_t
assh_portfwd_decode_forwarded_tcpip(struct assh_portfwd_forwarded_tcpip_s *i,
                                  const uint8_t *data, size_t size)

{
  assh_error_t err;
  const uint8_t *n, *d = data;

  ASSH_RET_ON_ERR(assh_check_string(data, size, d, &n));
  i->conn_addr.data = d + 4;
  i->conn_addr.size = n - d - 4;
  d = n;

  ASSH_RET_ON_ERR(assh_check_array(data, size, d, 4, &n));

  i->conn_port = assh_load_u32(d);
  d += 4;

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
assh_portfwd_init_direct_tcpip(struct assh_portfwd_direct_tcpip_s *i,
                             const char * conn_addr,
                             uint32_t conn_port,
                             const char * orig_addr,
                             uint32_t orig_port)
{
  i->conn_addr.str = conn_addr;
  i->conn_addr.len = conn_addr ? strlen(conn_addr) : 0;
  i->conn_port = conn_port;
  i->orig_addr.str = orig_addr;
  i->orig_addr.len = orig_addr ? strlen(orig_addr) : 0;
  i->orig_port = orig_port;
}

size_t
assh_portfwd_size_direct_tcpip(const struct assh_portfwd_direct_tcpip_s *i)
{
  return 4 + i->conn_addr.size           /* conn_addr */
       + 4                               /* conn_port */
       + 4 + i->orig_addr.size            /* orig_addr */
       + 4                               /* orig_port */
       ;
}

assh_error_t
assh_portfwd_encode_direct_tcpip(uint8_t *data, size_t size,
				const struct assh_portfwd_direct_tcpip_s *i)

{
  assh_error_t err;

  ASSH_RET_IF_TRUE(assh_portfwd_size_direct_tcpip(i) > size,
	       ASSH_ERR_OUTPUT_OVERFLOW);

  uint8_t *d = data;

  size_t conn_addr_size = i->conn_addr.size;
  assh_store_u32(d, conn_addr_size);
  memcpy(d + 4, i->conn_addr.data, conn_addr_size);
  d += 4 + conn_addr_size;

  assh_store_u32(d, i->conn_port);
  d += 4;

  size_t orig_addr_size = i->orig_addr.size;
  assh_store_u32(d, orig_addr_size);
  memcpy(d + 4, i->orig_addr.data, orig_addr_size);
  d += 4 + orig_addr_size;

  assh_store_u32(d, i->orig_port);

  return ASSH_OK;
}
assh_error_t
assh_portfwd_open_direct_tcpip(struct assh_session_s *s,
                             struct assh_channel_s **ch,
                             const struct assh_portfwd_direct_tcpip_s *i)

{
  assh_error_t err;

  size_t sz = assh_portfwd_size_direct_tcpip(i);
  uint8_t buf[sz];

  ASSH_ASSERT(assh_portfwd_encode_direct_tcpip(buf, sz, i));
  ASSH_RET_ON_ERR(assh_channel_open(s, "direct-tcpip", 12, buf, sz, -1, -1, ch));

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_SERVER

assh_error_t
assh_portfwd_decode_direct_tcpip(struct assh_portfwd_direct_tcpip_s *i,
				 const uint8_t *data, size_t size)

{
  assh_error_t err;
  const uint8_t *n, *d = data;

  ASSH_RET_ON_ERR(assh_check_string(data, size, d, &n));
  i->conn_addr.data = d + 4;
  i->conn_addr.size = n - d - 4;
  d = n;

  ASSH_RET_ON_ERR(assh_check_array(data, size, d, 4, &n));

  i->conn_port = assh_load_u32(d);
  d += 4;

  ASSH_RET_ON_ERR(assh_check_string(data, size, d, &n));
  i->orig_addr.data = d + 4;
  i->orig_addr.size = n - d - 4;
  d = n;

  ASSH_RET_ON_ERR(assh_check_array(data, size, d, 4, &n));

  i->orig_port = assh_load_u32(d);

  return ASSH_OK;
}
#endif
