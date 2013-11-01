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

#include <assh/assh_service.h>
#include <assh/assh_session.h>

static ASSH_SERVICE_INIT_FCN(assh_connection_client_init)
{
  s->srv = &assh_service_connection_client;

  return ASSH_OK;
}

static ASSH_SERVICE_CLEANUP_FCN(assh_connection_client_cleanup)
{
  s->srv = NULL;
}

static ASSH_PROCESS_FCN(assh_connection_client_process)
{
  return ASSH_OK;
}

const struct assh_service_s assh_service_connection_client =
{
  .name = "ssh-connection",
  .side = ASSH_CLIENT,
  .f_init = assh_connection_client_init,
  .f_cleanup = assh_connection_client_cleanup,
  .f_process = assh_connection_client_process,  
};

