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

static ASSH_SERVICE_INIT_FCN(assh_service_ssh_connection_init)
{
  return ASSH_OK;
}

static ASSH_SERVICE_CLEANUP_FCN(assh_service_ssh_connection_cleanup)
{
}

static ASSH_PROCESS_FCN(assh_service_ssh_connection_process)
{
  return ASSH_OK;
}

const struct assh_service_s assh_service_ssh_connection =
{
  .name = "ssh-connection",
  .f_init = assh_service_ssh_connection_init,
  .f_cleanup = assh_service_ssh_connection_cleanup,
  .f_process = assh_service_ssh_connection_process,  
};

