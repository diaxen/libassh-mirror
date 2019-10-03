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

/*
  This test replay some ssh sessions and check the generated ssh
  streams against files. Unlike some of other tests where the library
  is tested against itself, this test is able to check for
  compatibility with other implementations. It uses a dummy random
  generator with constant output which allows keeping the stream
  invariant between runs.

  This test may break even with valid stream if the library behavior
  is changed. When this happen, the CONFIG_ASSH_DEBUG macro must be
  enabled in order to be able to examine the stream differences. The
  library must then be validated against other implementations with
  the same set of algorithms as used in the failing tests before
  accepting the new test stream.

  The stream file is composed of chunks with this format:

    1 byte chunk type:
      0: assh server to client packet
      1: assh client to server packet
      2: remote server to client packet
      3: remote client to server packet
      4: server algorithm register
      5: client algorithm register
      6: server key load
      7: client key load
      8: kex threshold
      9: auth username
      10: client password list
      11: client user key
      12: client keyboard replies
      13: authentication params
      14: client keyboard prompt info
      15: client hostbased host
      16: client hostbased key
      17: max iterations before disconnect
      18: command line

    2 bytes :
      chunk size N
    N bytes :
      data

    For chunk types 0 to 3, data is the ssh stream content.

    For chunk types 4 and 5, data layout is:
      1 byte algo class
      2 bytes: algorithm name len
      N bytes: algorithm name

    For chunk types 6, 7, 11 and 16, data layout is:
      1 byte: key format
      1 byte: key role
      2 byte: algo name len
      N bytes: algo name
      N bytes: key blob

    For chunk types 9, 10, 12, 14 and 15, data layout is:
      N bytes: name

    For chunk types 13 data layout is:
      8*2: authentication related params as uint16

*/

#include <assh/assh_session.h>
#include <assh/assh_context.h>
#include <assh/assh_kex.h>
#include <assh/assh_cipher.h>
#include <assh/assh_sign.h>
#include <assh/assh_mac.h>
#include <assh/assh_compress.h>
#include <assh/assh_transport.h>
#include <assh/assh_connection.h>
#include <assh/assh_service.h>
#include <assh/assh_userauth_client.h>
#include <assh/assh_userauth_server.h>
#include <assh/assh_event.h>
#include <assh/helper_key.h>
#include <assh/helper_io.h>

#include <assh/key_rsa.h>
#include <assh/key_dsa.h>
#include <assh/key_eddsa.h>
#include <assh/key_ecdsa.h>

#define FIFO_BUF_SIZE CONFIG_ASSH_MAX_PAYLOAD

#include "leaks_check.h"
#include "fifo.h"
#include "test.h"
#include "keys.h"
#include "prng_weak.h"

#include <stdio.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <dirent.h>
#include <fnmatch.h>
#include <signal.h>

enum action_e
{
  REPLAY_SERVER = 1,
  REPLAY_CLIENT = 2,
  REPLAY_CLIENT_SERVER  = 3,
  RECORD_SERVER_CONNECT = 5,
  RECORD_CLIENT_CONNECT = 6,
  RECORD_CLIENT_SERVER  = 7,
};

enum chunk_type_e
{
  CHUNK_PKT_SRV2CLI       = 0,
  CHUNK_PKT_CLI2SRV       = 1,
  CHUNK_PKT_REMOTE2CLI    = 2,
  CHUNK_PKT_REMOTE2SRV    = 3,
  CHUNK_SRV_ALGO          = 4,
  CHUNK_CLI_ALGO          = 5,
  CHUNK_SRV_KEY           = 6,
  CHUNK_CLI_KEY           = 7,
  CHUNK_KEX_TH            = 8,
  CHUNK_USERNAME          = 9,
  CHUNK_PASSWORDS         = 10,
  CHUNK_USER_KEY          = 11,
  CHUNK_KEYBOARD_REPLIES  = 12,
  CHUNK_AUTH              = 13,
  CHUNK_KEYBOARD_INFOS    = 14,
  CHUNK_HOSTBASED_HOST    = 15,
  CHUNK_HOSTBASED_KEY     = 16,
  CHUNK_MAX_ITERS         = 17,
  CHUNK_COMMAND_LINE      = 18,
};

static int usage()
{
  fprintf(stderr, "usage: replay record|replay|replay_all [-h | options]\n");

  fprintf(stderr,
	  "Options:\n\n"

	  "    -h         show help\n"
	  "    -v         increase verbosity\n"
	  "    -R         save raw ssh streams for use in fuzzer corpus\n\n"

	  "Options usable with replay:\n\n"

	  "    -f file      specify the input .ssh stream file.\n\n"

	  "Options usable with replay_all:\n\n"

	  "    -d path      specify the directory of .ssh stream files.\n\n"

 	  "Options usable with record:\n\n"
	  "    -f file      specify the output .ssh stream file.\n"
	  "    -s           accept connect from a remote client\n"
	  "                 instead of running an assh client session.\n"
	  "    -c           connect to a remote server\n"
	  "                 instead of running an assh server session.\n"
	  "    -p port      specify the tcp port.\n"
	  "    -t N         set the re-kex threshold in bytes.\n"
	  "    -b T:algo    select an algorithm for both server and client side.\n"
	  "                 T specifis the algorithm type:\n"
	  "                   k:kex, s:sign, c:cipher, m:mac, C:compress\n"

	  "  Client only options:\n"
	  "    -H host      specify the remote server address.\n"
	  "    -a T:algo    select an algorithm for the client side only.\n"
	  "    -u name      specify a login name for user authentication.\n"
	  "    -P pass,pass specify a list of passwords to try.\n"
	  "    -k file      load an userauth user key file.\n"
	  "    -k algo:bits create an userauth user key.\n"
	  "    -y r,r,r,... specify the keyboard authentication replies.\n"
	  "    -K file      load an userauth host file key.\n"
	  "    -K algo:bits create an userauth host key.\n"
	  "    -S host      specify the userauth host name.\n"
	  "    -i N         make client disconnects after N iterations.\n\n"

	  "  Server only options:\n"
	  "    -A T:algo    select an algorithm for the server side only.\n"
	  "    -j file      load a host key file for the server side.\n"
	  "    -j algo:bits create a host key for the server side.\n"
	  "    -J file      load a kex key file for the server side.\n"
	  "    -j algo:bits create a kex key for the server side.\n"
	  "    -J algo:bits create a host key for the server side.\n"
	  "    -w 0102...   reverse list of userauth password decisions\n"
	  "                 (0:fail, 1:success, 2:pw change request).\n"
	  "    -O 0|1       host key accept decision.\n"
	  "    -l 01010...  reverse list of userauth pubkey decisions.\n"
	  "    -o 01010...  reverse list of userauth hostbased decisions.\n"
	  "    -Y a,b;c,d   list of keyboard userauth prompts.\n"
	  "    -B 01010...  reverse list of keyboard userauth decisions.\n"
	  "    -n 01010...  reverse list of userauth none decisions.\n"
	  "    -M mask      override server userauth methods in use.\n"
	  "    -F N         specify the number of multi factor auths.\n"
	  "    -I N         make server disconnects after N iterations.\n"
	  );

  exit(1);
}

static enum action_e action = REPLAY_CLIENT_SERVER;
static struct fifo_s fifo[2];
static struct assh_context_s context[2];
static struct assh_session_s session[2];
static FILE *f_out;
static FILE *f_in[2];
static int sock;
static int verbose = 0;
static uint32_t kex_th = 0;

static int save_raw = 0;
static FILE *f_raw_cli_out = NULL;
static FILE *f_raw_srv_out = NULL;

/* client */
static char *username = NULL;
static char *password = NULL;
static char *keyboard_replies = NULL;
static struct assh_key_s *userauth_keys = NULL;
static struct assh_key_s *hostbased_keys = NULL;
static char *hostbased_host = NULL;
static assh_bool_t hostkey_accept = 1;

/* server */
static enum assh_userauth_methods_e userauth_server = 0;
static uint16_t none_accepts = 0;
static uint16_t userkey_accepts = 0; /* 1 bit per try */
static uint16_t hostbased_accepts = 0; /* 1 bit per try */
static uint16_t password_accepts = 0; /* 2 bit per try */
static uint16_t keyboard_accepts = 0; /* 2 bit per try */
static char *keyboard_infos = NULL;
static uint_fast8_t multi_auth = 0;

static uint32_t iter[2];
static uint32_t max_iter[2] = { 0, 0 };

static void term_handler(int sig)
{
  static assh_bool_t stop = 0;

  /* first signal will only make recv return */
  if (stop)
    exit(1);

  if (action == RECORD_CLIENT_SERVER ||
      action == RECORD_SERVER_CONNECT)
    fprintf(stderr, "[server] iterations: %u\n", iter[0]);
  if (action == RECORD_CLIENT_SERVER ||
      action == RECORD_CLIENT_CONNECT)
    fprintf(stderr, "[client] iterations: %u\n", iter[1]);

  if (action == RECORD_CLIENT_SERVER)
    exit(1);

  stop = 1;
}

/*************************************************** FILE helpers */

static void open_raw_files(const char *fname)
{
  size_t len = strlen(fname);
  char *fcli = alloca(len + 5);
  char *fsrv = alloca(len + 5);
  memcpy(fcli, fname, len);
  memcpy(fsrv, fname, len);
  strcpy(fcli + len, ".cli");
  strcpy(fsrv + len, ".srv");
  f_raw_cli_out = fopen(fcli, "wb");
  f_raw_srv_out = fopen(fsrv, "wb");
  if (!f_raw_cli_out)
    TEST_FAIL("Unable to write: `%s' : %s\n", fcli, strerror(errno));
  if (!f_raw_srv_out)
    TEST_FAIL("Unable to write: `%s' : %s\n", fsrv, strerror(errno));
}

static void close_raw_files()
{
  fclose(f_raw_cli_out);
  fclose(f_raw_srv_out);
}

static void raw_write(int i, const uint8_t *data, size_t size)
{
  if (i)
    {
      if (f_raw_cli_out &&
	  fwrite(data, size, 1, f_raw_cli_out) != 1)
	TEST_FAIL("client raw stream write\n");
    }
  else
    {
      if (f_raw_srv_out &&
	  fwrite(data, size, 1, f_raw_srv_out) != 1)
	TEST_FAIL("server raw stream write\n");
    }
}

static uint16_t fget_u16(FILE *f)
{
  int r = fgetc(f);
  return (r << 8) | fgetc(f);
}

static uint32_t fget_u32(FILE *f)
{
  int r = fgetc(f);
  r = (r << 8) | fgetc(f);
  r = (r << 8) | fgetc(f);
  return (r << 8) | fgetc(f);
}

static void fput_u16(uint16_t x, FILE *f)
{
  fputc(x >> 8, f);
  fputc(x & 0xff, f);
}

static void fput_u32(uint32_t x, FILE *f)
{
  fputc(x >> 24, f);
  fputc(x >> 16, f);
  fputc(x >> 8, f);
  fputc(x & 0xff, f);
}

static int fget_dir(FILE *f, int dir)
{
  while (1)
    {
      int d = fgetc(f);
      if (d < 0 || (d < 4 && dir == (d & 1)))
	return d;
      /* skip chunk if direction does not match */
      int s = fget_u16(f);
      fseek(f, s, SEEK_CUR);
    }
}

/*************************************************** main loop */

static void test()
{
  unsigned i;
  for (i = 0; i < 2; i++)
    {
      struct assh_context_s *c = &context[i];

      fifo_init(&fifo[i]);
      iter[i] = 0;

      switch (action)
	{
	case RECORD_CLIENT_CONNECT:
	case REPLAY_CLIENT:
	  if (i == 0)
	    continue;
	  break;

	case RECORD_SERVER_CONNECT:
	case REPLAY_SERVER:
	  if (i == 1)
	    continue;
	  break;

	case RECORD_CLIENT_SERVER:
	case REPLAY_CLIENT_SERVER:
	  break;

	default:
	  ASSH_UNREACHABLE();
	}

      if (assh_service_register_va(c, i ? &assh_service_userauth_client
				        : &assh_service_userauth_server,
				   &assh_service_connection, NULL))
	TEST_FAIL("service register\n");

      if (assh_session_init(c, &session[i]))
	TEST_FAIL("sessions init failed, no algorithms ?\n");

      if (kex_th)
	if (assh_kex_set_threshold(&session[i], kex_th))
	  TEST_FAIL("set kex threshold");
    }

  uint_fast8_t stall = 0;
  uint_fast8_t running = 3;

  uint_fast8_t started = 0;
  struct assh_channel_s *ch[2];

  char *password_p = password;
  char *kbrps_p = keyboard_replies;
  char *kbinfo_p = keyboard_infos;

  while (running)
    {
      for (i = 0; i < 2; i++)
	{
	  struct assh_event_s event;
	  assh_status_t everr = ASSH_OK;
	  const char *side = i ? "client" : "server";

	  ASSH_DEBUG("---- %s %u ----\n", side, iter[i]);

	  switch (action)
	    {
	    case RECORD_CLIENT_CONNECT:
	      if (i == 1)
		break;
	      goto read_from_network;
	    case RECORD_SERVER_CONNECT:
	      if (i == 0)
		break;
	    read_from_network: {
	      uint8_t buf[CONFIG_ASSH_MAX_PAYLOAD];
	      struct pollfd p;
	      p.fd = sock;
	      p.events = POLLIN;
	      switch (poll(&p, 1, 100))
		{
		case 1: {
		  ssize_t r = recv(sock, buf, sizeof(buf), 0);
		  if (r > 0)
		    {
		      if (verbose > 2)
			assh_hexdump(i ? "remote client -> server"
				: "remote server -> client"
				, buf, r);
		      fifo_write(&fifo[i ^ 1], buf, r);
		      raw_write(i ^ 1, buf, r);

		      fputc(i | 2, f_out);
		      fput_u16(r, f_out);
		      fwrite(buf, r, 1, f_out);
		    }
		  else
		    {
		      running &= ~(1 << i);
		    }
		  break;
		}

		case 0:
		  continue;
		case -1:
		  running &= ~(1 << i);
		}
	      continue;
	    }

	    case REPLAY_CLIENT:
	      if (i == 1)
		break;
	      goto replay_from_file;
	    case REPLAY_SERVER:
	      if (i == 0)
		break;

	    replay_from_file: {
		if (((running >> !i) & 1) &&
		    fifo[i ^ 1].size != 0)
		  continue;

		/* replay packets from file */
		int d = fget_dir(f_in[i], i);

		if (d < 0)
		  {
		    running &= ~(1 << i);
		    if (verbose > 2)
		      fprintf(stderr, "[%s] EOF\n", side);
		    continue;
		  }

		int s = fget_u16(f_in[i]);
		if (s < 0)
		  TEST_FAIL("unexpected end of stream\n");
		uint8_t st[s];
		if (fread(st, 1, s, f_in[i]) != s)
		  TEST_FAIL("unexpected end of stream\n");
		fifo_write(&fifo[i ^ 1], st, s);
		raw_write(i ^ 1, st, s);
		if (verbose > 2)
		  assh_hexdump(i ? "replay client -> server"
			  : "replay server -> client", st, s);
		continue;
	      }

	    case RECORD_CLIENT_SERVER:
	    case REPLAY_CLIENT_SERVER:
	      break;

	    default:
	      ASSH_UNREACHABLE();
	    }

	  if (!((running >> i) & 1))
	    continue;

	  if ((started >> i) & 1)
	    {
	      uint8_t data[256];
	      if (assh_prng_get(&context[i], data, sizeof(data), ASSH_PRNG_QUALITY_WEAK))
		TEST_FAIL("prng get\n");
	      size_t size = data[0] + !data[0];
	      assh_channel_data(ch[i], (const uint8_t*)data, &size);
	    }

	  if (!assh_event_get(&session[i], &event, 0))
	    {
	      if (verbose > 0)
		fprintf(stderr, "[%s] No more event\n", side);
	      running &= ~(1 << i);
	      continue;
	    }

	  if (verbose > 2)
	    fprintf(stderr, "[%s] event %u\n", side, event.id);

	  switch (event.id)
	    {
	    case ASSH_EVENT_SESSION_ERROR:
	      if (verbose > 0)
		fprintf(stderr, "[%s] Error event: %s\n", side,
			assh_error_str(event.session.error.code));
	      break;

	    case ASSH_EVENT_DISCONNECT:
	      if (verbose > 0)
		fprintf(stderr, "[%s] Disconnect event: 0x%x, %.*s\n", side,
			event.transport.disconnect.reason,
			(int)event.transport.disconnect.desc.len,
			event.transport.disconnect.desc.str
			);
	      break;

	    case ASSH_EVENT_DEBUG:
	      if (verbose > 0)
		fprintf(stderr, "[%s] Debug event: %u, %.*s\n", side,
			event.transport.debug.display,
			(int)event.transport.debug.msg.len,
			event.transport.debug.msg.str
			);
	      break;

	    case ASSH_EVENT_KEX_HOSTKEY_LOOKUP:
	      if (verbose > 0)
		fprintf(stderr, "[%s] Host key lookup.\n", side);
	      assert(i == 1);
	      event.kex.hostkey_lookup.accept = hostkey_accept;
	      break;

	    case ASSH_EVENT_KEX_DONE:
	      if (verbose > 0)
		fprintf(stderr, "[%s] Kex done.\n", side);
	      if (verbose > 1)
		asshh_print_kex_details(&session[i], stderr, &event);
	      break;

	    case ASSH_EVENT_SERVICE_START:
	      if (verbose > 0)
		fprintf(stderr, "[%s] Service start: %s\n", side, event.service.start.srv->name);
	      if (event.service.start.srv == &assh_service_connection &&
		  /* client */ i == 1)
		{
		  if (assh_channel_open(&session[i], "session", 7, NULL, 0, -1, -1, &ch[i]))
		    TEST_FAIL("unable to open session channel\n");
		}
	      break;

	    case ASSH_EVENT_USERAUTH_CLIENT_USER:
	      assh_buffer_strset(&event.userauth_client.user.username, username);
	      break;
	    case ASSH_EVENT_USERAUTH_CLIENT_METHODS:
	      if (verbose > 0)
		fprintf(stderr, "[client] Userauth methods: ");

	      if ((event.userauth_client.methods.methods &
		   ASSH_USERAUTH_METHOD_PASSWORD) && password_p && *password_p)
		{
		  char *p = password_p;
		  password_p = strchr(password_p, ',');
		  if (password_p)
		    *password_p++ = '\0';
		  assh_buffer_strset(&event.userauth_client.methods.password, p);

		  event.userauth_client.methods.select = ASSH_USERAUTH_METHOD_PASSWORD;
		  if (verbose > 0)
		    fprintf(stderr, "Password %s\n", p);
		}

	      else if ((event.userauth_client.methods.methods &
			ASSH_USERAUTH_METHOD_PUBKEY) && userauth_keys)
		{
		  event.userauth_client.methods.keys = userauth_keys;
		  userauth_keys = NULL;

		  event.userauth_client.methods.select = ASSH_USERAUTH_METHOD_PUBKEY;
		  if (verbose > 0)
		    fprintf(stderr, "User key\n");
		}

	      else if ((event.userauth_client.methods.methods &
			ASSH_USERAUTH_METHOD_KEYBOARD) &&
		       kbrps_p && *kbrps_p)
		{
		  event.userauth_client.methods.select = ASSH_USERAUTH_METHOD_KEYBOARD;
		  assh_buffer_strset(&event.userauth_client.methods.keyboard_sub, "pam");
		  if (verbose > 0)
		    fprintf(stderr, "Keyboard\n");
		}

	      else if ((event.userauth_client.methods.methods &
			ASSH_USERAUTH_METHOD_HOSTBASED) && hostbased_keys)
		{
		  event.userauth_client.methods.keys = hostbased_keys;
		  hostbased_keys = NULL;

		  assh_buffer_strset(&event.userauth_client.methods.host_name,
				     hostbased_host ? hostbased_host : "localhost");
		  assh_buffer_strset(&event.userauth_client.methods.host_username,
				     username);

		  event.userauth_client.methods.select = ASSH_USERAUTH_METHOD_HOSTBASED;
		  if (verbose > 0)
		    fprintf(stderr, "Host based\n");
		}

	      else
		{
		  if (verbose > 0)
		    fprintf(stderr, "Void\n");
		}
	      break;
	    case ASSH_EVENT_USERAUTH_CLIENT_BANNER:
	      if (verbose > 0)
		fprintf(stderr, "[client] Userauth banner.\n");
	      break;
	    case ASSH_EVENT_USERAUTH_CLIENT_PWCHANGE:
	      if (verbose > 0)
		fprintf(stderr, "[client] Userauth password change.\n");
	      break;

	    case ASSH_EVENT_USERAUTH_CLIENT_KEYBOARD: {
	      uint_fast8_t i;
	      if (verbose > 0)
		fprintf(stderr, "[client] Userauth keyboard: ");
	      for (i = 0; i < event.userauth_client.keyboard.count; i++)
		{
		  char *p = kbrps_p;
		  if (*p)
		    {
		      kbrps_p = strchr(kbrps_p, ',');
		      if (kbrps_p)
			*kbrps_p++ = '\0';
		    }
		  assh_buffer_strset(&event.userauth_client.keyboard.responses[i], p);
		  if (verbose > 0)
		    fprintf(stderr, "`%s'", p);
		}
	      if (verbose > 0)
		fprintf(stderr, "\n");
	      break;
	    }

	    case ASSH_EVENT_USERAUTH_CLIENT_SUCCESS:
	      if (verbose > 0)
		fprintf(stderr, "[client] Userauth success.\n");
	      break;

	    case ASSH_EVENT_USERAUTH_CLIENT_SIGN:
	      if (verbose > 0)
		fprintf(stderr, "[client] Userauth sign.\n");
	      break;

	    case ASSH_EVENT_USERAUTH_SERVER_METHODS:
	      event.userauth_server.methods.methods = userauth_server;
	      if (verbose > 0)
		fprintf(stderr, "[server] Userauth methods: %x\n",
			userauth_server);
	      break;

	    case ASSH_EVENT_USERAUTH_SERVER_NONE:
	      event.userauth_server.none.accept = none_accepts & 1;
	      none_accepts >>= 1;
	      if (verbose > 0)
		fprintf(stderr, "[server] Userauth none.\n");
	      break;

	    case ASSH_EVENT_USERAUTH_SERVER_USERKEY:
	      event.userauth_server.userkey.found = userkey_accepts & 1;
	      userkey_accepts >>= 1;
	      if (verbose > 0)
		fprintf(stderr, "[server] Userauth public key: %u\n",
			event.userauth_server.userkey.found);
	      break;

	    case ASSH_EVENT_USERAUTH_SERVER_PASSWORD:
	      event.userauth_server.password.result = password_accepts & 3;
	      password_accepts >>= 2;
	      if (verbose > 0)
		fprintf(stderr, "[server] Userauth password: %u\n",
			event.userauth_server.password.result);
	      break;

	    case ASSH_EVENT_USERAUTH_SERVER_KBINFO: {
	      static struct assh_cbuffer_s bufs[8];
	      uint_fast8_t i = 0;

	      assh_buffer_strset(&event.userauth_server.kbinfo.name,
				 "name");
	      assh_buffer_strset(&event.userauth_server.kbinfo.instruction,
				 "instruction");

	      if (verbose > 0)
		fprintf(stderr, "[server] Userauth kbinfo: ");

	      while (*kbinfo_p && i < 8)
		{
		  char *n = kbinfo_p + strcspn(kbinfo_p, ";,");
		  bufs[i].str = kbinfo_p;
		  bufs[i].len = n - kbinfo_p;
		  if (verbose > 0)
		    fprintf(stderr, "`%.*s' ", (int)(n - kbinfo_p), kbinfo_p);
		  i++;
		  kbinfo_p = n;
		  if (*n)
		    {
		      kbinfo_p++;
		      if (*n == ';')
			break;
		    }
		}

	      event.userauth_server.kbinfo.count = i;
	      event.userauth_server.kbinfo.prompts = bufs;

	      if (verbose > 0)
		fprintf(stderr, "\n");
	      break;
	    }

	    case ASSH_EVENT_USERAUTH_SERVER_KBRESPONSE:
	      event.userauth_server.kbresponse.result = keyboard_accepts & 3;
	      keyboard_accepts >>= 2;
	      if (verbose > 0)
		fprintf(stderr, "[server] Userauth kbresponse: %u\n",
			event.userauth_server.kbresponse.result);
	      break;

	    case ASSH_EVENT_USERAUTH_SERVER_HOSTBASED:
	      event.userauth_server.hostbased.found = hostbased_accepts & 1;
	      hostbased_accepts >>= 1;
	      if (verbose > 0)
		fprintf(stderr, "[server] Userauth hostbased: %u\n",
			event.userauth_server.hostbased.found);
	      break;

	    case ASSH_EVENT_USERAUTH_SERVER_SUCCESS:
	      if (verbose > 0)
		fprintf(stderr, "[server] Userauth success.\n");

	      if (multi_auth)
		{
		  event.userauth_server.success.methods = userauth_server;
		  multi_auth--;
		}

	      break;

	    case ASSH_EVENT_CHANNEL_OPEN:
	      event.connection.channel_open.reply = ASSH_CONNECTION_REPLY_SUCCESS;
	      break;

	    case ASSH_EVENT_CHANNEL_CLOSE:
	      started &= ~(1 << i);
	      break;

	    case ASSH_EVENT_CHANNEL_CONFIRMATION:
	      assert(i == 1);
	      started |= 1 << i;
	      break;

	    case ASSH_EVENT_CHANNEL_DATA:
	      event.connection.channel_data.transferred =
		event.connection.channel_data.data.size;
	      break;

	    case ASSH_EVENT_READ: {
	      struct assh_event_transport_read_s *te = &event.transport.read;
	      if (fifo[i].size == 0)
		{
		  if (!((running >> !i) & 1))
		    everr = ASSH_ERR_IO;
		  else
		    stall++;
		}
	      else
		{
		  te->transferred = fifo_read(&fifo[i], te->buf.data, te->buf.size);
		}

	      if (te->transferred == te->buf.size)
		iter[i]++;

	      break;
	    }

	    case ASSH_EVENT_WRITE: {
	      struct assh_event_transport_write_s *te = &event.transport.write;

	      if (session[i].stream_out_size == 0)
		{
		  switch (action)
		    {
		    case RECORD_CLIENT_CONNECT:
		    case RECORD_SERVER_CONNECT:
		    case RECORD_CLIENT_SERVER:
		      fputc(i, f_out);
		      fput_u16(te->buf.size, f_out);
		      fwrite(te->buf.data, te->buf.size, 1, f_out);
		      if (verbose > 2)
			{
			  fprintf(stderr, "[%s] iterations: %u\n", side, iter[i]);
			  assh_hexdump(i ? "client -> server" : "server -> client",
				       te->buf.data, te->buf.size);
			}
		      break;

		    case REPLAY_CLIENT:
		    case REPLAY_SERVER:
		    case REPLAY_CLIENT_SERVER: {
		      if (verbose > 2)
			{
			  fprintf(stderr, "[%s] iterations: %u\n", side, iter[i]);
			  assh_hexdump(i ? "client -> server" : "server -> client",
				       te->buf.data, te->buf.size);
			}
		      int d = fget_dir(f_in[i], i);
		      if (d < 0)
			TEST_FAIL("unexpected end of stream\n");
		      int s = fget_u16(f_in[i]);
		      uint8_t st[s];
		      if (fread(st, 1, s, f_in[i]) != s)
			TEST_FAIL("unexpected end of stream\n");
		      if (s != te->buf.size || memcmp(st, te->buf.data, s))
			{
			  assh_hexdump("expected", st, s);
			  assh_hexdump("unexpected", te->buf.data, s);
			  TEST_FAIL("stream chunk with unexpected content\n");
			}
		      break;
		    }
		    }
		}

	      switch (action)
		{
		case RECORD_CLIENT_SERVER:
		case REPLAY_CLIENT_SERVER:
		  stall++;
		  if ((te->buf.size != 0) && (fifo[i ^ 1].size != FIFO_BUF_SIZE))
		    stall = 0;
		  te->transferred = fifo_write(&fifo[i ^ 1], te->buf.data, te->buf.size);
		  break;
		case RECORD_CLIENT_CONNECT:
		case RECORD_SERVER_CONNECT: {
		  int r = send(sock, te->buf.data, te->buf.size, 0);
		  if (r < 0)
		    everr = ASSH_ERR_IO;
		  te->transferred = r;
		  break;
		}
		case REPLAY_CLIENT:
		case REPLAY_SERVER:
		  te->transferred = te->buf.size;
		  break;
		}

	      raw_write(i ^ 1, te->buf.data, te->transferred);

	      break;
	    }

	    default:
	      ASSH_DEBUG("event %u not handled\n", event.id);
	    }

	  assh_event_done(&session[i], &event, everr);

	  if (max_iter[i] && iter[i] == max_iter[i])
	    {
	      if (verbose > 0)
		fprintf(stderr, "[%s] max iterations reached, disconnecting\n", side);
	      assh_session_disconnect(&session[i], SSH_DISCONNECT_BY_APPLICATION, NULL);
	    }

	  if (action == RECORD_CLIENT_SERVER)
	    {
	      if (stall >= 100)
		TEST_FAIL("stalled %u\n", i);
	    }
	}
    }

  switch (action)
    {
    case REPLAY_CLIENT_SERVER:
      if (fget_dir(f_in[0], 0) >= 0)
	TEST_FAIL("end of server stream not reached\n");
      if (fget_dir(f_in[1], 1) >= 0)
	TEST_FAIL("end of client stream not reached\n");
      break;
    case REPLAY_SERVER:
      if (fget_dir(f_in[0], 0) >= 0)
	TEST_FAIL("end of server stream not reached\n");
      break;
    case REPLAY_CLIENT:
      if (fget_dir(f_in[1], 1) >= 0)
	TEST_FAIL("end of client stream not reached\n");
      break;
    case RECORD_CLIENT_SERVER:
    case RECORD_SERVER_CONNECT:
    case RECORD_CLIENT_CONNECT:
      break;
    }

  switch (action)
    {
    case RECORD_CLIENT_SERVER:
    case REPLAY_CLIENT_SERVER:
      assh_session_cleanup(&session[0]);
      assh_session_cleanup(&session[1]);
      break;
    case RECORD_SERVER_CONNECT:
    case REPLAY_SERVER:
      assh_session_cleanup(&session[0]);
      break;
    case RECORD_CLIENT_CONNECT:
    case REPLAY_CLIENT:
      assh_session_cleanup(&session[1]);
      break;
    }
}

static assh_status_t
algo_lookup(enum assh_algo_class_e cl, const char *name,
	    const struct assh_algo_s **algo)
{
  if (!strcmp(name, "none") || !strcmp(name, "none@libassh.org"))
    {
      switch (cl)
	{
	case ASSH_ALGO_KEX:
	  *algo = &assh_kex_none.algo;
	  return ASSH_OK;
	case ASSH_ALGO_SIGN:
	  *algo = &assh_sign_none.algo;
	  return ASSH_OK;
	case ASSH_ALGO_CIPHER:
	  *algo = &assh_cipher_none.algo;
	  return ASSH_OK;
	case ASSH_ALGO_MAC:
	  *algo = &assh_hmac_none.algo;
	  return ASSH_OK;
	case ASSH_ALGO_COMPRESS:
	  *algo = &assh_compress_none.algo;
	  return ASSH_OK;
	default:
	  abort();
	}
    }
  else
    {
      return assh_algo_by_name_static(assh_algo_table, cl, name, strlen(name), algo, NULL);
    }
}

void context_cleanup_strings(void)
{
  free(username);
  username = strdup("test");

  free(password);
  password = NULL;

  free(keyboard_replies);
  keyboard_replies = NULL;

  free(keyboard_infos);
  keyboard_infos = NULL;

  free(hostbased_host);
  hostbased_host = NULL;
}

char * context_load_str(FILE *in)
{
  size_t l = fget_u16(in);
  char str[l];
  if (fread(str, 1, l, in) != l)
    TEST_FAIL("unexpected end of stream\n");
  str[l - 1] = 0;
  return strdup(str);
}

static void
context_load_key(struct assh_context_s *ctx, FILE *in, struct assh_key_s **key)
{
  enum assh_key_format_e format = fgetc(in);
  enum assh_algo_class_e role = fgetc(in);

  char *name = context_load_str(in);
  const struct assh_key_algo_s *a;
  if (assh_key_algo_by_name_static(assh_key_algo_table, name, strlen(name), &a))
    TEST_FAIL("ASSH_ERR_MISSING_ALGO");

  if (verbose > 0)
    fprintf(stderr, "`%s'\n", name);
  free(name);

  int s = fget_u16(in);
  uint8_t blob[s];
  const uint8_t *b = blob;
  if (fread(blob, 1, s, in) != s)
    TEST_FAIL("unexpected end of stream\n");

  if (assh_key_load(ctx, key, a, role, format, &b, s))
    TEST_FAIL("key loading failed\n");
}

static assh_status_t
context_load(struct assh_context_s *ctx, FILE *in, unsigned i)
{
  while (1)
    {
      int s, o = fgetc(in);
      const char *side = i & 1 ? "client" : "server";

      switch (o)
	{
	case EOF:
	  TEST_FAIL("unable to load context\n");
	case CHUNK_PKT_SRV2CLI:
	case CHUNK_PKT_CLI2SRV:
	case CHUNK_PKT_REMOTE2CLI:
	case CHUNK_PKT_REMOTE2SRV:	/* start of data stream */
	  ungetc(o, in);
	  return ASSH_OK;

	case CHUNK_SRV_ALGO:			/* algo register */
	case CHUNK_CLI_ALGO: {
	  s = fget_u16(in);
	  if (i != (o & 1))
	    goto skip;
	  enum assh_algo_class_e cl = fgetc(in);
	  char *name = context_load_str(in);
	  if (verbose > 0)
	    fprintf(stderr, "[%s] Loading algorithm: `%s'.\n", side, name);
	  const struct assh_algo_s *a;
	  if (algo_lookup(cl, name, &a)
	      || assh_algo_register_va(ctx, 50, 0, 0, a, NULL))
	    TEST_FAIL("ASSH_ERR_MISSING_ALGO: %s\n", name);
	  free(name);
	  break;
	}

	case CHUNK_SRV_KEY:			/* kex key */
	case CHUNK_CLI_KEY:
	  s = fget_u16(in);
	  if (i != (o & 1))
	    goto skip;
	  if (verbose > 0)
	    fprintf(stderr, "[%s] Loading kex keys: ", side);
	  context_load_key(ctx, in, &ctx->keys);
	  break;

	case CHUNK_USER_KEY:		/* userauth key */
	  s = fget_u16(in);
	  if (i == 0)
	    goto skip;
	  if (verbose > 0)
	    fprintf(stderr, "[client] Loading user key: ");
	  context_load_key(ctx, in, &userauth_keys);
	  break;

	case CHUNK_KEX_TH:			/* kex threshold */
	  if (fget_u16(in) != 2)
	    TEST_FAIL("bad input");
	  kex_th = fget_u16(in);
	  if (verbose > 0)
	    fprintf(stderr, "[%s] Loading kex threshold: %u bytes.\n", side, kex_th);
	  break;

	case CHUNK_AUTH:
	  s = fget_u16(in);
	  if (i == 1)
	    goto skip;
	  if (s < 2 * 8)
	    TEST_FAIL("bad input");
	  s -= 2 * 8;
	  userauth_server = fget_u16(in);
	  multi_auth = fget_u16(in);
	  hostkey_accept = fget_u16(in);
	  none_accepts = fget_u16(in);
	  userkey_accepts = fget_u16(in);
	  hostbased_accepts = fget_u16(in);
	  password_accepts = fget_u16(in);
	  keyboard_accepts = fget_u16(in);
	  if (verbose > 0)
	    fprintf(stderr, "[server] Loading user auth params.\n");
	  goto skip;

	case CHUNK_USERNAME:		/* username */
	  if (i == 0)
	    goto skip_s;
	  free(username);
	  username = context_load_str(in);
	  if (verbose > 0)
	    fprintf(stderr, "[client] Loading userauth login: `%s'.\n", username);
	  break;

	case CHUNK_PASSWORDS:		/* password */
	  if (i == 0)
	    goto skip_s;
	  free(password);
	  password = context_load_str(in);
	  if (verbose > 0)
	    fprintf(stderr, "[client] Loading password list: `%s'.\n", password);
	  break;

	case CHUNK_KEYBOARD_REPLIES:		/* keyboard interactive */
	  if (i == 0)
	    goto skip_s;
	  free(keyboard_replies);
	  keyboard_replies = context_load_str(in);
	  if (verbose > 0)
	    fprintf(stderr, "[client] Loading keyboard replies: `%s'.\n", keyboard_replies);
	  break;

	case CHUNK_KEYBOARD_INFOS:		/* keyboard interactive */
	  if (i == 1)
	    goto skip_s;
	  free(keyboard_infos);
	  keyboard_infos = context_load_str(in);
	  if (verbose > 0)
	    fprintf(stderr, "[server] Loading keyboard prompts: `%s'.\n", keyboard_infos);
	  break;

	case CHUNK_HOSTBASED_HOST:
	  if (i == 0)
	    goto skip_s;
	  free(hostbased_host);
	  hostbased_host = context_load_str(in);
	  if (verbose > 0)
	    fprintf(stderr, "[server] Loading hostbased host: `%s'.\n", hostbased_host);
	  break;

	case CHUNK_HOSTBASED_KEY:
	  s = fget_u16(in);
	  if (i == 0)
	    goto skip;
	  if (verbose > 0)
	    fprintf(stderr, "[client] Loading hostbased keys.");
	  context_load_key(ctx, in, &hostbased_keys);
	  break;

	case CHUNK_MAX_ITERS:
	  s = fget_u16(in);
	  max_iter[0] = fget_u32(in);
	  max_iter[1] = fget_u32(in);
	  break;

	case CHUNK_COMMAND_LINE: {
	  if (verbose == 0)
	    goto skip_s;
	  const char *cmd = context_load_str(in);
	  fprintf(stderr, "[%s] options: %s\n", side, cmd);
	  free((void*)cmd);
	  break;
	}

	default:
	  if (verbose > 0)
	    fprintf(stderr, "[%s] Skipping unknown chunk %u.\n", side, o);
	skip_s:
	  s = fget_u16(in);
	skip:
	  if (s)
	    fseek(in, s, SEEK_CUR);
	  break;
	}
    }
}

static void
context_store_key(struct assh_context_s *ctx, struct assh_key_s *k)
{
  const char *name = k->algo->name;
  uint_fast16_t nlen = strlen(name) + 1;
  size_t klen;
  enum assh_key_format_e fmt = k->private
    ? ASSH_KEY_FMT_PV_OPENSSH_V1_KEY
    : ASSH_KEY_FMT_PUB_RFC4253;

  if (assh_key_output(ctx, k, NULL, &klen, fmt))
    TEST_FAIL("key output error\n");
  uint8_t blob[klen];
  if (assh_key_output(ctx, k, blob, &klen, fmt))
    TEST_FAIL("key output error\n");

  fput_u16(6 + nlen + klen, f_out);
  fputc(fmt, f_out);
  fputc(k->role, f_out);
  fput_u16(nlen, f_out);
  fwrite(name, nlen, 1, f_out);
  fput_u16(klen, f_out);
  fwrite(blob, klen, 1, f_out);
}

static void
context_store(struct assh_context_s *ctx, unsigned i)
{
  uint_fast16_t j;
  for (j = 0; j < ctx->algo_cnt; j++)
    {
      const struct assh_algo_s *a = ctx->algos[j];
      const char *name = assh_algo_name(a);
      uint_fast16_t len = strlen(name) + 1;
      fputc(i ? CHUNK_CLI_ALGO : CHUNK_SRV_ALGO, f_out);
      fput_u16(len + 3, f_out);
      fputc(a->class_, f_out);
      fput_u16(len, f_out);
      fwrite(name, len, 1, f_out);
    }

  struct assh_key_s *k;
  for (k = ctx->keys; k != NULL; k = k->next)
    {
      fputc(i ? CHUNK_CLI_KEY : CHUNK_SRV_KEY, f_out);
      context_store_key(ctx, k);
    }

  if (kex_th)
    {
      fputc(CHUNK_KEX_TH, f_out);
      fput_u16(2, f_out);
      fput_u16(kex_th, f_out);
    }

  fputc(CHUNK_AUTH, f_out);
  fput_u16(8 * 2, f_out);
  fput_u16(userauth_server, f_out);
  fput_u16(multi_auth, f_out);
  fput_u16(hostkey_accept, f_out);
  fput_u16(none_accepts, f_out);
  fput_u16(userkey_accepts, f_out);
  fput_u16(hostbased_accepts, f_out);
  fput_u16(password_accepts, f_out);
  fput_u16(keyboard_accepts, f_out);

  fputc(CHUNK_MAX_ITERS, f_out);
  fput_u16(2 * 4, f_out);
  fput_u32(max_iter[0], f_out);
  fput_u32(max_iter[1], f_out);

  if (i == 1)
    {
      fputc(CHUNK_USERNAME, f_out);
      fput_u16(strlen(username) + 1, f_out);
      fwrite(username, strlen(username) + 1, 1, f_out);

      if (password)
	{
	  fputc(CHUNK_PASSWORDS, f_out);
	  fput_u16(strlen(password) + 1, f_out);
	  fwrite(password, strlen(password) + 1, 1, f_out);
	}

      if (keyboard_replies)
	{
	  fputc(CHUNK_KEYBOARD_REPLIES, f_out);
	  fput_u16(strlen(keyboard_replies) + 1, f_out);
	  fwrite(keyboard_replies, strlen(keyboard_replies) + 1, 1, f_out);
	}

      for (k = userauth_keys; k != NULL; k = k->next)
	{
	  fputc(CHUNK_USER_KEY, f_out);
	  context_store_key(ctx, k);
	}

      if (hostbased_host)
	{
	  fputc(CHUNK_HOSTBASED_HOST, f_out);
	  fput_u16(strlen(hostbased_host) + 1, f_out);
	  fwrite(hostbased_host, strlen(hostbased_host) + 1, 1, f_out);
	}

      for (k = hostbased_keys; k != NULL; k = k->next)
	{
	  fputc(CHUNK_HOSTBASED_KEY, f_out);
	  context_store_key(ctx, k);
	}
    }
  else
    {
      if (keyboard_infos)
	{
	  fputc(CHUNK_KEYBOARD_INFOS, f_out);
	  fput_u16(strlen(keyboard_infos) + 1, f_out);
	  fwrite(keyboard_infos, strlen(keyboard_infos) + 1, 1, f_out);
	}
    }
}

static void replay_file(const char *fname)
{
  fprintf(stderr, "replaying `%s' ...\n", fname);

  f_in[0] = fopen(fname, "rb");
  if (!f_in[0])
    TEST_FAIL("unable to open input stream file\n");

  action = fgetc(f_in[0]) & 3;

  f_in[1] = fopen(fname, "rb");
  if (!f_in[1])
    TEST_FAIL("unable to open input stream file\n");

  fgetc(f_in[1]);

  if (action & REPLAY_SERVER)
    {
#if !defined(CONFIG_ASSH_SERVER)
      TEST_FAIL("server support not available\n");
#endif

      if (assh_context_init(&context[0], ASSH_SERVER,
			    assh_leaks_allocator, NULL,
			    &assh_prng_dummy, NULL))
	TEST_FAIL("server ctx init\n");

      if (context_load(&context[0], f_in[0], 0))
	TEST_FAIL("server ctx load\n");
    }

  if (action & REPLAY_CLIENT)
    {
#if !defined(CONFIG_ASSH_CLIENT)
      TEST_FAIL("client support not available\n");
#endif

      if (assh_context_init(&context[1], ASSH_CLIENT,
			    assh_leaks_allocator, NULL,
			    &assh_prng_dummy, NULL))
	TEST_FAIL("client ctx init\n");

      if (context_load(&context[1], f_in[1], 1))
	TEST_FAIL("client ctx load\n");
    }

  test();

  if (action & REPLAY_SERVER)
    assh_context_cleanup(&context[0]);

  if (action & REPLAY_CLIENT)
    {
      assh_key_flush(&context[1], &hostbased_keys);
      assh_key_flush(&context[1], &userauth_keys);
      assh_context_cleanup(&context[1]);
    }

  if (alloc_size != 0)
    TEST_FAIL("memory leak detected, %zu bytes allocated\n", alloc_size);
}

static void replay_directory(int argc, char **argv)
{
  const char *dname = ".";
  int opt;

  while ((opt = getopt(argc, argv, "vhd:R")) != -1)
    {
      switch (opt)
	{
	case 'd':
	  dname = optarg;
	  break;
	case 'v':
	  verbose++;
	  break;
	case 'R':
	  save_raw++;
	  break;
	case 'h':
	  usage();

	default:
	  exit(1);
	}
    }

  DIR *d = opendir(dname);
  if (!d)
    TEST_FAIL("unable to open directory `%s'", dname);

  struct dirent *ent;
  assh_bool_t done = 0;

  while ((ent = readdir(d)))
    if (ent->d_type & (DT_REG | DT_LNK))
      if (!fnmatch("*.ssh", ent->d_name, FNM_PATHNAME))
	{
	  char path[512];
	  snprintf(path, sizeof(path), "%s/%s", dname, ent->d_name);
	  path[sizeof(path) - 1] = 0;
	  if (save_raw)
	    open_raw_files(path);
	  context_cleanup_strings();
	  replay_file(path);
	  if (save_raw)
	    close_raw_files();
	  done = 1;
	}

  closedir(d);

  if (!done)
    TEST_FAIL("no .ssh stream file found in the directory `%s'\n", dname);

  fprintf(stderr, "Done.\n");
}

static void replay(int argc, char **argv)
{
  const char *fname = "stream.ssh";

  action = REPLAY_CLIENT_SERVER;

  context_cleanup_strings();

  int opt;
  while ((opt = getopt(argc, argv, "f:vhR")) != -1)
    {
      switch (opt)
	{
	case 'f':
	  fname = optarg;
	  break;
	case 'v':
	  verbose++;
	  break;
	case 'R':
	  save_raw++;
	  break;
	case 'h':
	  usage();

	default:
	  exit(1);
	}
    }

  if (save_raw)
    open_raw_files(fname);

  replay_file(fname);

  if (save_raw)
    close_raw_files();

  fprintf(stderr, "Done.\n");
}

static void record(int argc, char **argv)
{
  const char *hostname = "localhost";
  const char *port = NULL;
  const char *fname = "stream.ssh";

  context_cleanup_strings();

#if defined(CONFIG_ASSH_SERVER)
  if (assh_context_init(&context[0], ASSH_SERVER,
			assh_leaks_allocator, NULL,
			&assh_prng_dummy, NULL))
    TEST_FAIL("server ctx init\n");
#endif

#if defined(CONFIG_ASSH_CLIENT)
  if (assh_context_init(&context[1], ASSH_CLIENT,
			assh_leaks_allocator, NULL,
			&assh_prng_dummy, NULL))
    TEST_FAIL("client ctx init\n");
#endif

#if defined(CONFIG_ASSH_SERVER) && defined(CONFIG_ASSH_CLIENT)
  action = RECORD_CLIENT_SERVER;
#elif defined(CONFIG_ASSH_CLIENT)
  action = RECORD_CLIENT_CONNECT;
#else
  action = RECORD_SERVER_CONNECT;
#endif

  char cmdline[512];
  int cmdi = 0;

  uint_fast16_t i;
  for (i = 0; i < argc; i++)
    cmdi += snprintf(cmdline + cmdi, sizeof(cmdline) - cmdi, "%s ", argv[i]);

  int opt;
  struct assh_context_s *c;
  struct assh_key_s **keys;

  while ((opt = getopt(argc, argv, "i:I:p:H:t:csf:a:A:b:j:J:j:i:u:P:k:y:O:l:o:w:B:Y:M:n:F:K:S:vhR")) != -1)
    {
      switch (opt)
	{
	case 'i':
	  max_iter[1] = atoi(optarg);
	  break;
	case 'I':
	  max_iter[0] = atoi(optarg);
	  break;
	case 'f':
	  fname = optarg;
	  break;
	case 'p':
	  port = optarg;
	  break;
	case 'H':
	  hostname = optarg;
	  break;
	case 't':
	  kex_th = atoi(optarg);
	  break;
#if defined(CONFIG_ASSH_CLIENT)
	case 'c':
	  action = RECORD_CLIENT_CONNECT;
	  break;
#endif
#if defined(CONFIG_ASSH_CLIENT)
	case 's':
	  action = RECORD_SERVER_CONNECT;
	  break;
#endif
#if defined(CONFIG_ASSH_CLIENT)
	case 'a':
#endif
#if defined(CONFIG_ASSH_SERVER)
	case 'A':
#endif
	case 'b':
	{
	  if (!optarg[0] || optarg[1] != ':')
	    TEST_FAIL("bad algorithm class syntax `%s'.\n", optarg);
	  enum assh_algo_class_e cl;
	  switch (optarg[0])
	    {
	    case 'k':
	      cl = ASSH_ALGO_KEX;
	      break;
	    case 's':
	      cl = ASSH_ALGO_SIGN;
	      break;
	    case 'c':
	      cl = ASSH_ALGO_CIPHER;
	      break;
	    case 'm':
	      cl = ASSH_ALGO_MAC;
	      break;
	    case 'C':
	      cl = ASSH_ALGO_COMPRESS;
	      break;
	    default:
	      TEST_FAIL("bad algorithm class `%c'.\n", optarg[0]);
	    }
	  optarg += 2;
	  const struct assh_algo_s *a;
	  if (algo_lookup(cl, optarg, &a))
	    TEST_FAIL("algorithm not available: `%s'\n", optarg);

#if defined(CONFIG_ASSH_SERVER)
	  if (opt == 'A' || opt == 'b')
	    if (assh_algo_register_va(&context[0], 50, 0, 0, a, NULL))
	      TEST_FAIL("unable to register algorithm\n");
#endif
#if defined(CONFIG_ASSH_CLIENT)
	  if (opt == 'a' || opt == 'b')
	    if (assh_algo_register_va(&context[1], 50, 0, 0, a, NULL))
	      TEST_FAIL("unable to register algorithm\n");
#endif
	  break;
	}

#if defined(CONFIG_ASSH_CLIENT)
	case 'k':
	  c = &context[1];
	  keys = &userauth_keys;
	  goto key_ctx;
	case 'K':
	  c = &context[1];
	  keys = &hostbased_keys;
	  goto key_ctx;
#endif
#if defined(CONFIG_ASSH_SERVER)
	case 'J':
	case 'j':
	  c = &context[0];
	  keys = &c->keys;
#endif
	  {
	  key_ctx:;
	    enum assh_algo_class_e role = opt == 'j' ? ASSH_ALGO_KEX : ASSH_ALGO_SIGN;
	    char *col = strchr(optarg, ':');

	    if (col)
	      {
#ifdef CONFIG_ASSH_KEY_CREATE
		size_t bits = atoi(col + 1);
		*col = 0;

		const struct assh_key_algo_s *algo;
		if (assh_key_algo_by_name_static(assh_key_algo_table,
						 optarg, strlen(optarg), &algo))
		  TEST_FAIL("key algorithm not available: `%s'\n", optarg);

		/* creating a key use random bits but we need to keep
		   the prng in sync with the replay session. */
		uint64_t seed = assh_load_u64le(c->prng_pv);
		if (assh_key_create(c, keys, bits, algo, role))
		  TEST_FAIL("unable to create key: `%s'\n", optarg);
		/* restore seed */
		assh_store_u64le(c->prng_pv, seed);
#else
		TEST_FAIL("unable to create key: disabled at compile time\n");
#endif
	      }
	    else
	      {
		if (asshh_load_key_filename(c, keys, NULL, role,
					   optarg, ASSH_KEY_FMT_NONE, NULL, 0))
		  TEST_FAIL("unable to load key: `%s'\n", optarg);
	      }
	    break;
	  }

	case 'u':
	  free(username);
	  username = strdup(optarg);
	  break;
	case 'P':
	  password = strdup(optarg);
	  break;
	case 'y':
	  keyboard_replies = strdup(optarg);
	  break;
	case 'Y':
	  keyboard_infos = strdup(optarg);
	  break;
	case 'S':
	  hostbased_host = strdup(optarg);
	  break;
	case 'O':
	  hostkey_accept = atoi(optarg);
	  break;
	case 'M':
	  userauth_server |= strtoul(optarg, NULL, 0);
	  break;
	case 'n':
	  userauth_server |= ASSH_USERAUTH_METHOD_NONE;
	  none_accepts = strtoul(optarg, NULL, 2);
	  break;
	case 'l':
	  userauth_server |= ASSH_USERAUTH_METHOD_PUBKEY;
	  userkey_accepts = strtoul(optarg, NULL, 2);
	  break;
	case 'o':
	  userauth_server |= ASSH_USERAUTH_METHOD_HOSTBASED;
	  hostbased_accepts = strtoul(optarg, NULL, 2);
	  break;
	case 'w':
	  userauth_server |= ASSH_USERAUTH_METHOD_PASSWORD;
	  password_accepts = strtoul(optarg, NULL, 4);
	  break;
	case 'B':
	  userauth_server |= ASSH_USERAUTH_METHOD_KEYBOARD;
	  keyboard_accepts = strtoul(optarg, NULL, 4);
	  break;
	case 'F':
	  multi_auth = atoi(optarg);
	  break;
	case 'v':
	  verbose++;
	  break;
	case 'R':
	  save_raw++;
	  break;
	case 'h':
	  usage();

	default:
	  exit(1);
	}
    }

  verbose += !verbose;

  fprintf(stderr, "Recording `%s' ...\n", fname);

  f_out = fopen(fname, "wb");
  if (!f_out)
    TEST_FAIL("unable to open output stream file\n");

  if (save_raw)
    open_raw_files(fname);

  fputc(action & 3, f_out);

  switch (action)
    {
    case RECORD_CLIENT_CONNECT: {

      if (!port)
	port = "22";

      struct addrinfo hints = {
	.ai_family = AF_UNSPEC,
	.ai_socktype = SOCK_STREAM,
      };

      struct addrinfo *servinfo, *si;
      if (!getaddrinfo(hostname, port, &hints, &servinfo))
	{
	  for (si = servinfo; si != NULL; si = si->ai_next)
	    {
	      sock = socket(si->ai_family, si->ai_socktype, si->ai_protocol);
	      if (sock < 0)
		continue;

	      if (connect(sock, si->ai_addr, si->ai_addrlen))
		{
		  close(sock);
		  sock = -1;
		  continue;
		}

	      break;
	    }

	  freeaddrinfo(servinfo);
	}
      if (sock < 0)
	TEST_FAIL("unable to connect to %s:%s\n", hostname, port);
      break;
    }

    case RECORD_SERVER_CONNECT: {

      if (!port)
	port = "22222";

      int s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
      if (s < 0)
	TEST_FAIL("Unable to create socket: %s\n", strerror(errno));

      int tmp = 1;
      setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp));

      struct sockaddr_in addr =
	{
	  .sin_port = htons(atoi(port)),
	  .sin_family = AF_INET,
	};

      if (bind(s, (struct sockaddr*)&addr, sizeof (struct sockaddr_in)) < 0)
	TEST_FAIL("Unable to bind: %s\n", strerror(errno));

      if (listen(s, 8) < 0)
	TEST_FAIL("Unable to listen: %s\n", strerror(errno));

      struct sockaddr_in con_addr;
      socklen_t addr_size = sizeof(con_addr);

      fprintf(stderr, "Waiting for connection on port %s\n", port);

      sock = accept(s, (struct sockaddr*)&con_addr, &addr_size);
      if (sock < 0)
	TEST_FAIL("Unable to accept: %s\n", strerror(errno));

      break;
    }

    default:
      break;
    }

  /* store command line used */
  fputc(CHUNK_COMMAND_LINE, f_out);
  fput_u16(cmdi + 1, f_out);
  fwrite(cmdline, cmdi, 1, f_out);
  fputc(0, f_out);

  /* serialize server side setup */
  if (action & REPLAY_SERVER)
    context_store(&context[0], 0);

  /* serialize client side setup */
  if (action & REPLAY_CLIENT)
    context_store(&context[1], 1);

  test();

  if (save_raw)
    close_raw_files();

  assh_context_cleanup(&context[0]);

  assh_key_flush(&context[1], &userauth_keys);
  assh_key_flush(&context[1], &hostbased_keys);
  assh_context_cleanup(&context[1]);

  if (alloc_size != 0)
    TEST_FAIL("memory leak detected, %zu bytes allocated\n", alloc_size);

  fprintf(stderr, "Done.\n");
}

int main(int argc, char **argv)
{
  if (assh_deps_init())
    return -1;

  struct sigaction act = {
    .sa_handler = term_handler,
  };
  sigaction(SIGINT, &act, NULL);

  if (argc < 2)
    replay_directory(0, NULL);
  else if (!strcmp(argv[1], "replay"))
    replay(argc - 1, argv + 1);
  else if (!strcmp(argv[1], "record"))
    record(argc - 1, argv + 1);
  else if (!strcmp(argv[1], "replay_all"))
    replay_directory(argc - 1, argv + 1);
  else
    usage();

  free(username);
  free(password);
  free(keyboard_replies);
  free(keyboard_infos);
  free(hostbased_host);

  return 0;
}
