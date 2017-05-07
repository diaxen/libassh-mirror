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

  As a special exception, for the purpose of developing applications
  using libassh, the content of helper_client.h and helper_client.c
  files may be freely reused without causing the resulting work to be
  covered by the GNU Lesser General Public License.

*/

#include <assh/helper_client.h>
#include <assh/helper_key.h>
#include <assh/helper_fd.h>
#include <assh/helper_interactive.h>
#include <assh/assh_key.h>
#include <assh/key_rsa.h>
#include <assh/key_dsa.h>
#include <assh/key_eddsa.h>
#include <assh/key_ecdsa.h>
#include <assh/assh_kex.h>
#include <assh/assh_userauth_client.h>
#include <assh/assh_alloc.h>
#include <assh/assh_session.h>
#include <assh/assh_connection.h>
#include <assh/assh_event.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>

assh_error_t
assh_client_openssh_get_known_hosts(struct assh_context_s *c, struct assh_key_s **keys,
				    const char *filename, const char *host)
{
  assh_error_t err;
  FILE *f = fopen(filename, "r");
  uint_fast8_t state = 3;
  uint_fast8_t hlen = 0;
  uint_fast16_t l = 0;
  int_fast16_t in;
  char hostn[256];

  ASSH_RET_IF_TRUE(f == NULL, ASSH_ERR_IO);

  while (1)
    {
      in = fgetc(f);
      if (in == EOF)
	break;

      switch (state)
	{
	case 3:			/* start of line */
	  if (isblank(in))
	    continue;
	  l++;
	  if (in == '\n')
	    continue;
	  if (in == '#')	/* comment line */
	    {
	      state = 1;
	      break;
	    }
	  state = 0;
	case 0:                 /* read hostname */
	  if (in == ',' || isblank(in))
	    {
	      hostn[hlen] = 0;
	      hlen = 0;

	      /* compare hostname */
	      if (!strcmp(host, hostn))
		{
		  if (isblank(in))
		    goto read_key;
		  state = 2;
		}
	      else
		{
		  if (isblank(in))
		    state = 1;
		}
	    }
	  else
	    {
	      if (hlen + 1 < sizeof(hostn))
		hostn[hlen++] = in;
	    }
	  break;

	case 1:			/* skip end of line */
	  if (in == '\n')
	    state = 3;
	  break;

	case 2:			/* skip end of host name list */
	  if (!isblank(in))
	    break;

	read_key:		/* load key */
	  if (!assh_load_key_file(c, keys, NULL, ASSH_ALGO_SIGN, f,
				  ASSH_KEY_FMT_PUB_OPENSSH, NULL, 0))
	    {
	      char comment[256];
	      if (snprintf(comment, sizeof(comment), "%s:%u", filename, (unsigned)l)
		  < sizeof(comment))
		assh_key_comment(c, *keys, comment);
	    }

	  state = 3;
	  break;
	}
    }

  fclose(f);
  return ASSH_OK;
}

assh_error_t
assh_client_openssh_add_known_hosts(struct assh_context_s *c, const char *filename,
				    const char *host, const struct assh_key_s *key)
{
  assh_error_t err;
  FILE *f = fopen(filename, "a");

  ASSH_RET_IF_TRUE(f == NULL, ASSH_ERR_IO);

  ASSH_JMP_IF_TRUE(fputs(host, f) == EOF, ASSH_ERR_IO, err_);
  ASSH_JMP_IF_TRUE(fputc(' ', f) == EOF, ASSH_ERR_IO, err_);
  ASSH_JMP_ON_ERR(assh_save_key_file(c, key, f, ASSH_KEY_FMT_PUB_OPENSSH, NULL), err_);

 err_:
  fclose(f);
  return err;
}

static const char *
assh_client_openssh_userpath(char *buf, size_t buf_size, const char *filename)
{
  const char *home = getenv("HOME");
  if (home != NULL && snprintf(buf, buf_size, "%s/.ssh/%s", home,
			       filename) < buf_size)
    return buf;
  return NULL;
}

void
assh_client_event_openssh_hk_lookup(struct assh_session_s *s,
				    const char *host,
				    struct assh_event_s *event)
{
  struct assh_event_kex_hostkey_lookup_s *ev = &event->kex.hostkey_lookup;
  struct assh_context_s *c = s->ctx;
  assh_error_t err;

  assert(event->id == ASSH_EVENT_KEX_HOSTKEY_LOOKUP);

  char path[128];
  const char *home = assh_client_openssh_userpath(path,
			      sizeof(path), "known_hosts");

  struct assh_key_s *ek = ev->key;

  assh_client_event_openssh_hk_lookup_va(s, host, event,
			      "/etc/ssh/ssh_known_hosts", home, NULL);
}

void
assh_client_event_openssh_hk_add(struct assh_session_s *s,
				 const char *host,
				 struct assh_event_s *event)
{
  struct assh_event_kex_done_s *ev = &event->kex.done;
  struct assh_key_s *hk = ev->host_key;
  assh_error_t err;

  assert(event->id == ASSH_EVENT_KEX_DONE);

  if (hk && !hk->stored)
    {
      char path[128];
      const char *home = assh_client_openssh_userpath(path,
				  sizeof(path), "known_hosts");

      if (!assh_client_openssh_add_known_hosts(s->ctx,
			       home, host, ev->host_key))
	hk->stored = 1;
    }

  assh_event_done(s, event, ASSH_OK);
}

void
assh_client_event_openssh_hk_lookup_va(struct assh_session_s *s, const char *host,
				       struct assh_event_s *event, ...)
{
  struct assh_event_kex_hostkey_lookup_s *ev =
    &event->kex.hostkey_lookup;
  struct assh_context_s *c = s->ctx;
  assh_error_t err;

  struct assh_key_s *mk, *k, *ek = ev->key;
  struct assh_key_s *keys = NULL;
  uint_fast16_t line;
  uint_fast16_t fcount = 0;
  va_list ap;

  assert(event->id == ASSH_EVENT_KEX_HOSTKEY_LOOKUP);

  ev->accept = 0;

  va_start(ap, event);

  while (1)
    {
      const char *f = va_arg(ap, const char *);
      if (!f)
	break;

      assh_client_openssh_get_known_hosts(c, &keys, f, host);
    }

  va_end(ap);

  char fp_md5[48];
  char fp_sha[44];

  size_t fp_size = sizeof(fp_md5);
  ASSH_JMP_ON_ERR(assh_key_fingerprint(c, ek, ASSH_FP_RFC4716_MD5,
				    fp_md5, &fp_size), err_);

  fp_size = sizeof(fp_sha);
  ASSH_JMP_ON_ERR(assh_key_fingerprint(c, ek, ASSH_FP_BASE64_SHA256,
				    fp_sha, &fp_size), err_);

  for (mk = k = keys; k != NULL; k = k->next)
    {
      if (assh_key_cmp(c, k, ek, 1))
	{
	  ek->stored = 1;
	  goto accept;
	}
      else if (!strcmp(k->type, ek->type))
	{
	  fprintf(stderr,
		  "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
	          "ERROR: It is not possible to trust the remote host because it sent a key which\n"
		  "does not match the one seen on previous connections. It might not be the ssh\n"
		  "server you are expecting or it might have been compromised. Keep your password\n"
		  "and any other sensitive information away from this untrusted server until you\n"
		  "have checked the untrusted key. Please contact the administrator of the remote\n"
		  "host in order to check if its key has been replaced and confirm a\n"
		  "fingerprint of the new public key.\n"
		  "\n"
	          "Untrusted public key sent by `%s':\n"
		  "  Type                   : %s\n"
		  "  Algorithmic safety     : %s (%u%%)\n"
		  "  SHA256 fingerprint     : %s\n"
		  "  MD5 fingerprint (weak) : %s\n"
		  "\n"
	          "Known public key stored locally:\n"
		  "  Type                   : %s\n"
		  "  Algorithmic safety     : %s (%u%%)\n"
		  "  Location               : %s\n",
		  host, ek->type, assh_safety_name(ek->safety), ek->safety, fp_sha, fp_md5,
		  k->type, assh_safety_name(k->safety), k->safety, k->comment);
	  goto done;
	}
      if (mk->safety > k->safety)
	mk = k;
    }

  if (mk)
    {
      fprintf(stderr,
	      "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
	      "WARNING: It is not possible to trust the remote host because it sent an\n"
	      "unknown key. Other key(s) of incompatible type are known from previous\n"
	      "connections to this server. It might not be the ssh server you are expecting,\n"
	      "it might have been compromised or the configuration of either side might have\n"
	      "been altered. Keep your password and other sensitive information away from\n"
	      "this untrusted server until you have checked the untrusted key. Please contact\n"
	      "the administrator of the remote host in order to confirm a fingerprint of\n"
	      "the new public key.\n"
	      "\n"
	      "Untrusted public key sent by `%s':\n"
	      "  Type                   : %s\n"
	      "  Algorithmic safety     : %s (%u%%)\n"
	      "  SHA256 fingerprint     : %s\n"
	      "  MD5 fingerprint (weak) : %s\n"
	      "\n"
	      "Best known public key stored locally:\n"
	      "  Type                   : %s\n"
	      "  Algorithmic safety     : %s (%u%%)\n"
	      "  File location          : %s\n",
	      host, ek->type, assh_safety_name(ek->safety), ek->safety, fp_sha, fp_md5,
	      mk->type, assh_safety_name(mk->safety), mk->safety, mk->comment);
    }
  else
    {
      fprintf(stderr,
	      "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
	      "There is currently no known key stored locally for the remote host. It is not\n"
	      "possible to ensure you are connecting to the ssh server you are expecting\n"
	      "without first checking the received key. The *whole* security of the ssh\n"
	      "protocol relies on this simple check. Keep your password and other sensitive\n"
	      "information away from this untrusted server and contact the administrator of\n"
	      "the remote host in order to confirm a fingerprint of the new public key.\n"
	      "\n"
	      "Untrusted public key sent by `%s':\n"
	      "  Type                   : %s\n"
	      "  Algorithmic safety     : %s (%u%%)\n"
	      "  SHA256 fingerprint     : %s\n"
	      "  MD5 fingerprint (weak) : %s\n",
	      host, ek->type, assh_safety_name(ek->safety), ek->safety, fp_sha, fp_md5);
    }

  int fd = fileno(stdin);
  assh_bool_t tty = fd >= 0 && isatty(fd);

  if (!tty)
    {
      fprintf(stderr, "\nNot a tty, unable to prompt for key verification...\n");
      goto done;
    }

  ASSH_JMP_ON_ERR(assh_key_validate(c, ek), err_);

  fprintf(stderr, "\nHave you verified the untrusted key? (type uppercase yes) : ");

  if (getchar() != 'Y' || getchar() != 'E' || getchar() != 'S')
    goto done;

 accept:
  ev->accept = 1;

 done:
  err = ASSH_OK;
  assh_key_flush(c, &keys);

 err_:
  assh_event_done(s, event, err);
}

/* print string, skipping any terminal control characters */
static void
assh_client_print_string(const struct assh_cbuffer_s *str)
{
  size_t i;

  for (i = 0; i < str->len; i++)
    {
      char c = str->str[i];

      if ((c >= ' ' && c <= 127) || c == '\n' || c == '\t')
	fputc(c, stderr);
    }
}

static assh_error_t
assh_client_load_key_passphrase(struct assh_context_s *c,
				struct assh_key_s **head,
				const struct assh_key_ops_s *algo,
				enum assh_algo_class_e role,
				const char *filename,
				enum assh_key_format_e format)
{
  assh_error_t err;

  err = assh_load_key_filename(c, head, algo, role,
			       filename, format, NULL, 0);

  switch (ASSH_ERR_ERROR(err))
    {
    case ASSH_OK:
      return ASSH_OK;

    case ASSH_ERR_MISSING_KEY: {
      fprintf(stderr, "Passphrase for `%s': ",
	      filename);
      const char *pass;
      ASSH_RET_ON_ERR(assh_fd_get_password(c, &pass, 80, 0, 0));
      putc('\n', stderr);
      err = assh_load_key_filename(c, head, algo, role,
				   filename, format, pass, 0);
      assh_free(c, (void*)pass);
    }

    default:
      ASSH_RET_ON_ERR(err);
    }
}

const struct assh_client_openssh_user_key_s assh_client_openssh_user_key_default[] =
{
  { "id_ed25519", &assh_key_ed25519,
    ASSH_ALGO_SIGN, ASSH_KEY_FMT_PV_OPENSSH_V1 },
  { "id_rsa",     &assh_key_rsa,
    ASSH_ALGO_SIGN, ASSH_KEY_FMT_PV_PEM },
  { "id_ecdsa",   &assh_key_ecdsa_nistp,
    ASSH_ALGO_SIGN, ASSH_KEY_FMT_PV_PEM },
  { "id_dsa",     &assh_key_dsa,
    ASSH_ALGO_SIGN, ASSH_KEY_FMT_PV_PEM },
  { NULL }
};

void
assh_client_event_openssh_auth(struct assh_session_s *s,
			       const char *user, const char *host,
			       enum assh_userauth_methods_e *methods,
			       const struct assh_client_openssh_user_key_s *key_files,
			       struct assh_event_s *event)
{
  struct assh_context_s *c = s->ctx;
  assh_error_t err;

  switch (event->id)
    {
    case ASSH_EVENT_USERAUTH_CLIENT_BANNER: {
      struct assh_event_userauth_client_banner_s *ev =
	&event->userauth_client.banner;

      assert(event->id == ASSH_EVENT_USERAUTH_CLIENT_BANNER);
      assh_client_print_string(&ev->text);
      fputc('\n', stderr);

      assh_event_done(s, event, ASSH_OK);
      break;
    }

    case ASSH_EVENT_USERAUTH_CLIENT_USER: {
      struct assh_event_userauth_client_user_s *ev =
	&event->userauth_client.user;

      assh_buffer_strset(&ev->username, user);

      assh_event_done(s, event, ASSH_OK);
      break;
    }

    case ASSH_EVENT_USERAUTH_CLIENT_METHODS: {
      struct assh_event_userauth_client_methods_s *ev
	= &event->userauth_client.methods;

      enum assh_userauth_methods_e m = ev->methods & *methods;

      if (m & ASSH_USERAUTH_METHOD_PUBKEY)
	{
	  char path_buf[128];
	  const char *path;

	  if (key_files)
	    {
	      /* load all available user keys */
	      for (; key_files->filename; key_files++)
		{
		  path = assh_client_openssh_userpath(path_buf, sizeof(path_buf),
						      key_files->filename);

		  if (path)
		    assh_client_load_key_passphrase(c, &ev->keys,
		      key_files->algo, key_files->role, path, key_files->format);
		}
	    }

	  /* no more keys, do not retry with this method */
	  *methods ^= ASSH_USERAUTH_METHOD_PUBKEY;

	  if (ev->keys != NULL)
	    {
	      /* select public key authentication */
	      ev->select = ASSH_USERAUTH_METHOD_PUBKEY;
	      assh_event_done(s, event, ASSH_OK);
	      break;
	    }
	}

      if (m & ASSH_USERAUTH_METHOD_PASSWORD)
	{
	  err = ASSH_ERR_NOTSUP;
	  const char *pass;

	  if (isatty(0))
	    {
	      fprintf(stderr, "Password for `%s@%s': ", user, host);
	      err = assh_fd_get_password(c, &pass, 80, 0, 0);
	      fputc('\n', stderr);
	    }

	  if (!err)
	    {
	      /* select password authentication */
	      assh_buffer_strset(&ev->password, pass);
	      ev->select = ASSH_USERAUTH_METHOD_PASSWORD;
	    }
	  else
	    {
	      /* unable to ask for the password,
		 do not retry with this method */
	      *methods ^= ASSH_USERAUTH_METHOD_PASSWORD;
	      pass = NULL;
	    }

	  assh_event_done(s, event, ASSH_OK);

	  if (pass)
	    assh_free(c, (void*)pass);

	  break;
	}

      if (m & ASSH_USERAUTH_METHOD_KEYBOARD)
	{
	  if (isatty(0))
	    {
	      /* select keyboard interactive authentication */
	      assh_buffer_strset(&ev->keyboard_sub, "pam");
	      ev->select = ASSH_USERAUTH_METHOD_KEYBOARD;
	    }
	  else
	    {
	      *methods ^= ASSH_USERAUTH_METHOD_KEYBOARD;
	    }
	}

      assh_event_done(s, event, ASSH_OK);
      break;
    }

    case ASSH_EVENT_USERAUTH_CLIENT_PWCHANGE: {
      struct assh_event_userauth_client_pwchange_s *ev =
	&event->userauth_client.pwchange;

      assh_client_print_string(&ev->prompt);
      fputc('\n', stderr);

      const char *old_pass, *new_pass;
      fprintf(stderr, "Current password for `%s@%s': ",
	      user, host);
      err = assh_fd_get_password(c, &old_pass, 80, 0, 0);
      fputc('\n', stderr);

      if (!err)
	{
	  fprintf(stderr, "New password for `%s@%s': ",
		  user, host);
	  err = assh_fd_get_password(c, &new_pass, 80, 0, 0);
	  fputc('\n', stderr);

	  if (!err)
	    {
	      assh_buffer_strset(&ev->old_password, old_pass);
	      assh_buffer_strset(&ev->new_password, new_pass);
	    }
	  else
	    {
	      new_pass = NULL;
	    }
	}
      else
	{
	  new_pass = old_pass = NULL;
	}

      assh_event_done(s, event, ASSH_OK);

      if (old_pass)
	assh_free(c, (void*)old_pass);
      if (new_pass)
	assh_free(c, (void*)new_pass);

      break;
    }

    case ASSH_EVENT_USERAUTH_CLIENT_KEYBOARD: {
      struct assh_event_userauth_client_keyboard_s *ev =
	&event->userauth_client.keyboard;

      uint_fast8_t i = 0, count = ev->count;
      struct assh_cbuffer_s rsp[count];

      if (count)
	{
	  fprintf(stderr, "Interactive authentication for `%s@%s':\n", user, host);

	  if (ev->instruction.len)
	    {
	      assh_client_print_string(&ev->instruction);
	      fputc('\n', stderr);
	    }

	  for (; i < count; i++)
	    {
	      const char *v;
	      assh_client_print_string(&ev->prompts[i]);
	      err = assh_fd_get_password(c, &v, 80, 0, (ev->echos >> i) & 1);
	      fputc('\n', stderr);
	      assh_buffer_strset(&rsp[i], err ? "" : v);
	    }

	  ev->responses = rsp;
	}

      assh_event_done(s, event, ASSH_OK);

      while (i--)
	assh_free(c, (void*)rsp[i].str);

      break;
    }

    default:
      abort();
    }
}

void
assh_client_init_inter_session(struct assh_client_inter_session_s *ctx,
                               const char *command, const char *term)
{
  ctx->state = ASSH_CLIENT_INTER_ST_INIT;
  ctx->command = command;
  ctx->term = term;
  ctx->channel = NULL;
  ctx->request = NULL;
}

void
assh_client_event_inter_session(struct assh_session_s *s,
				struct assh_event_s *event,
				struct assh_client_inter_session_s *ctx)
{
  struct assh_context_s *c = s->ctx;
  assh_error_t err;

  switch (event->id)
    {
    case ASSH_EVENT_CONNECTION_START:
      /* we can send channel related requests from this point */
      assert(ctx->state == ASSH_CLIENT_INTER_ST_INIT);
      assh_event_done(s, event, ASSH_OK);

      if (assh_inter_open_session(s, &ctx->channel))
	goto err;
      ctx->state = ASSH_CLIENT_INTER_ST_SESSION;
      return;

    case ASSH_EVENT_CHANNEL_OPEN_REPLY: {
      struct assh_event_channel_open_reply_s *ev =
	&event->connection.channel_open_reply;

      if (ev->ch != ctx->channel)
	return;

      assert(ctx->state == ASSH_CLIENT_INTER_ST_SESSION);

      enum assh_connection_reply_e r = ev->reply;
      assh_event_done(s, event, ASSH_OK);

      if (r != ASSH_CONNECTION_REPLY_SUCCESS)
	goto err;
      ctx->state = ASSH_CLIENT_INTER_ST_PTY;

      struct assh_inter_pty_req_s i;
      assh_inter_init_pty_req(&i, ctx->term, 0, 0, 0, 0, NULL);

      if (assh_inter_send_pty_req(s, ctx->channel, &ctx->request, &i))
	goto err;

      return;
    }

    case ASSH_EVENT_CHANNEL_CLOSE: {
      struct assh_event_channel_close_s *ev =
	&event->connection.channel_close;

      if (ev->ch != ctx->channel)
	return;

      ctx->state = ASSH_CLIENT_INTER_ST_CLOSED;
      assh_event_done(s, event, ASSH_OK);
      return;
    }

    case ASSH_EVENT_REQUEST_REPLY: {
      struct assh_event_request_reply_s *ev =
	&event->connection.request_reply;

      if (ev->ch != ctx->channel ||
	  ev->rq != ctx->request)
	return;

      enum assh_connection_reply_e r = ev->reply;
      assh_event_done(s, event, ASSH_OK);

      if (r != ASSH_CONNECTION_REPLY_SUCCESS)
	{
	  goto err;
	}

      switch (ctx->state)
	{
	case ASSH_CLIENT_INTER_ST_PTY:
	  if (ctx->command)
	    {
	      struct assh_inter_exec_s i;
	      assh_buffer_strset(&i.command, ctx->command);
	      if (assh_inter_send_exec(s, ctx->channel, &ctx->request, &i))
		goto err;
	      ctx->state = ASSH_CLIENT_INTER_ST_EXEC;
	    }
	  else
	    {
	      if (assh_inter_send_shell(s, ctx->channel, &ctx->request))
		goto err;
	      ctx->state = ASSH_CLIENT_INTER_ST_EXEC;
	    }
	  return;

	case ASSH_CLIENT_INTER_ST_EXEC:
	  ctx->state = ASSH_CLIENT_INTER_ST_OPEN;
	  return;

	default:
	  abort();
	}

      return;
    }

    default:
      abort();
    }

err:
  switch (ctx->state)
    {
    case ASSH_CLIENT_INTER_ST_INIT:
    case ASSH_CLIENT_INTER_ST_SESSION:
      ctx->state = ASSH_CLIENT_INTER_ST_CLOSED;
      break;
    case ASSH_CLIENT_INTER_ST_PTY:
    case ASSH_CLIENT_INTER_ST_EXEC:
    case ASSH_CLIENT_INTER_ST_OPEN:
      assh_channel_close(ctx->channel);
      ctx->state = ASSH_CLIENT_INTER_ST_CLOSING;
      break;
    case ASSH_CLIENT_INTER_ST_CLOSING:
    case ASSH_CLIENT_INTER_ST_CLOSED:
      break;
    }
}
