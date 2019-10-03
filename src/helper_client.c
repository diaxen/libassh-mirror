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
#include <assh/helper_io.h>
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

#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>

assh_status_t
asshh_client_get_known_hosts(struct assh_context_s *c, struct assh_key_s **keys,
				    const char *filename, const char *host)
{
  assh_status_t err;
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
	  if (!asshh_load_key_file(c, keys, NULL, ASSH_ALGO_SIGN, f,
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

assh_status_t
asshh_client_add_known_hosts(struct assh_context_s *c, const char *filename,
				    const char *host, const struct assh_key_s *key)
{
  assh_status_t err;
  FILE *f = fopen(filename, "a");

  ASSH_RET_IF_TRUE(f == NULL, ASSH_ERR_IO);

  ASSH_JMP_IF_TRUE(fputs(host, f) == EOF, ASSH_ERR_IO, err_);
  ASSH_JMP_IF_TRUE(fputc(' ', f) == EOF, ASSH_ERR_IO, err_);
  ASSH_JMP_ON_ERR(asshh_save_key_file(c, key, f, ASSH_KEY_FMT_PUB_OPENSSH, NULL), err_);

 err_:
  fclose(f);
  return err;
}

static const char *
asshh_client_userpath(char *buf, size_t buf_size, const char *filename)
{
  const char *home = getenv("HOME");
  if (home != NULL && snprintf(buf, buf_size, "%s/.ssh/%s", home,
			       filename) < buf_size)
    return buf;
  return NULL;
}

void
asshh_client_event_hk_lookup(struct assh_session_s *s, FILE *out, FILE *in,
				    const char *host,
				    struct assh_event_s *event)
{
  assert(event->id == ASSH_EVENT_KEX_HOSTKEY_LOOKUP);

  char path[128];
  const char *home = asshh_client_userpath(path,
			      sizeof(path), "known_hosts");

  asshh_client_event_hk_lookup_va(s, out, in, host, event,
		 CONFIG_ASSH_OPENSSH_PREFIX "ssh_known_hosts", home, NULL);
}

void
asshh_client_event_hk_add(struct assh_session_s *s,
				 const char *host,
				 struct assh_event_s *event)
{
  struct assh_event_kex_done_s *ev = &event->kex.done;
  struct assh_key_s *hk = ev->host_key;

  assert(event->id == ASSH_EVENT_KEX_DONE);

  if (ev->initial && hk && !hk->stored)
    {
      char path[128];
      const char *home = asshh_client_userpath(path,
				  sizeof(path), "known_hosts");

      if (!asshh_client_add_known_hosts(s->ctx,
			       home, host, ev->host_key))
	hk->stored = 1;
    }

  assh_event_done(s, event, ASSH_OK);
}

void
asshh_client_event_hk_lookup_va(struct assh_session_s *s, FILE *out, FILE *in,
				       const char *host,
				       struct assh_event_s *event, ...)
{
  struct assh_event_kex_hostkey_lookup_s *ev =
    &event->kex.hostkey_lookup;
  struct assh_context_s *c = s->ctx;
  assh_status_t err;

  struct assh_key_s *mk, *k, *ek = ev->key;
  struct assh_key_s *keys = NULL;
  va_list ap;

  assert(event->id == ASSH_EVENT_KEX_HOSTKEY_LOOKUP);

  if (!ev->initial)
    goto accept;

  ev->accept = 0;

  va_start(ap, event);

  while (1)
    {
      const char *f = va_arg(ap, const char *);
      if (!f)
	break;

      asshh_client_get_known_hosts(c, &keys, f, host);
    }

  va_end(ap);

  char fp_md5[48];
  char fp_sha[44];

  size_t fp_size = sizeof(fp_md5);
  ASSH_JMP_ON_ERR(asshh_key_fingerprint(c, ek, ASSH_FP_RFC4716_MD5,
				    fp_md5, &fp_size, NULL), err_);

  fp_size = sizeof(fp_sha);
  ASSH_JMP_ON_ERR(asshh_key_fingerprint(c, ek, ASSH_FP_BASE64_SHA256,
				    fp_sha, &fp_size, NULL), err_);

  for (mk = k = keys; k != NULL; k = k->next)
    {
      if (assh_key_cmp(c, k, ek, 1))
	{
	  ek->stored = 1;
	  goto accept;
	}
      else if (!strcmp(k->type, ek->type))
	{
	  fprintf(out,
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
		  "  MD5 fingerprint        : %s\n"
		  "\n"
	          "Known public key stored locally:\n"
		  "  Type                   : %s\n"
		  "  Algorithmic safety     : %s (%u%%)\n"
		  "  Location               : %s\n",
		  host, assh_key_type_name(ek), assh_key_safety_name(ek), assh_key_safety(ek),
		  fp_sha, fp_md5, assh_key_type_name(k), assh_key_safety_name(k), assh_key_safety(k),
		  k->comment);
	  goto done;
	}
      if (mk->safety > k->safety)
	mk = k;
    }

  if (mk)
    {
      fprintf(out,
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
	      "  MD5 fingerprint        : %s\n"
	      "\n"
	      "Best known public key stored locally:\n"
	      "  Type                   : %s\n"
	      "  Algorithmic safety     : %s (%u%%)\n"
	      "  File location          : %s\n",
	      host, assh_key_type_name(ek), assh_key_safety_name(ek), assh_key_safety(ek),
	      fp_sha, fp_md5, mk->type,
	      assh_key_safety_name(mk), assh_key_safety(mk), mk->comment);
    }
  else
    {
      fprintf(out,
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
	      "  MD5 fingerprint        : %s\n",
	      host, assh_key_type_name(ek), assh_key_safety_name(ek), assh_key_safety(ek),
	      fp_sha, fp_md5);
    }

  int fd = fileno(in);
  assh_bool_t tty = fd >= 0 && isatty(fd);

  if (!tty)
    {
      fprintf(out, "\nNot a tty, unable to prompt for key verification...\n");
      goto done;
    }

#ifdef CONFIG_ASSH_KEY_VALIDATE
  enum assh_key_validate_result_e r;
  ASSH_JMP_ON_ERR(assh_key_validate(c, ek, &r), err_);
  ASSH_JMP_IF_TRUE(r < 0, ASSH_ERR_BAD_DATA, err_);
#endif

  fprintf(out, "\nHave you verified the authenticity of the\n"
	  "currently untrusted key? (type uppercase yes) : ");

  if (getc(in) != 'Y' || getc(in) != 'E' || getc(in) != 'S')
    goto done;

 accept:
  ev->accept = 1;

 done:
  err = ASSH_OK;
  assh_key_flush(c, &keys);

 err_:
  assh_event_done(s, event, err);
}

static assh_status_t
asshh_client_load_key_passphrase(struct assh_context_s *c, FILE *out, FILE *in,
				struct assh_key_s **head,
				const struct assh_key_algo_s *algo,
				enum assh_algo_class_e role,
				const char *filename,
				enum assh_key_format_e format)
{
  assh_status_t err;

  err = asshh_load_key_filename(c, head, algo, role,
			       filename, format, NULL, 0);

  switch (ASSH_STATUS(err))
    {
    case ASSH_OK:
      return ASSH_OK;

    case ASSH_ERR_MISSING_KEY: {
      fprintf(out, "Passphrase for `%s': ",
	      filename);
      const char *pass;
      ASSH_RET_ON_ERR(asshh_fd_get_password(c, &pass, 80, fileno(in), 0));
      putc('\n', out);
      err = asshh_load_key_filename(c, head, algo, role,
				   filename, format, pass, 0);
      assh_free(c, (void*)pass);
    }

    default:
      ASSH_RETURN(err);
    }
}

const struct asshh_client_user_key_s asshh_client_user_key_default[] =
{
  { "id_ed25519", &assh_key_ed25519,
    ASSH_ALGO_SIGN, ASSH_KEY_FMT_PV_OPENSSH_V1 },
  { "id_rsa",     &assh_key_rsa,
    ASSH_ALGO_SIGN, ASSH_KEY_FMT_PV_PEM },
  { "id_rsa",     &assh_key_rsa,
    ASSH_ALGO_SIGN, ASSH_KEY_FMT_PV_OPENSSH_V1 },
  { "id_ecdsa",   &assh_key_ecdsa_nistp,
    ASSH_ALGO_SIGN, ASSH_KEY_FMT_PV_PEM },
  { "id_ecdsa",   &assh_key_ecdsa_nistp,
    ASSH_ALGO_SIGN, ASSH_KEY_FMT_PV_OPENSSH_V1 },
  { "id_dsa",     &assh_key_dsa,
    ASSH_ALGO_SIGN, ASSH_KEY_FMT_PV_PEM },
  { "id_dsa",     &assh_key_dsa,
    ASSH_ALGO_SIGN, ASSH_KEY_FMT_PV_OPENSSH_V1 },
  { NULL }
};

void
asshh_client_event_auth(struct assh_session_s *s, FILE *out, FILE *in,
			       const char *user, const char *host,
			       enum assh_userauth_methods_e *methods,
			       const struct asshh_client_user_key_s *key_files,
			       struct assh_event_s *event)
{
  struct assh_context_s *c = s->ctx;
  assh_status_t err;

  switch (event->id)
    {
    case ASSH_EVENT_USERAUTH_CLIENT_BANNER: {
      struct assh_event_userauth_client_banner_s *ev =
	&event->userauth_client.banner;

      assert(event->id == ASSH_EVENT_USERAUTH_CLIENT_BANNER);
      asshh_print_string(out, &ev->text);
      fputc('\n', out);

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
		  path = asshh_client_userpath(path_buf, sizeof(path_buf),
						      key_files->filename);

		  if (path)
		    asshh_client_load_key_passphrase(c, out, in, &ev->keys,
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

	  if (isatty(fileno(in)))
	    {
	      fprintf(out, "Password for `%s@%s': ", user, host);
	      err = asshh_fd_get_password(c, &pass, 80, fileno(in), 0);
	      fputc('\n', out);
	    }

	  if (ASSH_STATUS(err) == ASSH_OK)
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
	  if (isatty(fileno(in)))
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

      asshh_print_string(out, &ev->prompt);
      fputc('\n', out);

      const char *old_pass, *new_pass;
      fprintf(out, "Current password for `%s@%s': ",
	      user, host);
      err = asshh_fd_get_password(c, &old_pass, 80, fileno(in), 0);
      fputc('\n', out);

      if (ASSH_STATUS(err) == ASSH_OK)
	{
	  fprintf(out, "New password for `%s@%s': ",
		  user, host);
	  err = asshh_fd_get_password(c, &new_pass, 80, fileno(in), 0);
	  fputc('\n', out);

	  if (ASSH_STATUS(err) == ASSH_OK)
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

      err = ASSH_OK;
      if (count)
	{
	  fprintf(out, "Interactive user authentication for `%s@%s':\n", user, host);

	  if (ev->instruction.len)
	    {
	      asshh_print_string(out, &ev->instruction);
	      fputc('\n', out);
	    }

	  for (; i < count; i++)
	    {
	      const char *v;
	      asshh_print_string(out, &ev->prompts[i]);
	      err = asshh_fd_get_password(c, &v, 80, fileno(in), (ev->echos >> i) & 1);
	      if (ASSH_STATUS(err) != ASSH_OK)
		break;
	      fputc('\n', out);
	      assh_buffer_strset(&rsp[i], v);
	    }

	  ev->responses = rsp;
	}

      assh_event_done(s, event, err);

      while (i--)
	assh_free(c, (void*)rsp[i].str);

      break;
    }

    default:
      ASSH_UNREACHABLE();
    }
}

void
asshh_client_init_inter_session(struct asshh_client_inter_session_s *ctx,
                               const char *command, const char *term)
{
  ASSH_SET_STATE(ctx, state, ASSH_CLIENT_INTER_ST_INIT);
  ctx->command = command;
  ctx->term = term;
  ctx->channel = NULL;
  ctx->request = NULL;
}

void
asshh_client_event_inter_session(struct assh_session_s *s,
				struct assh_event_s *event,
				struct asshh_client_inter_session_s *ctx)
{
  switch (event->id)
    {
    case ASSH_EVENT_SERVICE_START: {
      assh_bool_t conn = event->service.start.srv ==
	                   &assh_service_connection;

      assh_event_done(s, event, ASSH_OK);

      if (conn)
	{
	  /* we can send channel related requests from this point */
	  assert(ctx->state == ASSH_CLIENT_INTER_ST_INIT);

	  if (asshh_inter_open_session(s, &ctx->channel))
	    goto err;

	  ASSH_SET_STATE(ctx, state, ASSH_CLIENT_INTER_ST_SESSION);
	}
      return;
    }

    case ASSH_EVENT_CHANNEL_CONFIRMATION: {
      struct assh_event_channel_confirmation_s *ev =
	&event->connection.channel_confirmation;

      if (ev->ch != ctx->channel)
	return;

      assert(ctx->state == ASSH_CLIENT_INTER_ST_SESSION);

      assh_event_done(s, event, ASSH_OK);

      if (ctx->term == NULL)
	goto exec;

      ASSH_SET_STATE(ctx, state, ASSH_CLIENT_INTER_ST_PTY);

      struct asshh_inter_pty_req_s i;
      asshh_inter_init_pty_req(&i, ctx->term, 0, 0, 0, 0, NULL);

      if (asshh_inter_send_pty_req(s, ctx->channel, &ctx->request, &i))
	goto err;

      return;
    }

    case ASSH_EVENT_CHANNEL_FAILURE: {
      struct assh_event_channel_failure_s *ev =
	&event->connection.channel_failure;

      if (ev->ch != ctx->channel)
	return;

      assert(ctx->state == ASSH_CLIENT_INTER_ST_SESSION);

      assh_event_done(s, event, ASSH_OK);

      goto err;
    }

    case ASSH_EVENT_CHANNEL_CLOSE: {
      struct assh_event_channel_close_s *ev =
	&event->connection.channel_close;

      if (ev->ch != ctx->channel)
	return;

      ASSH_SET_STATE(ctx, state, ASSH_CLIENT_INTER_ST_CLOSED);
      assh_event_done(s, event, ASSH_OK);
      return;
    }

    case ASSH_EVENT_REQUEST_FAILURE: {
      struct assh_event_request_failure_s *ev =
	&event->connection.request_failure;

      if (ev->ch != ctx->channel ||
	  ev->rq != ctx->request)
	return;

      assh_event_done(s, event, ASSH_OK);

      goto err;
    }

    case ASSH_EVENT_REQUEST_SUCCESS: {
      struct assh_event_request_success_s *ev =
	&event->connection.request_success;

      if (ev->ch != ctx->channel ||
	  ev->rq != ctx->request)
	return;

      assh_event_done(s, event, ASSH_OK);

      switch (ctx->state)
	{
	case ASSH_CLIENT_INTER_ST_PTY:
	exec:
	  if (ctx->command)
	    {
	      struct asshh_inter_exec_s i;
	      assh_buffer_strset(&i.command, ctx->command);
	      if (asshh_inter_send_exec(s, ctx->channel, &ctx->request, &i))
		goto err;
	      ASSH_SET_STATE(ctx, state, ASSH_CLIENT_INTER_ST_EXEC);
	    }
	  else
	    {
	      if (asshh_inter_send_shell(s, ctx->channel, &ctx->request))
		goto err;
	      ASSH_SET_STATE(ctx, state, ASSH_CLIENT_INTER_ST_EXEC);
	    }
	  return;

	case ASSH_CLIENT_INTER_ST_EXEC:
	  ASSH_SET_STATE(ctx, state, ASSH_CLIENT_INTER_ST_OPEN);
	  return;

	default:
	  ASSH_UNREACHABLE();
	}

      return;
    }

    default:
      ASSH_UNREACHABLE();
    }

err:
  switch (ctx->state)
    {
    case ASSH_CLIENT_INTER_ST_INIT:
    case ASSH_CLIENT_INTER_ST_SESSION:
      ASSH_SET_STATE(ctx, state, ASSH_CLIENT_INTER_ST_CLOSED);
      break;
    case ASSH_CLIENT_INTER_ST_PTY:
    case ASSH_CLIENT_INTER_ST_EXEC:
    case ASSH_CLIENT_INTER_ST_OPEN:
      assh_channel_close(ctx->channel);
      ASSH_SET_STATE(ctx, state, ASSH_CLIENT_INTER_ST_CLOSING);
      break;
    case ASSH_CLIENT_INTER_ST_CLOSING:
    case ASSH_CLIENT_INTER_ST_CLOSED:
      break;
    }
}
