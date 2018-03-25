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
  using libassh, the content of helper_server.h and helper_server.c
  files may be freely reused without causing the resulting work to be
  covered by the GNU Lesser General Public License.

*/

#include "config.h"

#include <assh/key_rsa.h>
#include <assh/key_dsa.h>
#include <assh/key_eddsa.h>
#include <assh/key_ecdsa.h>
#include <assh/helper_key.h>
#include <assh/assh_key.h>
#include <assh/assh_session.h>
#include <assh/assh_userauth_server.h>
#include <assh/assh_event.h>
#include <assh/assh_alloc.h>

#include <ctype.h>
#include <stdio.h>

#ifdef CONFIG_ASSH_GETPWNAM_R
# include <pwd.h>
#endif

#ifdef CONFIG_ASSH_GETSPNAM_R
# include <shadow.h>
#endif

#ifdef CONFIG_ASSH_CRYPT_R
# include <crypt.h>
#endif

assh_error_t
assh_server_openssh_load_hk(struct assh_context_s *c)
{
  uint_fast8_t count = 0;
  assh_error_t err;

  count += !assh_load_hostkey_filename(c, &assh_key_dsa, ASSH_ALGO_SIGN,
				   CONFIG_ASSH_OPENSSH_PREFIX "ssh_host_dsa_key",
				   ASSH_KEY_FMT_PV_PEM_ASN1, 0);

  count += !assh_load_hostkey_filename(c, &assh_key_rsa, ASSH_ALGO_SIGN,
				   CONFIG_ASSH_OPENSSH_PREFIX "ssh_host_rsa_key",
				   ASSH_KEY_FMT_PV_PEM, 0);

  count += !assh_load_hostkey_filename(c, &assh_key_ed25519, ASSH_ALGO_SIGN,
				   CONFIG_ASSH_OPENSSH_PREFIX "ssh_host_ed25519_key",
				   ASSH_KEY_FMT_PV_OPENSSH_V1, 0);

  count += !assh_load_hostkey_filename(c, &assh_key_eddsa_e382, ASSH_ALGO_SIGN,
				   CONFIG_ASSH_OPENSSH_PREFIX "ssh_host_e382_key",
				   ASSH_KEY_FMT_PV_OPENSSH_V1, 0);

  count += !assh_load_hostkey_filename(c, &assh_key_eddsa_e521, ASSH_ALGO_SIGN,
				   CONFIG_ASSH_OPENSSH_PREFIX "ssh_host_e521_key",
				   ASSH_KEY_FMT_PV_OPENSSH_V1, 0);

  count += !assh_load_hostkey_filename(c, &assh_key_ecdsa_nistp, ASSH_ALGO_SIGN,
				   CONFIG_ASSH_OPENSSH_PREFIX "ssh_host_ecdsa_key",
				   ASSH_KEY_FMT_PV_PEM, 0);

  ASSH_RET_IF_TRUE(count == 0, ASSH_ERR_MISSING_KEY);
  return ASSH_OK;
}

assh_error_t
assh_server_openssh_ak_lookup(struct assh_session_s *s,
			      const char *filename,
			      const struct assh_key_s *key)
{
  assh_error_t err;
  FILE *f = fopen(filename, "r");
  struct assh_key_s *k;
  uint_fast8_t state = 0;
  uint_fast16_t l = 0;

  ASSH_RET_IF_TRUE(f == NULL, ASSH_ERR_IO);

  while (1)
    {
      int_fast16_t in = fgetc(f);
      if (in == EOF)
	break;

      switch (state)
	{
	case 0:			/* start of line */
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

	  if (!assh_load_key_file(s->ctx, &k, NULL, ASSH_ALGO_SIGN, f,
				  ASSH_KEY_FMT_PUB_OPENSSH, NULL, 0))
	    {
              assh_bool_t found = assh_key_cmp(s->ctx, k, key, 1);
              assh_key_drop(s->ctx, &k);

              if (found)
                {
		  fclose(f);
                  return ASSH_OK;
                }
	    }
	  break;

	case 1:			/* skip end of line */
	  if (in == '\n')
	    state = 0;
	  break;
	}
    }

  fclose(f);
  ASSH_RETURN(ASSH_ERR_MISSING_KEY);
}

assh_error_t
assh_server_event_user_id(struct assh_session_s *s,
			  uid_t *uid, gid_t *gid,
			  struct assh_event_s *event)
{
  assh_error_t err;

  assert(event->id == ASSH_EVENT_USERAUTH_SERVER_SUCCESS);

  struct assh_event_userauth_server_success_s *ev =
    &event->userauth_server.success;

  char str[128];
  ASSH_JMP_IF_TRUE(assh_buffer_tostr(str, sizeof(str), &ev->username) == NULL,
	       ASSH_ERR_INPUT_OVERFLOW, err_);

  char pwbuf[256];
  struct passwd pwd, *pwdp = NULL;
  getpwnam_r(str, &pwd, pwbuf, sizeof(pwbuf), &pwdp);
  ASSH_JMP_IF_TRUE(pwdp == NULL, ASSH_ERR_MISSING_KEY, err_);

  if (uid)
    *uid = pwd.pw_uid;
  if (gid)
    *gid = pwd.pw_gid;

  err = ASSH_OK;

 err_:
  assh_event_done(s, event, ASSH_OK);
  return err;
}

assh_error_t
assh_server_event_openssh_auth(struct assh_session_s *s,
			       struct assh_event_s *event)
{
  assh_error_t err;

  static const size_t str_size = 128;
  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, str, str_size,
		     ASSH_ERRSV_CONTINUE, err);

  struct passwd pwd, *pwdp = NULL;

  switch (event->id)
    {
#ifdef CONFIG_ASSH_GETPWNAM_R
    case ASSH_EVENT_USERAUTH_SERVER_USERKEY: {
      struct assh_event_userauth_server_userkey_s *ev =
	&event->userauth_server.userkey;

      ASSH_JMP_IF_TRUE(assh_buffer_tostr(str, str_size, &ev->username) == NULL,
		   ASSH_ERR_INPUT_OVERFLOW, err_sc);

      char fname[128];
      char pwbuf[256];
      getpwnam_r(str, &pwd, pwbuf, sizeof(pwbuf), &pwdp);
      ASSH_JMP_IF_TRUE(pwdp == NULL, ASSH_ERR_MISSING_KEY, err_sc);

      size_t l = snprintf(fname, sizeof(fname), "%s/.ssh/authorized_keys", pwd.pw_dir);
      ASSH_JMP_IF_TRUE(l >= sizeof(fname), ASSH_ERR_INPUT_OVERFLOW, err_sc);

      ASSH_JMP_ON_ERR(assh_server_openssh_ak_lookup(s, fname, ev->pub_key), err_sc);

      ev->found = 1;
      break;
    }
#endif

#if defined(CONFIG_ASSH_CRYPT_R) && defined(CONFIG_ASSH_GETPWNAM_R)
    case ASSH_EVENT_USERAUTH_SERVER_PASSWORD: {
      struct assh_event_userauth_server_password_s *ev =
	&event->userauth_server.password;

      ASSH_JMP_IF_TRUE(assh_buffer_tostr(str, str_size, &ev->username) == NULL,
		   ASSH_ERR_INPUT_OVERFLOW, err_sc);

      char pwbuf[256];
      struct passwd pwd, *pwdp;
      getpwnam_r(str, &pwd, pwbuf, sizeof(pwbuf), &pwdp);
      ASSH_JMP_IF_TRUE(pwdp == NULL, ASSH_ERR_MISSING_KEY, err_sc);

      const char *pass = pwd.pw_passwd;

# ifdef CONFIG_ASSH_GETSPNAM_R
      char spbuf[256];
      struct spwd spwd, *spwdp;
      getspnam_r(str, &spwd, spbuf, sizeof(spbuf), &spwdp);
      if (spwdp != NULL)
	pass = spwd.sp_pwdp;
# endif

      ASSH_JMP_IF_TRUE(assh_buffer_tostr(str, str_size, &ev->password) == NULL,
		   ASSH_ERR_INPUT_OVERFLOW, err_sc);

      struct crypt_data cr;
      cr.initialized = 0;
      const char *enc = crypt_r(str, pass, &cr);

      if (enc && !strcmp(enc, pass))
	ev->result = ASSH_SERVER_PWSTATUS_SUCCESS;

      break;
    }
#endif
    }

  err = ASSH_OK;

 err_sc:
  ASSH_SCRATCH_FREE(s->ctx, str);
 err:
  assh_event_done(s, event, ASSH_OK);
  return err;
}
