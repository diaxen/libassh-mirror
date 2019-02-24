/*

  libassh - asynchronous ssh2 client/server library.

  Copyright (C) 2016 Alexandre Becoulet <alexandre.becoulet@free.fr>

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

#include <assh/assh_session.h>
#include <assh/assh_context.h>
#include <assh/assh_service.h>
#include <assh/assh_kex.h>
#include <assh/assh_cipher.h>
#include <assh/assh_sign.h>
#include <assh/assh_mac.h>
#include <assh/assh_prng.h>
#include <assh/assh_compress.h>
#include <assh/helper_key.h>
#include <assh/assh_connection.h>
#include <assh/assh_userauth_client.h>
#include <assh/assh_userauth_server.h>
#include <assh/assh_event.h>
#include <assh/key_eddsa.h>

#include "fifo.h"
#include "prng_weak.h"
#include "leaks_check.h"
#include "test.h"

static struct fifo_s fifo[2];
static struct assh_context_s context[2];
static struct assh_session_s session[2];

static const struct assh_key_algo_s *key_algo = &assh_key_ed25519;
static const struct assh_algo_sign_s *sign_algo = &assh_sign_ed25519;
static struct assh_key_s *key_s, *key_c, *key_cbad;

enum test_state_e
{
  /* TEST00: check none fail */
  TEST00_ST_INIT,
  TEST00_ST_SEND_NONE,
  TEST00_ST_SERVER_FAILED,
  TEST00_ST_FAILED,
  TEST00_ST_DONE,
#if defined(CONFIG_ASSH_SERVER_AUTH_NONE)
  /* TEST01: check none pass */
  TEST01_ST_INIT,
  TEST01_ST_SEND_NONE,
  TEST01_ST_WAIT_NONE,
  TEST01_ST_WAIT_SUCCESS,
  TEST01_ST_SERVER_SUCCESS,
  TEST01_ST_SUCCESS,
  TEST01_ST_DONE,
  /* TEST29: check none pass */
  TEST29_ST_INIT,
  TEST29_ST_SEND_NONE,
  TEST29_ST_WAIT_NONE,
  TEST29_ST_WAIT_FAIL,
  TEST29_ST_SERVER_FAILED,
  TEST29_ST_FAILED,
  TEST29_ST_DONE,
#endif
#if defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY)
  /* TEST02: check key found with valid pubkey signature */
  TEST02_ST_INIT,
  TEST02_ST_SEND_SIGN,
  TEST02_ST_WAIT_SIGN,
  TEST02_ST_KEY_FOUND,
  TEST02_ST_KEY_FOUND_COK,
  TEST02_ST_SERVER_SUCCESS,
  TEST02_ST_SUCCESS,
  TEST02_ST_DONE,
  /* TEST03: check key found with bad signature  */
  TEST03_ST_INIT,
  TEST03_ST_SEND_SIGN,
  TEST03_ST_WAIT_SIGN,
  TEST03_ST_KEY_FOUND,
  TEST03_ST_SERVER_REJECT,
  /* TEST04: check key found with pkok and valid pubkey signature */
  TEST04_ST_INIT,
  TEST04_ST_SEND_KEY,
  TEST04_ST_WAIT_PKOK,
  TEST04_ST_KEY_FOUND,
  TEST04_ST_WAIT_SIGN,
  TEST04_ST_SERVER_SUCCESS,
  TEST04_ST_SUCCESS,
  TEST04_ST_DONE,
  /* TEST05: check key found with pkok and bad signature */
  TEST05_ST_INIT,
  TEST05_ST_SEND_KEY,
  TEST05_ST_WAIT_PKOK,
  TEST05_ST_KEY_FOUND,
  TEST05_ST_WAIT_SIGN,
  TEST05_ST_SERVER_REJECT,
  /* TEST06: check key found with pkok then change user on signature */
  TEST06_ST_INIT,
  TEST06_ST_SEND_KEY,
  TEST06_ST_WAIT_PKOK,
  TEST06_ST_KEY_FOUND,
  TEST06_ST_WAIT_SIGN,
  TEST06_ST_DONE,
  /* TEST07: check key found with pkok then change key on signature */
  TEST07_ST_INIT,
  TEST07_ST_SEND_KEY,
  TEST07_ST_WAIT_PKOK,
  TEST07_ST_KEY_FOUND,
  TEST07_ST_WAIT_SIGN,
  TEST07_ST_DONE,
  /* TEST08: check key not found with pkok */
  TEST08_ST_INIT,
  TEST08_ST_SEND_KEY,
  TEST08_ST_NOT_FOUND,
  TEST08_ST_WAIT_FAIL,
  TEST08_ST_SERVER_FAILED,
  TEST08_ST_NOT_FOUND2,
  TEST08_ST_WAIT_FAIL2,
  TEST08_ST_SERVER_FAILED2,
  TEST08_ST_FAILED,
  TEST08_ST_DONE,
#endif
#if defined(CONFIG_ASSH_SERVER_AUTH_PASSWORD)
  /* TEST09: password wrong, user ok */
  TEST09_ST_INIT,
  TEST09_ST_SEND_PASSWD,
  TEST09_ST_WRONG,
  TEST09_ST_WAIT_FAIL,
  TEST09_ST_SERVER_FAILED,
  TEST09_ST_FAILED,
  TEST09_ST_DONE,
  /* TEST10: password ok, user bad */
  TEST10_ST_INIT,
  TEST10_ST_SEND_PASSWD,
  TEST10_ST_WRONG,
  TEST10_ST_WAIT_FAIL,
  TEST10_ST_SERVER_FAILED,
  TEST10_ST_FAILED,
  TEST10_ST_DONE,
  /* TEST11: password success */
  TEST11_ST_INIT,
  TEST11_ST_SEND_PASSWD,
  TEST11_ST_PASSWD_OK,
  TEST11_ST_WAIT_SUCCESS,
  TEST11_ST_SERVER_SUCCESS,
  TEST11_ST_SUCCESS,
  TEST11_ST_DONE,
  /* TEST12: server requests password change, success */
  TEST12_ST_INIT,
  TEST12_ST_SEND_PASSWD,
  TEST12_ST_PASSWD_OK,
  TEST12_ST_WAIT_CHANGE,
  TEST12_ST_PASSWD_CHANGE,
  TEST12_ST_CHANGED,
  TEST12_ST_SERVER_SUCCESS,
  TEST12_ST_SUCCESS,
  TEST12_ST_DONE,
  /* TEST13: server requests password change, bad old password */
  TEST13_ST_INIT,
  TEST13_ST_SEND_PASSWD,
  TEST13_ST_PASSWD_OK,
  TEST13_ST_WAIT_CHANGE,
  TEST13_ST_PASSWD_CHANGE,
  TEST13_ST_WAIT_FAIL,
  TEST13_ST_SERVER_FAILED,
  TEST13_ST_FAILED,
  TEST13_ST_DONE,
  /* TEST14: server requests password change, client doesnt provide a new passord */
  TEST14_ST_INIT,
  TEST14_ST_SEND_PASSWD,
  TEST14_ST_PASSWD_OK,
  TEST14_ST_WAIT_CHANGE,
  TEST14_ST_WAIT_FAIL,
  TEST14_ST_SERVER_FAILED,
  TEST14_ST_FAILED,
  TEST14_ST_DONE,
  /* TEST15: client requests password change, success */
  TEST15_ST_INIT,
  TEST15_ST_SEND_CHANGE,
  TEST15_ST_PASSWD_CHANGE,
  TEST15_ST_CHANGED,
  TEST15_ST_SERVER_SUCCESS,
  TEST15_ST_SUCCESS,
  TEST15_ST_DONE,
  /* TEST16: client requests password change, bad old password */
  TEST16_ST_INIT,
  TEST16_ST_SEND_CHANGE,
  TEST16_ST_PASSWD_CHANGE,
  TEST16_ST_WAIT_FAIL,
  TEST16_ST_SERVER_FAILED,
  TEST16_ST_FAILED,
  TEST16_ST_DONE,
  /* TEST17: server requests password change, change user on new password */
  TEST17_ST_INIT,
  TEST17_ST_SEND_PASSWD,
  TEST17_ST_PASSWD_OK,
  TEST17_ST_WAIT_CHANGE,
  TEST17_ST_PASSWD_CHANGE,
  TEST17_ST_WAIT_FAIL,
  TEST17_ST_SERVER_FAILED,
  TEST17_ST_FAILED,
  TEST17_ST_DONE,
#endif
#if defined(CONFIG_ASSH_SERVER_AUTH_KEYBOARD)
  /* TEST18: keyboard-interactive success */
  TEST18_ST_INIT,
  TEST18_ST_SEND_METHOD,
  TEST18_ST_WAIT_INFO,
  TEST18_ST_SENT_INFO,
  TEST18_ST_WAIT_RESPONSE,
  TEST18_ST_SEND_RESPONSE,
  TEST18_ST_SERVER_SUCCESS,
  TEST18_ST_SUCCESS,
  TEST18_ST_DONE,
  /* TEST19: keyboard-interactive fail */
  TEST19_ST_INIT,
  TEST19_ST_SEND_METHOD,
  TEST19_ST_WAIT_INFO,
  TEST19_ST_SENT_INFO,
  TEST19_ST_WAIT_RESPONSE,
  TEST19_ST_SEND_RESPONSE,
  TEST19_ST_SERVER_FAILED,
  TEST19_ST_FAILED,
  TEST19_ST_DONE,
  /* TEST20: keyboard-interactive zero/continue/success */
  TEST20_ST_INIT,
  TEST20_ST_SEND_METHOD,
  TEST20_ST_WAIT_INFO,
  TEST20_ST_SENT_INFO,
  TEST20_ST_WAIT_RESPONSE,
  TEST20_ST_CONTINUE,
  TEST20_ST_SENT_INFO2,
  TEST20_ST_WAIT_RESPONSE2,
  TEST20_ST_SEND_RESPONSE2,
  TEST20_ST_SERVER_SUCCESS,
  TEST20_ST_SUCCESS,
  TEST20_ST_DONE,
  /* TEST21: keyboard-interactive zero/continue/fail */
  TEST21_ST_INIT,
  TEST21_ST_SEND_METHOD,
  TEST21_ST_WAIT_INFO,
  TEST21_ST_SENT_INFO,
  TEST21_ST_WAIT_RESPONSE,
  TEST21_ST_CONTINUE,
  TEST21_ST_SENT_INFO2,
  TEST21_ST_WAIT_RESPONSE2,
  TEST21_ST_SEND_RESPONSE2,
  TEST21_ST_SERVER_FAILED,
  TEST21_ST_FAILED,
  TEST21_ST_DONE,
  /* TEST22: keyboard-interactive count missmatch */
  TEST22_ST_INIT,
  TEST22_ST_SEND_METHOD,
  TEST22_ST_WAIT_INFO,
  TEST22_ST_SENT_INFO,
  TEST22_ST_WAIT_RESPONSE,
  TEST22_ST_SERVER_FAILED,
  TEST22_ST_FAILED,
  TEST22_ST_DONE,
#endif
#if defined(CONFIG_ASSH_SERVER_AUTH_HOSTBASED)
  /* TEST23: hostbased: check key found with valid signature */
  TEST23_ST_INIT,
  TEST23_ST_SEND_SIGN,
  TEST23_ST_WAIT_SIGN,
  TEST23_ST_KEY_FOUND,
  TEST23_ST_KEY_FOUND_COK,
  TEST23_ST_SERVER_SUCCESS,
  TEST23_ST_SUCCESS,
  TEST23_ST_DONE,
  /* TEST24: hostbased: check key found with bad signature */
  TEST24_ST_INIT,
  TEST24_ST_SEND_SIGN,
  TEST24_ST_WAIT_SIGN,
  TEST24_ST_KEY_FOUND,
  TEST24_ST_SERVER_REJECT,
  /* TEST25: hostbased: check key not found */
  TEST25_ST_INIT,
  TEST25_ST_SEND_SIGN,
  TEST25_ST_WAIT_SIGN,
  TEST25_ST_KEY_NOT_FOUND,
  TEST25_ST_SERVER_FAILED,
  TEST25_ST_FAILED,
  TEST25_ST_DONE,
#endif
#if defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY) && \
  defined(CONFIG_ASSH_SERVER_AUTH_PASSWORD)
  /* TEST26 partial auth success */
  TEST26_ST_INIT,
  TEST26_ST_SEND_SIGN,
  TEST26_ST_WAIT_SIGN,
  TEST26_ST_KEY_FOUND,
  TEST26_ST_PARTIAL_SUCCESS,
  TEST26_ST_SEND_PASSWD,
  TEST26_ST_PASSWD_OK,
  TEST26_ST_WAIT_SUCCESS,
  TEST26_ST_SERVER_SUCCESS,
  TEST26_ST_SUCCESS,
  TEST26_ST_DONE,
  /* TEST27 partial auth failure */
  TEST27_ST_INIT,
  TEST27_ST_SEND_SIGN,
  TEST27_ST_WAIT_SIGN,
  TEST27_ST_KEY_FOUND,
  TEST27_ST_PARTIAL_SUCCESS,
  TEST27_ST_SEND_PASSWD,
  TEST27_ST_PASSWD_WRONG,
  TEST27_ST_WAIT_FAIL,
  TEST27_ST_SERVER_FAILED,
  TEST27_ST_FAILED,
  TEST27_ST_DONE,
#endif
  /* TEST28: check bad method fails */
  TEST28_ST_INIT,
  TEST28_ST_SEND_BAD,
  TEST28_ST_SERVER_FAILED,
  TEST28_ST_FAILED,
  TEST28_ST_DONE,

  /*************************************/
  TEST_COUNT
};

static enum test_state_e test_state;
static enum test_state_e seq_state = TEST00_ST_INIT;

static void test_state_set(enum test_state_e s)
{
  test_state = s;
  ASSH_DEBUG("============ TEST STATE = %u\n", s);

  fprintf(stderr, "%03u.", s);

  if (s != seq_state++)
    TEST_FAIL("missing state %03u\n", seq_state);

  if (seq_state % 20 == 0)
    fprintf(stderr, "\n");
}

/**************************************************** client test service */

static void
assh_userauth_client_pck_head(struct assh_session_s *s,
			      struct assh_packet_s **pout,
			      size_t extra_len,
			      const char *username,
			      const char *srvname,
			      const char *method)
{
  size_t username_len = strlen(username);
  size_t srvname_len = strlen(srvname);
  size_t method_len = strlen(method);

  ASSH_ASSERT(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_REQUEST,
                 4 + username_len + 4 + srvname_len +
                 4 + method_len + extra_len, pout));
  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_string(*pout, username_len, &str));
  memcpy(str, username, username_len);
  ASSH_ASSERT(assh_packet_add_string(*pout, srvname_len, &str));
  memcpy(str, srvname, srvname_len);
  ASSH_ASSERT(assh_packet_add_string(*pout, method_len, &str));
  memcpy(str, method, method_len);
}

static const struct assh_service_s test_service_userauth_client;

static ASSH_SERVICE_INIT_FCN(test_userauth_client_init)
{
  s->srv = &test_service_userauth_client;

  return ASSH_OK;
}

static ASSH_SERVICE_CLEANUP_FCN(test_userauth_client_cleanup)
{
}

static void
test_userauth_client_none(struct assh_session_s *s, const char *user)
{
  struct assh_packet_s *pout;

  assh_userauth_client_pck_head(s, &pout, 0,
                                user, "ssh-connection", "none");

  assh_transport_push(s, pout);
}

#if defined(CONFIG_ASSH_SERVER_AUTH_KEYBOARD)
#define TEST_USERAUTH_KBINFO_COUNT 4

static const struct assh_cbuffer_s
test_userauth_kbinfo_rq[TEST_USERAUTH_KBINFO_COUNT] = {
  { .str = "password: ", .len = 10 },
  { .str = "token: ", .len = 7 },
  { .str = "foo: ", .len = 5 },
  { .str = "bar: ", .len = 5 },
};

static const struct assh_buffer_s
test_userauth_kbinfo_resp[TEST_USERAUTH_KBINFO_COUNT] = {
  { .str = "BaR_", .len = 4 },
  { .str = "FoOFoF", .len = 6 },
  { .str = "_bAr_", .len = 5 },
  { .str = "_fOfBaR_", .len = 8 },
};

static void
test_userauth_client_keyboard_reponse(struct assh_session_s *s,
                                      const struct assh_buffer_s *resp,
                                      size_t count)
{
  struct assh_packet_s *pout;

  size_t i, psize = 4;
  for (i = 0; i < count; i++)
    psize += 4 + resp[i].len;

  ASSH_ASSERT(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_INFO_RESPONSE,
                                 psize, &pout));

  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_array(pout, 4, &str));
  assh_store_u32(str, count);

  for (i = 0; i < count; i++)
    {
      size_t len = resp[i].len;
      ASSH_ASSERT(assh_packet_add_string(pout, len, &str));
      memcpy(str, resp[i].str, len);
    }

  assh_transport_push(s, pout);
}

static void
test_userauth_client_keyboard(struct assh_session_s *s,
                              const char *sub, const char *user)
{
  size_t sub_len = strlen(sub);
  struct assh_packet_s *pout;

  assh_userauth_client_pck_head(s, &pout, 4 + 4 + sub_len,
                                user, "ssh-connection", "keyboard-interactive");

  uint8_t *str;

  ASSH_ASSERT(assh_packet_add_string(pout, 0, &str)); /* lang */
  ASSH_ASSERT(assh_packet_add_string(pout, sub_len, &str));
  memcpy(str, sub, sub_len);

  assh_transport_push(s, pout);
}
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_PASSWORD)
static void
test_userauth_client_password(struct assh_session_s *s, const char *pw,
			      const char *new_pw, const char *user)
{
  size_t pw_len = 4 + strlen(pw);
  size_t new_pw_len = new_pw ? 4 + strlen(new_pw) : 0;
  struct assh_packet_s *pout;

  assh_userauth_client_pck_head(s, &pout, 1 + pw_len + new_pw_len,
                                user, "ssh-connection", "password");

  uint8_t *bool_, *str;

  ASSH_ASSERT(assh_packet_add_array(pout, 1, &bool_));
  *bool_ = (new_pw != NULL);

  ASSH_ASSERT(assh_packet_add_string(pout, pw_len - 4, &str));
  memcpy(str, pw, pw_len - 4);

  if (new_pw)
    {
      ASSH_ASSERT(assh_packet_add_string(pout, new_pw_len - 4, &str));
      memcpy(str, new_pw, new_pw_len - 4);
    }

  assh_transport_push(s, pout);
}
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_HOSTBASED) || \
defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY)
static void
test_userauth_client_sign(struct assh_session_s *s,
                          struct assh_packet_s *pout,
                          size_t sign_len, struct assh_key_s *key,
                          assh_bool_t bad_sign)
{
  uint8_t sid_len[4];   /* fake string header for session id */
  assh_store_u32(sid_len, s->session_id_len);

  /* buffers that must be signed by the client */
  struct assh_cbuffer_s data[3] = {
    { .data = sid_len,         .len = 4 },
    { .data = s->session_id,   .len = s->session_id_len },
    { .data = &pout->head.msg, .len = pout->data_size - 5 },
  };

  /* append the signature */
  uint8_t *sign;
  ASSH_ASSERT(assh_packet_add_string(pout, sign_len, &sign));
  if (assh_sign_generate(s->ctx, sign_algo, key,
                         3, data, sign, &sign_len))
    TEST_FAIL("");

  if (bad_sign)
    sign[8] ^= 1;

  assh_packet_shrink_string(pout, sign, sign_len);
}
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY)
static void
test_userauth_client_pubkey(struct assh_session_s *s, struct assh_key_s *key,
                            const char *user, assh_bool_t pkok,
                            assh_bool_t bad_sign)
{
  size_t sign_len = 0;

  if (!pkok)
    {
      if (assh_sign_generate(s->ctx, sign_algo, key, 0,
			     NULL, NULL, &sign_len))
	TEST_FAIL("");
      sign_len += 4;
    }

  struct assh_packet_s *pout;

  size_t algo_name_len = strlen(assh_algo_name(&sign_algo->algo));

  size_t blob_len;
  if (assh_key_output(s->ctx, key,
		  NULL, &blob_len, ASSH_KEY_FMT_PUB_RFC4253))
    TEST_FAIL("");

  assh_userauth_client_pck_head(s, &pout,
			 1 + 4 + algo_name_len + 4 + blob_len + 4 + sign_len,
				    user, "ssh-connection", "publickey");

  /* add boolean */
  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_array(pout, 1, &str));
  *str = !pkok;

  /* add signature algorithm name */
  uint8_t *algo_name;
  ASSH_ASSERT(assh_packet_add_string(pout, algo_name_len, &algo_name));
  memcpy(algo_name, assh_algo_name(&sign_algo->algo), algo_name_len);

  /* add public key blob */
  uint8_t *blob;
  ASSH_ASSERT(assh_packet_add_string(pout, blob_len, &blob));
  if (assh_key_output(s->ctx, key, blob, &blob_len,
			  ASSH_KEY_FMT_PUB_RFC4253))
    TEST_FAIL("");

  assh_packet_shrink_string(pout, blob, blob_len);

  if (!pkok)
    test_userauth_client_sign(s, pout, sign_len, key, bad_sign);

  assh_transport_push(s, pout);
}
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_HOSTBASED)
static void
test_userauth_client_hostbased(struct assh_session_s *s, struct assh_key_s *key,
                               const char *user, const char *hostname,
                               const char *husername, assh_bool_t bad_sign)
{
  size_t sign_len = 0;

  if (assh_sign_generate(s->ctx, sign_algo, key, 0,
                         NULL, NULL, &sign_len))
    TEST_FAIL("");

  struct assh_packet_s *pout;

  size_t algo_name_len = strlen(assh_algo_name(&sign_algo->algo));
  size_t hostname_len = strlen(hostname);
  size_t husername_len = strlen(husername);

  size_t blob_len;
  if (assh_key_output(s->ctx, key,
		  NULL, &blob_len, ASSH_KEY_FMT_PUB_RFC4253))
    TEST_FAIL("");

  assh_userauth_client_pck_head(s, &pout,
                                4 + algo_name_len + 4 + blob_len +
                                4 + hostname_len + 4 + husername_len +
                                4 + sign_len,
				    user, "ssh-connection", "hostbased");

  /* add signature algorithm name */
  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_string(pout, algo_name_len, &str));
  memcpy(str, assh_algo_name(&sign_algo->algo), algo_name_len);

  /* add public key blob */
  uint8_t *blob;
  ASSH_ASSERT(assh_packet_add_string(pout, blob_len, &blob));
  if (assh_key_output(s->ctx, key, blob, &blob_len,
			  ASSH_KEY_FMT_PUB_RFC4253))
    TEST_FAIL("");
  assh_packet_shrink_string(pout, blob, blob_len);

  ASSH_ASSERT(assh_packet_add_string(pout, hostname_len, &str));
  memcpy(str, hostname, hostname_len);

  ASSH_ASSERT(assh_packet_add_string(pout, husername_len, &str));
  memcpy(str, husername, husername_len);

  test_userauth_client_sign(s, pout, sign_len, key, bad_sign);

  assh_transport_push(s, pout);
}
#endif

static ASSH_SERVICE_PROCESS_FCN(test_userauth_client_process)
{
  switch (test_state)
    {
      /*************************************************** TEST00 */
    case TEST00_ST_SEND_NONE:
      test_userauth_client_none(s, "allowed");
      test_state_set(TEST00_ST_SERVER_FAILED);
      goto no_packet;

    case TEST00_ST_SERVER_FAILED:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_FAILURE)
	TEST_FAIL("");
      test_state_set(TEST00_ST_FAILED);
      break;

#if defined(CONFIG_ASSH_SERVER_AUTH_NONE)
      /*************************************************** TEST01 */
    case TEST01_ST_SEND_NONE:
      test_userauth_client_none(s, "allowed");
      test_state_set(TEST01_ST_WAIT_NONE);
      goto no_packet;

    case TEST01_ST_SERVER_SUCCESS:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_SUCCESS)
	TEST_FAIL("");
      test_state_set(TEST01_ST_SUCCESS);
      break;

      /*************************************************** TEST29 */
    case TEST29_ST_SEND_NONE:
      test_userauth_client_none(s, "allowed");
      test_state_set(TEST29_ST_WAIT_NONE);
      goto no_packet;

    case TEST29_ST_SERVER_FAILED:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_FAILURE)
	TEST_FAIL("");
      test_state_set(TEST29_ST_FAILED);
      break;
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY)
      /*************************************************** TEST02 */
    case TEST02_ST_SEND_SIGN:
      test_userauth_client_pubkey(s, key_c, "allowed", 0, 0);
      test_state_set(TEST02_ST_WAIT_SIGN);
      goto no_packet;

    case TEST02_ST_WAIT_SIGN:
      goto no_packet;

    case TEST02_ST_KEY_FOUND:
      test_state_set(TEST02_ST_KEY_FOUND_COK);
      goto no_packet;

    case TEST02_ST_SERVER_SUCCESS:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_SUCCESS)
	TEST_FAIL("");
      test_state_set(TEST02_ST_SUCCESS);
      break;

      /*************************************************** TEST03 */
    case TEST03_ST_SEND_SIGN:
      test_userauth_client_pubkey(s, key_c, "allowed", 0, 1);
      test_state_set(TEST03_ST_WAIT_SIGN);
      goto no_packet;

    case TEST03_ST_WAIT_SIGN:
    case TEST03_ST_KEY_FOUND:
      goto no_packet;

      /*************************************************** TEST04 */
    case TEST04_ST_SEND_KEY:
      test_userauth_client_pubkey(s, key_c, "allowed", 1, 0);
      test_state_set(TEST04_ST_WAIT_PKOK);
      goto no_packet;

    case TEST04_ST_KEY_FOUND:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_PK_OK)
	TEST_FAIL("");
      test_userauth_client_pubkey(s, key_c, "allowed", 0, 0);
      test_state_set(TEST04_ST_WAIT_SIGN);
      break;
    case TEST04_ST_SERVER_SUCCESS:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_SUCCESS)
	TEST_FAIL("");
      test_state_set(TEST04_ST_SUCCESS);
      break;

      /*************************************************** TEST05 */
    case TEST05_ST_SEND_KEY:
      test_userauth_client_pubkey(s, key_c, "allowed", 1, 0);
      test_state_set(TEST05_ST_WAIT_PKOK);
      goto no_packet;

    case TEST05_ST_KEY_FOUND:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_PK_OK)
	TEST_FAIL("");
      test_userauth_client_pubkey(s, key_c, "allowed", 0, 1);
      test_state_set(TEST05_ST_WAIT_SIGN);
      break;

      /*************************************************** TEST06 */
    case TEST06_ST_SEND_KEY:
      test_userauth_client_pubkey(s, key_c, "allowed", 1, 0);
      test_state_set(TEST06_ST_WAIT_PKOK);
      goto no_packet;

    case TEST06_ST_KEY_FOUND:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_PK_OK)
	TEST_FAIL("");
      test_userauth_client_pubkey(s, key_c, "badguy", 0, 0);
      test_state_set(TEST06_ST_WAIT_SIGN);
      break;

      /*************************************************** TEST07 */
    case TEST07_ST_SEND_KEY:
      test_userauth_client_pubkey(s, key_c, "allowed", 1, 0);
      test_state_set(TEST07_ST_WAIT_PKOK);
      goto no_packet;

    case TEST07_ST_KEY_FOUND:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_PK_OK)
	TEST_FAIL("");
      test_userauth_client_pubkey(s, key_cbad, "allowed", 0, 0);
      test_state_set(TEST07_ST_WAIT_SIGN);
      break;

      /*************************************************** TEST08 */
    case TEST08_ST_SEND_KEY:
      test_userauth_client_pubkey(s, key_c, "allowed", 1, 0);
      test_state_set(TEST08_ST_NOT_FOUND);
      goto no_packet;
    case TEST08_ST_SERVER_FAILED:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_FAILURE)
	TEST_FAIL("");
      test_userauth_client_pubkey(s, key_c, "allowed", 0, 0);
      test_state_set(TEST08_ST_NOT_FOUND2);
      break;
    case TEST08_ST_SERVER_FAILED2:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_FAILURE)
	TEST_FAIL("");
      test_state_set(TEST08_ST_FAILED);
      break;
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_PASSWORD)
      /*************************************************** TEST09 */
    case TEST09_ST_SEND_PASSWD:
      test_userauth_client_password(s, "wrong", NULL, "allowed");
      test_state_set(TEST09_ST_WRONG);
      goto no_packet;
    case TEST09_ST_SERVER_FAILED:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_FAILURE)
	TEST_FAIL("");
      test_state_set(TEST09_ST_FAILED);
      break;

      /*************************************************** TEST10 */
    case TEST10_ST_SEND_PASSWD:
      test_userauth_client_password(s, "pass", NULL, "badguy");
      test_state_set(TEST10_ST_WRONG);
      goto no_packet;
    case TEST10_ST_SERVER_FAILED:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_FAILURE)
	TEST_FAIL("");
      test_state_set(TEST10_ST_FAILED);
      break;

      /*************************************************** TEST11 */
    case TEST11_ST_SEND_PASSWD:
      test_userauth_client_password(s, "pass", NULL, "allowed");
      test_state_set(TEST11_ST_PASSWD_OK);
      goto no_packet;
    case TEST11_ST_SERVER_SUCCESS:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_SUCCESS)
	TEST_FAIL("");
      test_state_set(TEST11_ST_SUCCESS);
      break;

      /*************************************************** TEST12 */
    case TEST12_ST_SEND_PASSWD:
      test_userauth_client_password(s, "pass", NULL, "allowed");
      test_state_set(TEST12_ST_PASSWD_OK);
      goto no_packet;
    case TEST12_ST_WAIT_CHANGE:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_PASSWD_CHANGEREQ)
	TEST_FAIL("");
      test_userauth_client_password(s, "pass", "newpass", "allowed");
      test_state_set(TEST12_ST_PASSWD_CHANGE);
      break;
    case TEST12_ST_SERVER_SUCCESS:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_SUCCESS)
	TEST_FAIL("");
      test_state_set(TEST12_ST_SUCCESS);
      break;

      /*************************************************** TEST13 */
    case TEST13_ST_SEND_PASSWD:
      test_userauth_client_password(s, "pass", NULL, "allowed");
      test_state_set(TEST13_ST_PASSWD_OK);
      goto no_packet;
    case TEST13_ST_WAIT_CHANGE:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_PASSWD_CHANGEREQ)
	TEST_FAIL("");
      test_userauth_client_password(s, "wrong", "newpass", "allowed");
      test_state_set(TEST13_ST_PASSWD_CHANGE);
      break;
    case TEST13_ST_SERVER_FAILED:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_FAILURE)
	TEST_FAIL("");
      test_state_set(TEST13_ST_FAILED);
      break;

      /*************************************************** TEST14 */
    case TEST14_ST_SEND_PASSWD:
      test_userauth_client_password(s, "pass", NULL, "allowed");
      test_state_set(TEST14_ST_PASSWD_OK);
      goto no_packet;
    case TEST14_ST_WAIT_CHANGE:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_PASSWD_CHANGEREQ)
	TEST_FAIL("");
      test_userauth_client_password(s, "pass", NULL, "allowed");
      test_state_set(TEST14_ST_WAIT_FAIL);
      break;
    case TEST14_ST_SERVER_FAILED:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_FAILURE)
	TEST_FAIL("");
      test_state_set(TEST14_ST_FAILED);
      break;

      /*************************************************** TEST15 */
    case TEST15_ST_SEND_CHANGE:
      test_userauth_client_password(s, "pass", "newpass", "allowed");
      test_state_set(TEST15_ST_PASSWD_CHANGE);
      break;
    case TEST15_ST_SERVER_SUCCESS:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_SUCCESS)
	TEST_FAIL("");
      test_state_set(TEST15_ST_SUCCESS);
      break;

      /*************************************************** TEST16 */
    case TEST16_ST_SEND_CHANGE:
      test_userauth_client_password(s, "wrong", "newpass", "allowed");
      test_state_set(TEST16_ST_PASSWD_CHANGE);
      break;
    case TEST16_ST_SERVER_FAILED:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_FAILURE)
	TEST_FAIL("");
      test_state_set(TEST16_ST_FAILED);
      break;

      /*************************************************** TEST17 */
    case TEST17_ST_SEND_PASSWD:
      test_userauth_client_password(s, "pass", NULL, "allowed");
      test_state_set(TEST17_ST_PASSWD_OK);
      goto no_packet;
    case TEST17_ST_WAIT_CHANGE:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_PASSWD_CHANGEREQ)
	TEST_FAIL("");
      test_userauth_client_password(s, "pass", "newpass", "badguy");
      test_state_set(TEST17_ST_PASSWD_CHANGE);
      break;
    case TEST17_ST_SERVER_FAILED:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_FAILURE)
	TEST_FAIL("");
      test_state_set(TEST17_ST_FAILED);
      break;
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_KEYBOARD)
      /*************************************************** TEST18 */
    case TEST18_ST_SEND_METHOD:
      test_userauth_client_keyboard(s, "sub", "allowed");
      test_state_set(TEST18_ST_WAIT_INFO);
      goto no_packet;

    case TEST18_ST_SENT_INFO:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_INFO_REQUEST)
	TEST_FAIL("");
      test_userauth_client_keyboard_reponse(s, test_userauth_kbinfo_resp, 4);
      test_state_set(TEST18_ST_WAIT_RESPONSE);
      break;

    case TEST18_ST_SERVER_SUCCESS:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_SUCCESS)
	TEST_FAIL("");
      test_state_set(TEST18_ST_SUCCESS);
      break;

      /*************************************************** TEST19 */
    case TEST19_ST_SEND_METHOD:
      test_userauth_client_keyboard(s, "sub", "allowed");
      test_state_set(TEST19_ST_WAIT_INFO);
      goto no_packet;

    case TEST19_ST_SENT_INFO:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_INFO_REQUEST)
	TEST_FAIL("");
      test_userauth_client_keyboard_reponse(s, test_userauth_kbinfo_resp, 4);
      test_state_set(TEST19_ST_WAIT_RESPONSE);
      break;

    case TEST19_ST_SERVER_FAILED:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_FAILURE)
	TEST_FAIL("");
      test_state_set(TEST19_ST_FAILED);
      break;

      /*************************************************** TEST20 */
    case TEST20_ST_SEND_METHOD:
      test_userauth_client_keyboard(s, "sub", "allowed");
      test_state_set(TEST20_ST_WAIT_INFO);
      goto no_packet;

    case TEST20_ST_SENT_INFO:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_INFO_REQUEST)
	TEST_FAIL("");
      test_userauth_client_keyboard_reponse(s, test_userauth_kbinfo_resp, 0);
      test_state_set(TEST20_ST_WAIT_RESPONSE);
      break;

    case TEST20_ST_SENT_INFO2:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_INFO_REQUEST)
	TEST_FAIL("");
      test_userauth_client_keyboard_reponse(s, test_userauth_kbinfo_resp, 2);
      test_state_set(TEST20_ST_WAIT_RESPONSE2);
      break;

    case TEST20_ST_SERVER_SUCCESS:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_SUCCESS)
	TEST_FAIL("");
      test_state_set(TEST20_ST_SUCCESS);
      break;

      /*************************************************** TEST21 */
    case TEST21_ST_SEND_METHOD:
      test_userauth_client_keyboard(s, "sub", "allowed");
      test_state_set(TEST21_ST_WAIT_INFO);
      goto no_packet;

    case TEST21_ST_SENT_INFO:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_INFO_REQUEST)
	TEST_FAIL("");
      test_userauth_client_keyboard_reponse(s, test_userauth_kbinfo_resp, 0);
      test_state_set(TEST21_ST_WAIT_RESPONSE);
      break;

    case TEST21_ST_SENT_INFO2:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_INFO_REQUEST)
	TEST_FAIL("");
      test_userauth_client_keyboard_reponse(s, test_userauth_kbinfo_resp, 2);
      test_state_set(TEST21_ST_WAIT_RESPONSE2);
      break;

    case TEST21_ST_SERVER_FAILED:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_FAILURE)
	TEST_FAIL("");
      test_state_set(TEST21_ST_FAILED);
      break;

      /*************************************************** TEST22 */
    case TEST22_ST_SEND_METHOD:
      test_userauth_client_keyboard(s, "sub", "allowed");
      test_state_set(TEST22_ST_WAIT_INFO);
      goto no_packet;

    case TEST22_ST_SENT_INFO:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_INFO_REQUEST)
	TEST_FAIL("");
      test_userauth_client_keyboard_reponse(s, test_userauth_kbinfo_resp, 1);
      test_state_set(TEST22_ST_WAIT_RESPONSE);
      break;

    case TEST22_ST_SERVER_FAILED:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_FAILURE)
	TEST_FAIL("");
      test_state_set(TEST22_ST_FAILED);
      break;
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_HOSTBASED)
      /*************************************************** TEST23 */
    case TEST23_ST_SEND_SIGN:
      test_userauth_client_hostbased(s, key_c, "allowed", "localhost", "hallowed", 0);
      test_state_set(TEST23_ST_WAIT_SIGN);
      goto no_packet;

    case TEST23_ST_WAIT_SIGN:
      goto no_packet;

    case TEST23_ST_KEY_FOUND:
      test_state_set(TEST23_ST_KEY_FOUND_COK);
      goto no_packet;

    case TEST23_ST_SERVER_SUCCESS:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_SUCCESS)
	TEST_FAIL("");
      test_state_set(TEST23_ST_SUCCESS);
      break;

      /*************************************************** TEST24 */
    case TEST24_ST_SEND_SIGN:
      test_userauth_client_hostbased(s, key_c, "allowed", "localhost", "hallowed", 1);
      test_state_set(TEST24_ST_WAIT_SIGN);
      goto no_packet;

    case TEST24_ST_WAIT_SIGN:
    case TEST24_ST_KEY_FOUND:
      goto no_packet;

      /*************************************************** TEST25 */
    case TEST25_ST_SEND_SIGN:
      test_userauth_client_hostbased(s, key_c, "allowed", "localhost", "hallowed", 0);
      test_state_set(TEST25_ST_WAIT_SIGN);
      goto no_packet;

    case TEST25_ST_SERVER_FAILED:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_FAILURE)
	TEST_FAIL("");
      test_state_set(TEST25_ST_FAILED);
      break;
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY) && \
  defined(CONFIG_ASSH_SERVER_AUTH_PASSWORD)
      /*************************************************** TEST26 */
    case TEST26_ST_SEND_SIGN:
      test_userauth_client_pubkey(s, key_c, "allowed", 0, 0);
      test_state_set(TEST26_ST_WAIT_SIGN);
      goto no_packet;

    case TEST26_ST_WAIT_SIGN:
      goto no_packet;

    case TEST26_ST_KEY_FOUND:
      test_state_set(TEST26_ST_PARTIAL_SUCCESS);
      goto no_packet;

    case TEST26_ST_SEND_PASSWD: {
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_FAILURE)
	TEST_FAIL("");
      const uint8_t *str = p->head.end;
      if (assh_packet_check_string(p, str, &str) ||
          assh_packet_check_array(p, str, 1, NULL) || !*str)
        TEST_FAIL("no partial success");
      test_userauth_client_password(s, "pass", NULL, "allowed");
      test_state_set(TEST26_ST_PASSWD_OK);
      return ASSH_OK;
    }

    case TEST26_ST_SERVER_SUCCESS:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_SUCCESS)
	TEST_FAIL("");
      test_state_set(TEST26_ST_SUCCESS);
      break;

      /*************************************************** TEST27 */
    case TEST27_ST_SEND_SIGN:
      test_userauth_client_pubkey(s, key_c, "allowed", 0, 0);
      test_state_set(TEST27_ST_WAIT_SIGN);
      goto no_packet;

    case TEST27_ST_WAIT_SIGN:
      goto no_packet;

    case TEST27_ST_KEY_FOUND:
      test_state_set(TEST27_ST_PARTIAL_SUCCESS);
      goto no_packet;

    case TEST27_ST_SEND_PASSWD: {
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_FAILURE)
	TEST_FAIL("");
      const uint8_t *str = p->head.end;
      if (assh_packet_check_string(p, str, &str) ||
          assh_packet_check_array(p, str, 1, NULL) || !*str)
        TEST_FAIL("no partial success");
      test_userauth_client_password(s, "wrong", NULL, "allowed");
      test_state_set(TEST27_ST_PASSWD_WRONG);
      return ASSH_OK;
    }

    case TEST27_ST_SERVER_FAILED:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_FAILURE)
	TEST_FAIL("");
      test_state_set(TEST27_ST_FAILED);
      break;
#endif

      /*************************************************** TEST28 */
    case TEST28_ST_SEND_BAD: {
      struct assh_packet_s *pout;
      assh_userauth_client_pck_head(s, &pout, 0,
        "allowed", "ssh-connection", "bad");
      assh_transport_push(s, pout);
      test_state_set(TEST28_ST_SERVER_FAILED);
      goto no_packet;
    }

    case TEST28_ST_SERVER_FAILED:
      if (p == NULL)
	break;
      if (p->head.msg != SSH_MSG_USERAUTH_FAILURE)
	TEST_FAIL("");
      test_state_set(TEST28_ST_FAILED);
      break;


    default:
      break;
    }

  return ASSH_OK;

 no_packet:
  if (p != NULL)
    TEST_FAIL("unexpected packet");

  return ASSH_OK;
}

static const struct assh_service_s test_service_userauth_client =
{
  .name = "ssh-userauth",
  .side = ASSH_CLIENT,
  .f_init = test_userauth_client_init,
  .f_cleanup = test_userauth_client_cleanup,
  .f_process = test_userauth_client_process,
};

/************************************************************** event loop */

static void test()
{
  uint_fast8_t i;
  uint_fast8_t stall = 0;
  size_t alloc_size_init = alloc_size;

  for (i = 0; i < 2; i++)
    {
      if (assh_session_init(&context[i], &session[i]) != ASSH_OK)
	TEST_FAIL("");

      fifo_init(&fifo[i]);
    }

  while (1)
    {
      struct assh_event_s event;

      /****************************************************/
      ASSH_DEBUG("=== server %u ===\n", stall);
      if (!assh_event_get(&session[0], &event, 0))
        TEST_FAIL("session terminated");

      switch (event.id)
	{
	case ASSH_EVENT_READ:
	  if (fifo_rw_event(fifo, &event, 0))
	    stall++;
	  break;

	case ASSH_EVENT_WRITE:
          stall++;
	  if (!fifo_rw_event(fifo, &event, 0))
	    stall = 0;
	  break;

        case ASSH_EVENT_SESSION_ERROR:
	  switch (test_state)
	    {
#if defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY)
	      /*************************************************** TEST05 */
	    case TEST05_ST_WAIT_SIGN:
	      test_state_set(TEST05_ST_SERVER_REJECT);
	      goto done;
#endif
#if defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY)
	      /*************************************************** TEST03 */
	    case TEST03_ST_KEY_FOUND:
	      test_state_set(TEST03_ST_SERVER_REJECT);
	      goto done;
#endif
#if defined(CONFIG_ASSH_SERVER_AUTH_HOSTBASED)
	      /*************************************************** TEST24 */
	    case TEST24_ST_KEY_FOUND:
	      test_state_set(TEST24_ST_SERVER_REJECT);
	      goto done;
#endif
	    default:
	      TEST_FAIL("server unexpected error event");
	    }
          break;

	case ASSH_EVENT_USERAUTH_SERVER_METHODS:
	  switch (test_state)
	    {
	      /*************************************************** TEST00 */
	    case TEST00_ST_INIT:
	      if (event.userauth_server.methods.failed)
		TEST_FAIL("");
	      test_state_set(TEST00_ST_SEND_NONE);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_SERVER_IMPLEMENTED &
                ~ASSH_USERAUTH_METHOD_NONE;
	      break;

#if defined(CONFIG_ASSH_SERVER_AUTH_NONE)
	      /*************************************************** TEST01 */
	    case TEST01_ST_INIT:
	      test_state_set(TEST01_ST_SEND_NONE);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_NONE;
	      break;
	      /*************************************************** TEST29 */
	    case TEST29_ST_INIT:
	      test_state_set(TEST29_ST_SEND_NONE);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_NONE;
	      break;
	    case TEST29_ST_WAIT_FAIL:
	      test_state_set(TEST29_ST_SERVER_FAILED);
	      break;
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY)
	      /*************************************************** TEST02 */
	    case TEST02_ST_INIT:
	      test_state_set(TEST02_ST_SEND_SIGN);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_PUBKEY;
	      break;
	      /*************************************************** TEST03 */
	    case TEST03_ST_INIT:
	      test_state_set(TEST03_ST_SEND_SIGN);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_PUBKEY;
	      break;
	      /*************************************************** TEST04 */
	    case TEST04_ST_INIT:
	      test_state_set(TEST04_ST_SEND_KEY);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_PUBKEY;
	      break;
	      /*************************************************** TEST05 */
	    case TEST05_ST_INIT:
	      test_state_set(TEST05_ST_SEND_KEY);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_PUBKEY;
	      break;
	      /*************************************************** TEST06 */
	    case TEST06_ST_INIT:
	      test_state_set(TEST06_ST_SEND_KEY);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_PUBKEY;
	      break;
	      /*************************************************** TEST07 */
	    case TEST07_ST_INIT:
	      test_state_set(TEST07_ST_SEND_KEY);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_PUBKEY;
	      break;
	      /*************************************************** TEST08 */
	    case TEST08_ST_INIT:
	      test_state_set(TEST08_ST_SEND_KEY);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_PUBKEY;
	      break;
	    case TEST08_ST_WAIT_FAIL:
	      if (!event.userauth_server.methods.failed)
		TEST_FAIL("");
	      test_state_set(TEST08_ST_SERVER_FAILED);
	      break;
	    case TEST08_ST_WAIT_FAIL2:
	      if (!event.userauth_server.methods.failed)
		TEST_FAIL("");
	      test_state_set(TEST08_ST_SERVER_FAILED2);
	      break;
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_PASSWORD)
	      /*************************************************** TEST09 */
	    case TEST09_ST_INIT:
	      test_state_set(TEST09_ST_SEND_PASSWD);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_PASSWORD;
	      break;
	    case TEST09_ST_WAIT_FAIL:
	      if (!event.userauth_server.methods.failed)
		TEST_FAIL("");
	      test_state_set(TEST09_ST_SERVER_FAILED);
	      break;
	      /*************************************************** TEST10 */
	    case TEST10_ST_INIT:
	      test_state_set(TEST10_ST_SEND_PASSWD);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_PASSWORD;
	      break;
	    case TEST10_ST_WAIT_FAIL:
	      if (!event.userauth_server.methods.failed)
		TEST_FAIL("");
	      test_state_set(TEST10_ST_SERVER_FAILED);
	      break;
	      /*************************************************** TEST11 */
	    case TEST11_ST_INIT:
	      test_state_set(TEST11_ST_SEND_PASSWD);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_PASSWORD;
	      break;
	      /*************************************************** TEST12 */
	    case TEST12_ST_INIT:
	      test_state_set(TEST12_ST_SEND_PASSWD);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_PASSWORD;
	      break;
	      /*************************************************** TEST13 */
	    case TEST13_ST_INIT:
	      test_state_set(TEST13_ST_SEND_PASSWD);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_PASSWORD;
	      break;
	    case TEST13_ST_WAIT_FAIL:
	      if (!event.userauth_server.methods.failed)
		TEST_FAIL("");
	      test_state_set(TEST13_ST_SERVER_FAILED);
	      break;
	      /*************************************************** TEST14 */
	    case TEST14_ST_INIT:
	      test_state_set(TEST14_ST_SEND_PASSWD);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_PASSWORD;
	      break;
	    case TEST14_ST_WAIT_FAIL:
	      if (!event.userauth_server.methods.failed)
		TEST_FAIL("");
	      test_state_set(TEST14_ST_SERVER_FAILED);
	      break;
	      /*************************************************** TEST15 */
	    case TEST15_ST_INIT:
	      test_state_set(TEST15_ST_SEND_CHANGE);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_PASSWORD;
	      break;
	      /*************************************************** TEST16 */
	    case TEST16_ST_INIT:
	      test_state_set(TEST16_ST_SEND_CHANGE);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_PASSWORD;
	      break;
	    case TEST16_ST_WAIT_FAIL:
	      if (!event.userauth_server.methods.failed)
		TEST_FAIL("");
	      test_state_set(TEST16_ST_SERVER_FAILED);
	      break;
	      /*************************************************** TEST17 */
	    case TEST17_ST_INIT:
	      test_state_set(TEST17_ST_SEND_PASSWD);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_PASSWORD;
	      break;
	    case TEST17_ST_WAIT_FAIL:
	      if (!event.userauth_server.methods.failed)
		TEST_FAIL("");
	      test_state_set(TEST17_ST_SERVER_FAILED);
	      break;
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_KEYBOARD)
	      /*************************************************** TEST18 */
	    case TEST18_ST_INIT:
	      test_state_set(TEST18_ST_SEND_METHOD);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_KEYBOARD;
	      break;
	      /*************************************************** TEST19 */
	    case TEST19_ST_INIT:
	      test_state_set(TEST19_ST_SEND_METHOD);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_KEYBOARD;
	      break;

            case TEST19_ST_SEND_RESPONSE:
	      if (!event.userauth_server.methods.failed)
		TEST_FAIL("");
	      test_state_set(TEST19_ST_SERVER_FAILED);
	      break;
	      /*************************************************** TEST20 */
	    case TEST20_ST_INIT:
	      test_state_set(TEST20_ST_SEND_METHOD);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_KEYBOARD;
	      break;

	      /*************************************************** TEST21 */
	    case TEST21_ST_INIT:
	      test_state_set(TEST21_ST_SEND_METHOD);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_KEYBOARD;
	      break;

            case TEST21_ST_SEND_RESPONSE2:
	      if (!event.userauth_server.methods.failed)
		TEST_FAIL("");
	      test_state_set(TEST21_ST_SERVER_FAILED);
	      break;

	      /*************************************************** TEST22 */
	    case TEST22_ST_INIT:
	      test_state_set(TEST22_ST_SEND_METHOD);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_KEYBOARD;
	      break;

            case TEST22_ST_WAIT_RESPONSE:
	      if (!event.userauth_server.methods.failed)
		TEST_FAIL("");
	      test_state_set(TEST22_ST_SERVER_FAILED);
	      break;
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_HOSTBASED)
	      /*************************************************** TEST23 */
	    case TEST23_ST_INIT:
	      test_state_set(TEST23_ST_SEND_SIGN);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_HOSTBASED;
	      break;

	      /*************************************************** TEST24 */
	    case TEST24_ST_INIT:
	      test_state_set(TEST24_ST_SEND_SIGN);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_HOSTBASED;
	      break;

	      /*************************************************** TEST25 */
	    case TEST25_ST_INIT:
	      test_state_set(TEST25_ST_SEND_SIGN);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_HOSTBASED;
	      break;

	    case TEST25_ST_KEY_NOT_FOUND:
	      if (!event.userauth_server.methods.failed)
		TEST_FAIL("");
	      test_state_set(TEST25_ST_SERVER_FAILED);
	      break;
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY) &&       \
  defined(CONFIG_ASSH_SERVER_AUTH_PASSWORD)
	      /*************************************************** TEST26 */
	    case TEST26_ST_INIT:
	      test_state_set(TEST26_ST_SEND_SIGN);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_PUBKEY;
	      break;

	      /*************************************************** TEST27 */
	    case TEST27_ST_INIT:
	      test_state_set(TEST27_ST_SEND_SIGN);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_PUBKEY;
	      break;
	    case TEST27_ST_WAIT_FAIL:
	      if (!event.userauth_server.methods.failed)
		TEST_FAIL("");
	      test_state_set(TEST27_ST_SERVER_FAILED);
	      break;
#endif
	      /*************************************************** TEST28 */
	    case TEST28_ST_INIT:
	      if (event.userauth_server.methods.failed)
		TEST_FAIL("");
	      test_state_set(TEST28_ST_SEND_BAD);
	      event.userauth_server.methods.methods =
		ASSH_USERAUTH_METHOD_SERVER_IMPLEMENTED;
	      break;

	    default:
	      TEST_FAIL("bad server state %u\n", test_state);
	    }
	  break;

#if defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY)
	case ASSH_EVENT_USERAUTH_SERVER_USERKEY: {
	  stall = 0;
	  assh_bool_t uok = !assh_buffer_strcmp(
	    &event.userauth_server.userkey.username, "allowed");
	  assh_bool_t keq = assh_key_cmp(&context[0],
	    event.userauth_server.userkey.pub_key, key_c, 1);

	  switch (test_state)
	    {
	      /*************************************************** TEST02 */
	    case TEST02_ST_WAIT_SIGN:
	      if (!uok || !keq)
		TEST_FAIL("bad user/key");
	      event.userauth_server.userkey.found = 1;
	      test_state_set(TEST02_ST_KEY_FOUND);
	      break;
	      /*************************************************** TEST03 */
	    case TEST03_ST_WAIT_SIGN:
	      if (!uok || !keq)
		TEST_FAIL("bad user/key");
	      event.userauth_server.userkey.found = 1;
	      test_state_set(TEST03_ST_KEY_FOUND);
	      break;
	      /*************************************************** TEST04 */
	    case TEST04_ST_WAIT_PKOK:
	      if (!uok || !keq)
		TEST_FAIL("bad user/key");
	      event.userauth_server.userkey.found = 1;
	      test_state_set(TEST04_ST_KEY_FOUND);
	      break;
	      /*************************************************** TEST05 */
	    case TEST05_ST_WAIT_PKOK:
	      if (!uok || !keq)
		TEST_FAIL("bad user/key");
	      event.userauth_server.userkey.found = 1;
	      test_state_set(TEST05_ST_KEY_FOUND);
	      break;
	      /*************************************************** TEST06 */
	    case TEST06_ST_WAIT_PKOK:
	      if (!uok || !keq)
		TEST_FAIL("bad user/key");
	      event.userauth_server.userkey.found = 1;
	      test_state_set(TEST06_ST_KEY_FOUND);
	      break;
	    case TEST06_ST_WAIT_SIGN:
	      if (uok || !keq)
		TEST_FAIL("bad user/key");
	      test_state_set(TEST06_ST_DONE);
	      goto done;
	      /*************************************************** TEST07 */
	    case TEST07_ST_WAIT_PKOK:
	      if (!uok || !keq)
		TEST_FAIL("bad user/key");
	      event.userauth_server.userkey.found = 1;
	      test_state_set(TEST07_ST_KEY_FOUND);
	      break;
	    case TEST07_ST_WAIT_SIGN:
	      if (!uok || keq)
		TEST_FAIL("bad user/key");
	      test_state_set(TEST07_ST_DONE);
	      goto done;
	      /*************************************************** TEST08 */
	    case TEST08_ST_NOT_FOUND:
	      event.userauth_server.userkey.found = 0;
	      test_state_set(TEST08_ST_WAIT_FAIL);
	      break;
	    case TEST08_ST_NOT_FOUND2:
	      event.userauth_server.userkey.found = 0;
	      test_state_set(TEST08_ST_WAIT_FAIL2);
	      break;

# if defined(CONFIG_ASSH_SERVER_AUTH_PASSWORD)
	      /*************************************************** TEST26 */
	    case TEST26_ST_WAIT_SIGN:
	      if (!uok || !keq)
		TEST_FAIL("bad user/key");
	      event.userauth_server.userkey.found = 1;
	      test_state_set(TEST26_ST_KEY_FOUND);
	      break;
	      /*************************************************** TEST27 */
	    case TEST27_ST_WAIT_SIGN:
	      if (!uok || !keq)
		TEST_FAIL("bad user/key");
	      event.userauth_server.userkey.found = 1;
	      test_state_set(TEST27_ST_KEY_FOUND);
	      break;
# endif
	    default:
	      TEST_FAIL("bad server state %u\n", test_state);
	    }
	  break;
	}
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_HOSTBASED)
	case ASSH_EVENT_USERAUTH_SERVER_HOSTBASED: {
	  stall = 0;
	  assh_bool_t uok = !assh_buffer_strcmp(
	      &event.userauth_server.hostbased.username, "allowed");
          assh_bool_t hok = !assh_buffer_strcmp(
	      &event.userauth_server.hostbased.hostname, "localhost");
          assh_bool_t huok = !assh_buffer_strcmp(
	      &event.userauth_server.hostbased.host_username, "hallowed");
	  assh_bool_t keq = assh_key_cmp(&context[0],
	    event.userauth_server.hostbased.host_key, key_c, 1);

	  switch (test_state)
	    {
	      /*************************************************** TEST23 */
	    case TEST23_ST_WAIT_SIGN:
	      if (!uok || !hok || !huok || !keq)
		TEST_FAIL("bad user/key");
	      event.userauth_server.hostbased.found = 1;
	      test_state_set(TEST23_ST_KEY_FOUND);
	      break;
	      /*************************************************** TEST24 */
	    case TEST24_ST_WAIT_SIGN:
	      if (!uok || !hok || !huok || !keq)
		TEST_FAIL("bad user/key");
	      event.userauth_server.hostbased.found = 1;
	      test_state_set(TEST24_ST_KEY_FOUND);
	      break;
	      /*************************************************** TEST25 */
	    case TEST25_ST_WAIT_SIGN:
	      if (!uok || !hok || !huok || !keq)
		TEST_FAIL("bad user/key");
	      event.userauth_server.hostbased.found = 0;
	      test_state_set(TEST25_ST_KEY_NOT_FOUND);
	      break;

	    default:
	      TEST_FAIL("bad server state %u\n", test_state);
	    }
	  break;
	}
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_PASSWORD)

	case ASSH_EVENT_USERAUTH_SERVER_PASSWORD: {
	  stall = 0;
	  assh_bool_t uok = !assh_buffer_strcmp(
	    &event.userauth_server.password.username, "allowed");
	  assh_bool_t pok = !assh_buffer_strcmp(
	    &event.userauth_server.password.password, "pass");
	  assh_bool_t nok = !assh_buffer_strcmp(
	    &event.userauth_server.password.new_password, "newpass");

	  switch (test_state)
	    {
	      /*************************************************** TEST09 */
	    case TEST09_ST_WRONG:
	      if (!uok || pok)
		TEST_FAIL("bad user/pass");
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_FAILURE;
	      test_state_set(TEST09_ST_WAIT_FAIL);
	      break;

	      /*************************************************** TEST10 */
	    case TEST10_ST_WRONG:
	      if (uok || !pok)
		TEST_FAIL("bad user/pass");
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_FAILURE;
	      test_state_set(TEST10_ST_WAIT_FAIL);
	      break;

	      /*************************************************** TEST11 */
	    case TEST11_ST_PASSWD_OK:
	      if (!uok || !pok)
		TEST_FAIL("bad user/pass");
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_SUCCESS;
	      test_state_set(TEST11_ST_WAIT_SUCCESS);
	      break;

	      /*************************************************** TEST12 */
	    case TEST12_ST_PASSWD_OK:
	      if (!uok || !pok)
		TEST_FAIL("bad user/pass");
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_CHANGE;
	      test_state_set(TEST12_ST_WAIT_CHANGE);
	      break;

	    case TEST12_ST_PASSWD_CHANGE:
	      if (!uok || !pok || !nok)
		TEST_FAIL("bad user/pass");
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_SUCCESS;
	      test_state_set(TEST12_ST_CHANGED);
	      break;

	      /*************************************************** TEST13 */
	    case TEST13_ST_PASSWD_OK:
	      if (!uok || !pok)
		TEST_FAIL("bad user/pass");
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_CHANGE;
	      test_state_set(TEST13_ST_WAIT_CHANGE);
	      break;

	    case TEST13_ST_PASSWD_CHANGE:
	      if (!uok || pok || !nok)
		TEST_FAIL("bad user/pass");
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_FAILURE;
	      test_state_set(TEST13_ST_WAIT_FAIL);
	      break;

	      /*************************************************** TEST14 */
	    case TEST14_ST_PASSWD_OK:
	      if (!uok || !pok)
		TEST_FAIL("bad user/pass");
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_CHANGE;
	      test_state_set(TEST14_ST_WAIT_CHANGE);
	      break;

	      /*************************************************** TEST15 */
	    case TEST15_ST_PASSWD_CHANGE:
	      if (!uok || !pok || !nok)
		TEST_FAIL("bad user/pass");
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_SUCCESS;
	      test_state_set(TEST15_ST_CHANGED);
	      break;

	      /*************************************************** TEST16 */
	    case TEST16_ST_PASSWD_CHANGE:
	      if (!uok || pok || !nok)
		TEST_FAIL("bad user/pass");
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_FAILURE;
	      test_state_set(TEST16_ST_WAIT_FAIL);
	      break;

	      /*************************************************** TEST17 */
	    case TEST17_ST_PASSWD_OK:
	      if (!uok || !pok)
		TEST_FAIL("bad user/pass");
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_CHANGE;
	      test_state_set(TEST17_ST_WAIT_CHANGE);
	      break;

	    case TEST17_ST_PASSWD_CHANGE:
	      if (uok || !pok || !nok)
		TEST_FAIL("bad user/pass");
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_FAILURE;
	      test_state_set(TEST17_ST_WAIT_FAIL);
	      break;

# if defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY)
	      /*************************************************** TEST26 */
	    case TEST26_ST_PASSWD_OK:
	      if (!uok || !pok)
		TEST_FAIL("bad user/pass");
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_SUCCESS;
	      test_state_set(TEST26_ST_WAIT_SUCCESS);
	      break;
	      /*************************************************** TEST27 */
	    case TEST27_ST_PASSWD_WRONG:
	      if (!uok || pok)
		TEST_FAIL("bad user/pass");
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_FAILURE;
	      test_state_set(TEST27_ST_WAIT_FAIL);
	      break;
# endif
	    default:
	      TEST_FAIL("bad server state %u\n", test_state);
	    }
	  break;
	}
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_KEYBOARD)
	case ASSH_EVENT_USERAUTH_SERVER_KBINFO:
	  assh_buffer_strset(&event.userauth_server.kbinfo.name,
			     "name");
	  assh_buffer_strset(&event.userauth_server.kbinfo.instruction,
			     "instruction");
          event.userauth_server.kbinfo.prompts = test_userauth_kbinfo_rq;

	  switch (test_state)
	    {
	      /*************************************************** TEST18 */
            case TEST18_ST_WAIT_INFO:
              if (assh_buffer_strcmp(&event.userauth_server.kbinfo.sub, "sub"))
                TEST_FAIL("");
              event.userauth_server.kbinfo.count = 4;
              test_state_set(TEST18_ST_SENT_INFO);
              break;

	      /*************************************************** TEST19 */
            case TEST19_ST_WAIT_INFO:
              if (assh_buffer_strcmp(&event.userauth_server.kbinfo.sub, "sub"))
                TEST_FAIL("");
              event.userauth_server.kbinfo.count = 4;
              test_state_set(TEST19_ST_SENT_INFO);
              break;

	      /*************************************************** TEST20 */
            case TEST20_ST_WAIT_INFO:
              if (assh_buffer_strcmp(&event.userauth_server.kbinfo.sub, "sub"))
                TEST_FAIL("");
              event.userauth_server.kbinfo.count = 0;
              test_state_set(TEST20_ST_SENT_INFO);
              break;
            case TEST20_ST_CONTINUE:
              event.userauth_server.kbinfo.count = 2;
              test_state_set(TEST20_ST_SENT_INFO2);
              break;

	      /*************************************************** TEST21 */
            case TEST21_ST_WAIT_INFO:
              if (assh_buffer_strcmp(&event.userauth_server.kbinfo.sub, "sub"))
                TEST_FAIL("");
              event.userauth_server.kbinfo.count = 0;
              test_state_set(TEST21_ST_SENT_INFO);
              break;
            case TEST21_ST_CONTINUE:
              event.userauth_server.kbinfo.count = 2;
              test_state_set(TEST21_ST_SENT_INFO2);
              break;

	      /*************************************************** TEST22 */
            case TEST22_ST_WAIT_INFO:
              if (assh_buffer_strcmp(&event.userauth_server.kbinfo.sub, "sub"))
                TEST_FAIL("");
              event.userauth_server.kbinfo.count = 2;
              test_state_set(TEST22_ST_SENT_INFO);
              break;

            default:
              TEST_FAIL("");
            }
          break;

	case ASSH_EVENT_USERAUTH_SERVER_KBRESPONSE: {
	  stall = 0;
          uint_fast8_t count;
	  switch (test_state)
	    {
	      /*************************************************** TEST18 */
            case TEST18_ST_WAIT_RESPONSE:
              event.userauth_server.kbresponse.result = ASSH_SERVER_KBSTATUS_SUCCESS;
              count = 4;
              test_state_set(TEST18_ST_SEND_RESPONSE);
              goto kb_check;

	      /*************************************************** TEST19 */
            case TEST19_ST_WAIT_RESPONSE:
              event.userauth_server.kbresponse.result = ASSH_SERVER_KBSTATUS_FAILURE;
              count = 4;
              test_state_set(TEST19_ST_SEND_RESPONSE);
              goto kb_check;

	      /*************************************************** TEST20 */
            case TEST20_ST_WAIT_RESPONSE:
              event.userauth_server.kbresponse.result = ASSH_SERVER_KBSTATUS_CONTINUE;
              test_state_set(TEST20_ST_CONTINUE);
              count = 0;
              goto kb_check;

            case TEST20_ST_WAIT_RESPONSE2:
              event.userauth_server.kbresponse.result = ASSH_SERVER_KBSTATUS_SUCCESS;
              test_state_set(TEST20_ST_SEND_RESPONSE2);
              count = 2;
              goto kb_check;

	      /*************************************************** TEST21 */
            case TEST21_ST_WAIT_RESPONSE:
              event.userauth_server.kbresponse.result = ASSH_SERVER_KBSTATUS_CONTINUE;
              test_state_set(TEST21_ST_CONTINUE);
              count = 0;
              goto kb_check;

            case TEST21_ST_WAIT_RESPONSE2:
              event.userauth_server.kbresponse.result = ASSH_SERVER_KBSTATUS_FAILURE;
              test_state_set(TEST21_ST_SEND_RESPONSE2);
              count = 2;
              goto kb_check;

            kb_check:;
              if (event.userauth_server.kbresponse.count != count)
                TEST_FAIL("kb: bad responses count");
              uint_fast8_t i;
              for (i = 0; i < count; i++)
                if (assh_buffer_strcmp(&event.userauth_server.kbresponse.responses[i],
                                       test_userauth_kbinfo_resp[i].str))
                  TEST_FAIL("");

              break;

            default:
              TEST_FAIL("");
            }
          break;
        }
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_NONE)
	case ASSH_EVENT_USERAUTH_SERVER_NONE:
	  switch (test_state)
	    {
	    case TEST01_ST_WAIT_NONE:
              event.userauth_server.none.accept = 1;
	      test_state_set(TEST01_ST_WAIT_SUCCESS);
	      break;
	    case TEST29_ST_WAIT_NONE:
              event.userauth_server.none.accept = 0;
	      test_state_set(TEST29_ST_WAIT_FAIL);
	      break;
            default:
              TEST_FAIL("");
            }
          break;
#endif

	case ASSH_EVENT_USERAUTH_SERVER_SUCCESS:
	  stall = 0;
	  switch (test_state)
	    {
#if defined(CONFIG_ASSH_SERVER_AUTH_NONE)
	      /*************************************************** TEST01 */
	    case TEST01_ST_WAIT_SUCCESS:
	      test_state_set(TEST01_ST_SERVER_SUCCESS);
	      break;
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY)
	      /*************************************************** TEST02 */
	    case TEST02_ST_KEY_FOUND_COK:
	      test_state_set(TEST02_ST_SERVER_SUCCESS);
	      break;
	      /*************************************************** TEST03 */
	    case TEST03_ST_KEY_FOUND:
	      TEST_FAIL("server accepted bad signature\n");
	      /*************************************************** TEST04 */
	    case TEST04_ST_WAIT_SIGN:
	      test_state_set(TEST04_ST_SERVER_SUCCESS);
	      break;
	      /*************************************************** TEST05 */
	    case TEST05_ST_WAIT_SIGN:
	      TEST_FAIL("server accepted bad signature\n");
	      /*************************************************** TEST06 */
	    case TEST06_ST_WAIT_SIGN:
	      TEST_FAIL("server accepted wrong user\n");
	      /*************************************************** TEST07 */
	    case TEST07_ST_WAIT_SIGN:
	      TEST_FAIL("server accepted wrong user\n");
	      /*************************************************** TEST08 */
	    case TEST08_ST_WAIT_FAIL:
	    case TEST08_ST_WAIT_FAIL2:
	      TEST_FAIL("server accepted wrong key\n");
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_PASSWORD)
	      /*************************************************** TEST11 */
	    case TEST11_ST_WAIT_SUCCESS:
	      test_state_set(TEST11_ST_SERVER_SUCCESS);
	      break;
	      /*************************************************** TEST12 */
	    case TEST12_ST_CHANGED:
	      test_state_set(TEST12_ST_SERVER_SUCCESS);
	      break;
	      /*************************************************** TEST15 */
	    case TEST15_ST_CHANGED:
	      test_state_set(TEST15_ST_SERVER_SUCCESS);
	      break;
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_KEYBOARD)
	      /*************************************************** TEST18 */
            case TEST18_ST_SEND_RESPONSE:
	      if (!event.userauth_server.methods.failed)
		TEST_FAIL("");
	      test_state_set(TEST18_ST_SERVER_SUCCESS);
	      break;
	      /*************************************************** TEST20 */
            case TEST20_ST_SEND_RESPONSE2:
	      if (!event.userauth_server.methods.failed)
		TEST_FAIL("");
	      test_state_set(TEST20_ST_SERVER_SUCCESS);
	      break;
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_HOSTBASED)
	      /*************************************************** TEST23 */
	    case TEST23_ST_KEY_FOUND_COK:
	      test_state_set(TEST23_ST_SERVER_SUCCESS);
	      break;
	      /*************************************************** TEST24 */
	    case TEST24_ST_KEY_FOUND:
	      TEST_FAIL("server accepted bad signature\n");
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY) && \
  defined(CONFIG_ASSH_SERVER_AUTH_PASSWORD)
	      /*************************************************** TEST26 */
	    case TEST26_ST_PARTIAL_SUCCESS:
	      test_state_set(TEST26_ST_SEND_PASSWD);
              event.userauth_server.success.methods =
                ASSH_USERAUTH_METHOD_PASSWORD;
              break;
	    case TEST26_ST_WAIT_SUCCESS:
	      test_state_set(TEST26_ST_SERVER_SUCCESS);
	      break;
	      /*************************************************** TEST27 */
	    case TEST27_ST_PARTIAL_SUCCESS:
	      test_state_set(TEST27_ST_SEND_PASSWD);
              event.userauth_server.success.methods =
                ASSH_USERAUTH_METHOD_PASSWORD;
              break;
#endif
	    default:
	      TEST_FAIL("bad server state %u\n", test_state);
	    }
	  break;

	case ASSH_EVENT_SERVICE_START:
	  stall = 0;
	  break;

	default:
	  ASSH_DEBUG("server: don't know how to handle event %u\n", event.id);
	  break;
	}

      assh_event_done(&session[0], &event, ASSH_OK);

      /****************************************************/
      ASSH_DEBUG("=== client %u ===\n", stall);
      if (!assh_event_get(&session[1], &event, 0))
        TEST_FAIL("session terminated");

      switch (event.id)
	{
	case ASSH_EVENT_READ:
	  if (fifo_rw_event(fifo, &event, 1))
	    stall++;
	  break;

	case ASSH_EVENT_WRITE:
	  if (!fifo_rw_event(fifo, &event, 1))
	    stall = 0;
	  break;

        case ASSH_EVENT_SESSION_ERROR:
          TEST_FAIL("client error event\n");

	default:
	  ASSH_DEBUG("client: don't know how to handle event %u\n", event.id);
	  break;
	}

      assh_event_done(&session[1], &event, ASSH_OK);

      if (stall >= 100)
	TEST_FAIL("stalled");

      switch (test_state)
	{
	case TEST00_ST_FAILED:
	  test_state_set(TEST00_ST_DONE);
	  goto done;
#if defined(CONFIG_ASSH_SERVER_AUTH_NONE)
	case TEST01_ST_SUCCESS:
	  test_state_set(TEST01_ST_DONE);
	  goto done;
	case TEST29_ST_FAILED:
	  test_state_set(TEST29_ST_DONE);
	  goto done;
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY)
	case TEST02_ST_SUCCESS:
	  test_state_set(TEST02_ST_DONE);
	  goto done;
	case TEST08_ST_FAILED:
	  test_state_set(TEST08_ST_DONE);
	  goto done;
	case TEST04_ST_SUCCESS:
	  test_state_set(TEST04_ST_DONE);
	  goto done;
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_PASSWORD)
	case TEST09_ST_FAILED:
	  test_state_set(TEST09_ST_DONE);
	  goto done;
	case TEST10_ST_FAILED:
	  test_state_set(TEST10_ST_DONE);
	  goto done;
	case TEST11_ST_SUCCESS:
	  test_state_set(TEST11_ST_DONE);
	  goto done;
	case TEST12_ST_SUCCESS:
	  test_state_set(TEST12_ST_DONE);
	  goto done;
	case TEST13_ST_FAILED:
	  test_state_set(TEST13_ST_DONE);
	  goto done;
	case TEST14_ST_FAILED:
	  test_state_set(TEST14_ST_DONE);
	  goto done;
	case TEST15_ST_SUCCESS:
	  test_state_set(TEST15_ST_DONE);
	  goto done;
	case TEST16_ST_FAILED:
	  test_state_set(TEST16_ST_DONE);
	  goto done;
	case TEST17_ST_FAILED:
	  test_state_set(TEST17_ST_DONE);
	  goto done;
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_KEYBOARD)
	case TEST18_ST_SUCCESS:
	  test_state_set(TEST18_ST_DONE);
	  goto done;
	case TEST19_ST_FAILED:
	  test_state_set(TEST19_ST_DONE);
	  goto done;
	case TEST20_ST_SUCCESS:
	  test_state_set(TEST20_ST_DONE);
	  goto done;
	case TEST21_ST_FAILED:
	  test_state_set(TEST21_ST_DONE);
	  goto done;
	case TEST22_ST_FAILED:
	  test_state_set(TEST22_ST_DONE);
	  goto done;
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_HOSTBASED)
	case TEST23_ST_SUCCESS:
	  test_state_set(TEST23_ST_DONE);
	  goto done;
	case TEST25_ST_FAILED:
	  test_state_set(TEST25_ST_DONE);
	  goto done;
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY) &&       \
  defined(CONFIG_ASSH_SERVER_AUTH_PASSWORD)
	case TEST26_ST_SUCCESS:
	  test_state_set(TEST26_ST_DONE);
	  goto done;
	case TEST27_ST_FAILED:
	  test_state_set(TEST27_ST_DONE);
	  goto done;
#endif
	case TEST28_ST_FAILED:
	  test_state_set(TEST28_ST_DONE);
	  goto done;
	default:
	  break;
	}
    }

 done:

  ASSH_DEBUG("=== done ===\n");

  if (alloc_size == alloc_size_init)
    TEST_FAIL("leak checking not working\n");

  for (i = 0; i < 2; i++)
    assh_session_cleanup(&session[i]);

  assh_packet_collect(&context[0]);
  assh_packet_collect(&context[1]);

  if (alloc_size != alloc_size_init)
    TEST_FAIL("memory leak detected, %zu bytes allocated\n", alloc_size);
}

/************************************************************** main */

int main()
{
  if (assh_deps_init())
    return -1;

  static const struct assh_algo_s *algos[] = {
    &assh_kex_none.algo, &assh_sign_none.algo, &assh_sign_ed25519.algo,
    &assh_cipher_none.algo, &assh_hmac_none.algo, &assh_compress_none.algo,
    NULL
  };

  /* init server context */
  if (assh_context_init(&context[0], ASSH_SERVER,
			assh_leaks_allocator, NULL, &assh_prng_weak, NULL) ||
      assh_service_register_va(&context[0], &assh_service_userauth_server,
			       &assh_service_connection, NULL) ||
      assh_algo_register_static(&context[0], algos))
    TEST_FAIL("");

  /* create host key */
  if (assh_key_create(&context[0], &context[0].keys, 0, &assh_key_none,
		      ASSH_ALGO_SIGN) != ASSH_OK)
    TEST_FAIL("");

  /* init client context */
  if (assh_context_init(&context[1], ASSH_CLIENT,
			assh_leaks_allocator, NULL, &assh_prng_weak, NULL) ||
      assh_service_register_va(&context[1], &test_service_userauth_client,
			       &assh_service_connection, NULL) ||
      assh_algo_register_static(&context[1], algos))
    TEST_FAIL("");

  /* create some user authentication key */
  key_s = key_c = key_cbad = NULL;

  if (assh_key_create(&context[1], &key_cbad, 255,
		      key_algo, ASSH_ALGO_SIGN))
    TEST_FAIL("");

  if (assh_key_create(&context[1], &key_c, 255,
		      key_algo, ASSH_ALGO_SIGN))
    TEST_FAIL("");

  uint8_t *key_blob;
  size_t key_blob_len;

  if (assh_key_output(&context[1], key_c, NULL, &key_blob_len,
		      ASSH_KEY_FMT_PUB_RFC4253))
    TEST_FAIL("");

  key_blob = malloc(key_blob_len);
  if (key_blob == NULL)
    TEST_FAIL("");

  if (assh_key_output(&context[1], key_c, key_blob, &key_blob_len,
		      ASSH_KEY_FMT_PUB_RFC4253))
    TEST_FAIL("");

  const uint8_t *b = key_blob;
  if (assh_key_load(&context[0], &key_s, key_algo, ASSH_ALGO_SIGN,
		    ASSH_KEY_FMT_PUB_RFC4253, &b, key_blob_len))
    TEST_FAIL("");

  /*************************************************** TEST00 */
  test_state_set(TEST00_ST_INIT);
  test();
  if (test_state != TEST00_ST_DONE)
    TEST_FAIL("");

#if defined(CONFIG_ASSH_SERVER_AUTH_NONE)
  /*************************************************** TEST01 */
  test_state_set(TEST01_ST_INIT);
  test();
  if (test_state != TEST01_ST_DONE)
    TEST_FAIL("");
  /*************************************************** TEST29 */
  test_state_set(TEST29_ST_INIT);
  test();
  if (test_state != TEST29_ST_DONE)
    TEST_FAIL("");
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY)
  /*************************************************** TEST02 */
  test_state_set(TEST02_ST_INIT);
  test();
  if (test_state != TEST02_ST_DONE)
    TEST_FAIL("");

  /*************************************************** TEST03 */
  test_state_set(TEST03_ST_INIT);
  test();
  if (test_state != TEST03_ST_SERVER_REJECT)
    TEST_FAIL("");

  /*************************************************** TEST04 */
  test_state_set(TEST04_ST_INIT);
  test();
  if (test_state != TEST04_ST_DONE)
    TEST_FAIL("");

  /*************************************************** TEST05 */
  test_state_set(TEST05_ST_INIT);
  test();
  if (test_state != TEST05_ST_SERVER_REJECT)
    TEST_FAIL("");

  /*************************************************** TEST06 */
  test_state_set(TEST06_ST_INIT);
  test();
  if (test_state != TEST06_ST_DONE)
    TEST_FAIL("");

  /*************************************************** TEST07 */
  test_state_set(TEST07_ST_INIT);
  test();
  if (test_state != TEST07_ST_DONE)
    TEST_FAIL("");

  /*************************************************** TEST08 */
  test_state_set(TEST08_ST_INIT);
  test();
  if (test_state != TEST08_ST_DONE)
    TEST_FAIL("");
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_PASSWORD)
  /*************************************************** TEST09 */
  test_state_set(TEST09_ST_INIT);
  test();
  if (test_state != TEST09_ST_DONE)
    TEST_FAIL("");

  /*************************************************** TEST10 */
  test_state_set(TEST10_ST_INIT);
  test();
  if (test_state != TEST10_ST_DONE)
    TEST_FAIL("");

  /*************************************************** TEST11 */
  test_state_set(TEST11_ST_INIT);
  test();
  if (test_state != TEST11_ST_DONE)
    TEST_FAIL("");

  /*************************************************** TEST12 */
  test_state_set(TEST12_ST_INIT);
  test();
  if (test_state != TEST12_ST_DONE)
    TEST_FAIL("");

  /*************************************************** TEST13 */
  test_state_set(TEST13_ST_INIT);
  test();
  if (test_state != TEST13_ST_DONE)
    TEST_FAIL("");

  /*************************************************** TEST14 */
  test_state_set(TEST14_ST_INIT);
  test();
  if (test_state != TEST14_ST_DONE)
    TEST_FAIL("");

  /*************************************************** TEST15 */
  test_state_set(TEST15_ST_INIT);
  test();
  if (test_state != TEST15_ST_DONE)
    TEST_FAIL("");

  /*************************************************** TEST16 */
  test_state_set(TEST16_ST_INIT);
  test();
  if (test_state != TEST16_ST_DONE)
    TEST_FAIL("");

  /*************************************************** TEST17 */
  test_state_set(TEST17_ST_INIT);
  test();
  if (test_state != TEST17_ST_DONE)
    TEST_FAIL("");
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_KEYBOARD)
  /*************************************************** TEST18 */
  test_state_set(TEST18_ST_INIT);
  test();
  if (test_state != TEST18_ST_DONE)
    TEST_FAIL("");

  /*************************************************** TEST19 */
  test_state_set(TEST19_ST_INIT);
  test();
  if (test_state != TEST19_ST_DONE)
    TEST_FAIL("");

  /*************************************************** TEST20 */
  test_state_set(TEST20_ST_INIT);
  test();
  if (test_state != TEST20_ST_DONE)
    TEST_FAIL("");

  /*************************************************** TEST21 */
  test_state_set(TEST21_ST_INIT);
  test();
  if (test_state != TEST21_ST_DONE)
    TEST_FAIL("");

  /*************************************************** TEST22 */
  test_state_set(TEST22_ST_INIT);
  test();
  if (test_state != TEST22_ST_DONE)
    TEST_FAIL("");
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_HOSTBASED)
  /*************************************************** TEST23 */
  test_state_set(TEST23_ST_INIT);
  test();
  if (test_state != TEST23_ST_DONE)
    TEST_FAIL("");

  /*************************************************** TEST24 */
  test_state_set(TEST24_ST_INIT);
  test();
  if (test_state != TEST24_ST_SERVER_REJECT)
    TEST_FAIL("");

  /*************************************************** TEST25 */
  test_state_set(TEST25_ST_INIT);
  test();
  if (test_state != TEST25_ST_DONE)
    TEST_FAIL("");
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY) && \
  defined(CONFIG_ASSH_SERVER_AUTH_PASSWORD)
  /*************************************************** TEST26 */
  test_state_set(TEST26_ST_INIT);
  test();
  if (test_state != TEST26_ST_DONE)
    TEST_FAIL("");

  /*************************************************** TEST27 */
  test_state_set(TEST27_ST_INIT);
  test();
  if (test_state != TEST27_ST_DONE)
    TEST_FAIL("");
#endif

  /*************************************************** TEST28 */
  test_state_set(TEST28_ST_INIT);
  test();
  if (test_state != TEST28_ST_DONE)
    TEST_FAIL("");


  fprintf(stderr, "Done.\n");

  return 0;
}

