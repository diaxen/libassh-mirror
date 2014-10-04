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
   @short Key exchange API

   This headed file defines the interface to use for pluggable
   key exchange algorithm implementations.

   The key exchange process involve several functions calls performed
   in the following order:
   @list
     @item The @ref assh_kex_send_init and @ref assh_kex_got_init
       function are called by the transport layer code.
     @item The @ref assh_kex_init_t function of the pluggable algorithm
       module is called from @ref assh_kex_got_init.
     @item The @ref assh_kex_process_t function of the module is called
       multiple times for every incoming key-exchange packet and may
       return events.
     @item The @ref assh_kex_new_keys function must be called once from
       the module code when the shared secret is available.
     @item The @ref assh_kex_end function must be called once from the
       module code when the key exchange is over.
     @item The @ref assh_kex_cleanup_t function of the module is called.
   @end list

   The server host key must be verified during the key exchange by
   using the pluggable signature algorithm pointed to by @ref
   assh_session_s::host_sign_algo.
*/

#ifndef ASSH_KEX_H_
#define ASSH_KEX_H_

#ifdef ASSH_EVENT_H_
# warning The assh/assh_event.h header should be included after assh_kex.h
#endif

#include "assh_algo.h"

/**
   This function set the amount of ssh stream that can flow between
   the client and server between requesting a new key exchange.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_kex_set_threshold(struct assh_session_s *s, uint32_t bytes);

/**
   @internal This function is called internally by the transport layer
   when a key-exchange must be performed.

   This function send the kex exchange init packet.  A copy of the
   packet is kept in @ref assh_session_s::kex_init_local for hashing
   by the kex-exchange algorithm.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_kex_send_init(struct assh_session_s *s);

/**
   @internal This function is called internally by the transport layer
   when a key exchange init packet is received from the remote host. A
   copy of the packet is kept in @ref assh_session_s::kex_init_remote
   for hashing by the kex-exchange algorithm.

   This function selects the various algorithms from the client and
   server advertised lists and then initialize the pluggable key
   exchange module by calling its @ref assh_kex_init_t function.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_kex_got_init(struct assh_session_s *s, struct assh_packet_s *p);

#ifdef CONFIG_ASSH_CLIENT

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_kex_client_hash1(struct assh_session_s *s,
                      struct assh_hash_ctx_s *hash_ctx,
                      const uint8_t *k_str);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_kex_client_hash2(struct assh_session_s *s, struct assh_hash_ctx_s *hash_ctx,
                      struct assh_key_s *host_key, const uint8_t *secret_str,
                      const uint8_t *h_str);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_kex_client_get_key(struct assh_session_s *s, struct assh_key_s **key,
                        const uint8_t *ks_str, struct assh_event_s *e,
                        assh_error_t (*done)(struct assh_session_s *s,
                                             struct assh_event_s *e), void *pv);
#endif

#ifdef CONFIG_ASSH_SERVER

/** This helper function allocate a @ref SSH_MSG_KEXDH_REPLY key
    exchange packet, add public host key fields and update the hash
    context with various values including the host key.

    More fields may be added to the packet and hashed before calling
    the @ref assh_kex_server_hash2 function.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_kex_server_hash1(struct assh_session_s *s, size_t kex_len,
                      struct assh_hash_ctx_s *hash_ctx,
                      struct assh_packet_s **pout, size_t *sign_len,
                      const struct assh_key_s **host_key,
                      enum assh_ssh_msg_e msg);

/** This helper function hash the secret key then add the signature to
    the @ref SSH_MSG_KEXDH_REPLY packet and finally call @ref
    assh_kex_new_keys. 

    @see assh_kex_server_hash1
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_kex_server_hash2(struct assh_session_s *s,
                      struct assh_hash_ctx_s *hash_ctx,
                      struct assh_packet_s *pout, size_t sign_len,
                      const struct assh_key_s *host_key,
                      const uint8_t *secret_str);

#endif

/**
   @internal This function is called by the pluggable key exchange
   module when the exchange hash and the shared secret are
   available. It will use the provided hash algorithm to derive the
   various symmetric cipher keys from these values and initialize the
   associated algorithms.

   Two new @ref assh_kex_keys_s objects are ready for use and will
   replace the old keys when the next @ref SSH_MSG_NEWKEYS packets
   are sent and received.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_kex_new_keys(struct assh_session_s *s,
                  const struct assh_hash_algo_s *hash_algo,
                  const uint8_t *ex_hash,
                  const uint8_t *secret_str);

/**
   @internal This function is called by the pluggable key exchange
   module when the exchange hash is over. It will call the @ref
   assh_kex_cleanup_t function of the module and release init packets.

   If the @tt accept parameter is not zero, a @ref SSH_MSG_NEWKEYS
   packet is sent. If the @tt accept parameter is zero, the key
   exchange fails.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_kex_end(struct assh_session_s *s, assh_bool_t accept);

/**
   @internal This function is called internally when a @ref
   assh_kex_keys_s object and its associated resources have to be
   released.
*/
void assh_kex_keys_cleanup(struct assh_session_s *s,
                           struct assh_kex_keys_s *keys);

/** @internal @see assh_kex_init_t */
#define ASSH_KEX_INIT_FCN(n) assh_error_t (n)(struct assh_session_s *s, \
                                              size_t cipher_key_size)
/** @internal This function is called when the key exchange is
    initiated. It may allocate a private context and store it in the
    @ref assh_session_s::kex_pv field. */
typedef ASSH_KEX_INIT_FCN(assh_kex_init_t);

/** @internal @see assh_kex_cleanup_t */
#define ASSH_KEX_CLEANUP_FCN(n) void (n)(struct assh_session_s *s)
/** @internal This function is called when the key exchange is over if
    the @ref assh_session_s::kex_pv field is not @tt NULL. It must
    release the key exchange private context and set this field back
    to @tt NULL. */
typedef ASSH_KEX_CLEANUP_FCN(assh_kex_cleanup_t);

#define ASSH_KEX_PROCESS_FCN(n) assh_error_t (n)(struct assh_session_s *s, \
                                                 struct assh_packet_s *p, \
                                                 struct assh_event_s *e)
/** @internal This function is called when the current state of the
    transport layer is @ref #ASSH_TR_KEX_RUNNING and an incoming key
    exchange packet is available.

    The function may initialize the passed event object, in this case
    the event will be propagated to the caller of the @ref
    assh_event_get function.
*/
typedef ASSH_KEX_PROCESS_FCN(assh_kex_process_t);

/** @internal This object contains the various symmetric cipher
    algorithm contexts initialized from the shared secret. This is
    used by the transport layer code to process the ssh packet stream. */
struct assh_kex_keys_s
{
  const struct assh_algo_cipher_s *cipher;
  void *cipher_ctx;
  const struct assh_algo_mac_s *mac;
  void *mac_ctx;
  const struct assh_algo_compress_s *cmp;
  void *cmp_ctx;
  uint8_t iv[ASSH_MAX_BLOCK_SIZE];
};

/**
   The @ref ASSH_EVENT_KEX_HOSTKEY_LOOKUP event is returned when a
   client needs to lookup a server host key in the local database. The
   @ref accept field must be updated accordingly before calling the
   @ref assh_event_done function.
*/
struct assh_event_kex_hostkey_lookup_s
{
  struct assh_key_s * ASSH_EV_CONST key;  //< input
  assh_bool_t               accept;             //< output
};

/** @internal */
union assh_event_kex_u
{
  struct assh_event_kex_hostkey_lookup_s hostkey_lookup;
};

/** @internal This defines the interface of a pluggable key exchange
    algorithm. */
struct assh_algo_kex_s
{
  struct assh_algo_s algo;
  assh_kex_init_t *f_init;
  assh_kex_cleanup_t *f_cleanup;
  assh_kex_process_t *f_process;
};

extern const struct assh_algo_kex_s assh_kex_none;

extern const struct assh_algo_kex_s assh_kex_dh_group1_sha1;
extern const struct assh_algo_kex_s assh_kex_dh_group14_sha1;
extern const struct assh_algo_kex_s assh_kex_curve25519_sha256;
extern const struct assh_algo_kex_s assh_kex_m383_sha384;
extern const struct assh_algo_kex_s assh_kex_m511_sha512;

/** diffie-hellman-group-exchange-sha1, favors group size of n*n/12
    bits and allows groups size of n*n/16 bits where n is the size of
    the symmetric cipher key. */
extern const struct assh_algo_kex_s assh_kex_dh_gex_sha1;

/** diffie-hellman-group-exchange-sha256, favors group size of n*n/12
    bits and allows groups size of n*n/16 bits where n is the size of
    the symmetric cipher key. */
extern const struct assh_algo_kex_s assh_kex_dh_gex_sha256_12;

/** diffie-hellman-group-exchange-sha256, favors group size of n*n/8
    bits and allows groups size of n*n/12 bits where n is the size of
    the symmetric cipher key. */
extern const struct assh_algo_kex_s assh_kex_dh_gex_sha256_8;

/** diffie-hellman-group-exchange-sha256, favors group size of n*n/4
    bits and allows groups size of n*n/8 bits where n is the size of
    the symmetric cipher key. */
extern const struct assh_algo_kex_s assh_kex_dh_gex_sha256_4;

/** RSA based key exchange as defined in rfc4432, 1024 bits key, sha1 hash */
extern const struct assh_algo_kex_s assh_kex_rsa1024_sha1;

/** RSA based key exchange as defined in rfc4432, 2048 bits key, sha256 hash */
extern const struct assh_algo_kex_s assh_kex_rsa2048_sha256;

#endif

