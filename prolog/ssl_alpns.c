/* Building on macOS: */
/* gcc -I/Applications/SWI-Prolog.app/Contents/swipl/include/ -I/usr/local/Cellar/openssl/1.0.2n/include  -fpic -c ssl_alpns.c */
/* gcc -undefined dynamic_lookup -shared -o ssl_alpns.dylib ssl_alpns.o */

/*  Include file depends on local installation */
#include <SWI-Prolog.h>
#include <SWI-Stream.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/dh.h>

/* BEGIN COPIED FROM ssl4pl.c */
#define SSL_CONFIG_MAGIC 0x539dbe3a
#define SSL_MAX_CERT_KEY_PAIRS 12
typedef int BOOL;
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

typedef enum
{ PL_SSL_NONE
, PL_SSL_SERVER
, PL_SSL_CLIENT
} PL_SSL_ROLE;

typedef enum
{ SSL_PL_OK
, SSL_PL_RETRY
, SSL_PL_ERROR
} SSL_PL_STATUS;

typedef struct pl_cert_key_pair {
    X509                *certificate_X509;
    char                *key;
    char                *certificate;
} PL_CERT_KEY_PAIR;

typedef struct pl_ssl_callback {
    record_t goal;
    module_t module;
} PL_SSL_CALLBACK;

typedef struct pl_ssl_protocol {
    BOOL is_set;
    int version;
} PL_SSL_PROTOCOL;

typedef struct pl_ssl {
    long                 magic;
    /*
     * Are we server or client
     */
    PL_SSL_ROLE          role;

    int                  close_parent;
    atom_t               atom;
    BOOL                 close_notify;

    /*
     * Context, Certificate, SSL info
     */
    SSL_CTX             *ctx;
    int                  idx;
    X509                *peer_cert;

    /*
     * In case of the client the host we're connecting to.
     */
    char                *host;

    /*
     * Various parameters affecting the SSL layer
     */
    int                  use_system_cacert;
    char                *cacert;

    char                *certificate_file;
    char                *key_file;
    PL_CERT_KEY_PAIR     cert_key_pairs[SSL_MAX_CERT_KEY_PAIRS];
    int                  num_cert_key_pairs;

    char                *cipher_list;
    char                *ecdh_curve;
    STACK_OF(X509_CRL)  *crl_list;
    char                *password;
    BOOL                 crl_required;
    BOOL                 peer_cert_required;

    PL_SSL_PROTOCOL      min_protocol;
    PL_SSL_PROTOCOL      max_protocol;

    /*
     * Application defined handlers
     */
    PL_SSL_CALLBACK      cb_cert_verify;
    PL_SSL_CALLBACK      cb_pem_passwd;
    PL_SSL_CALLBACK      cb_sni;
#ifndef HAVE_X509_CHECK_HOST
    int                  hostname_check_status;
#endif
} PL_SSL;

typedef struct ssl_instance {
    PL_SSL              *config;
    SSL                 *ssl;
    IOSTREAM            *sread;         /* wire streams */
    IOSTREAM            *swrite;
    IOSTREAM            *dread;         /* data streams */
    IOSTREAM            *dwrite;
    int                  close_needed;
    BOOL                 fatal_alert;
} PL_SSL_INSTANCE;

static int
get_conf(term_t config, PL_SSL **conf)
{ PL_blob_t *type;
  void *data;

  if ( PL_get_blob(config, &data, NULL, &type) /*&& type == &ssl_context_type */)
  { PL_SSL **sslp = data;
    PL_SSL  *ssl  = *sslp;

    assert(ssl->magic == SSL_CONFIG_MAGIC);
    *conf = ssl;

    return TRUE;
  }

  return PL_type_error("ssl_context", config);
}
/* END COPIED FROM ssl4pl.c */

static int
set_alpn_protos(PL_SSL *conf, module_t module, term_t protos)
{
  term_t tail = PL_copy_term_ref(protos);
  term_t head = PL_new_term_ref();

  size_t current_size = 0;
  unsigned char *protos_vec = NULL;
  size_t total_length = 0;
  while( PL_get_list_ex(tail, head, tail) )
  { char *proto;
    if ( !PL_get_atom_chars(head, &proto) ) {
      return PL_warning("ssl_set_alpns_protos/2: Not an atom");
    }
    size_t proto_len = strlen(proto);
    total_length += proto_len + 1;
    if ( total_length > current_size ) {
      protos_vec = realloc(protos_vec, total_length);
      if ( protos_vec == NULL ) {
        return FALSE;
      }
    }
    protos_vec[current_size] = proto_len;
    memcpy(protos_vec + current_size + 1, proto, proto_len);
    current_size = total_length;
  }
  return SSL_CTX_set_alpn_protos(conf->ctx, protos_vec, total_length) == 0;
}

static foreign_t
pl_ssl_set_alpns_protos(term_t config, term_t protos)
{ PL_SSL *conf;
  module_t module = NULL;

  if ( !get_conf(config, &conf) ) {
    return FALSE;
  }

  if ( !PL_strip_module(protos, &module, protos) ) {
    return FALSE;
  }

  return set_alpn_protos(conf, module, protos);
}

install_t
install_ssl_alpns()
{ PL_register_foreign("ssl_set_alpns_protos", 2, pl_ssl_set_alpns_protos, 0);
}
