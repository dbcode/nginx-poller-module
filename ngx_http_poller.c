#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_config.h>
#include "ngx_http_poller.h"

typedef struct {
  ngx_http_poller_t          *poller;
  ngx_conf_t                  cf;
} ngx_http_poller_conf_ctx_t;

static void *ngx_http_poller_create_conf(ngx_conf_t *cf);
static char *ngx_http_poller_block(ngx_conf_t *cf, ngx_command_t *cmd,
				   void *conf);
static char *ngx_http_poller(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);
static ngx_int_t ngx_http_poller_init_process(ngx_cycle_t *cycle);
static void ngx_http_poller_event(ngx_event_t *ev);

static ngx_command_t ngx_http_poller_commands[] = {

  { ngx_string("poller"),
    NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
    ngx_http_poller_block,
    NGX_HTTP_MAIN_CONF_OFFSET,
    0,
    NULL },

  ngx_null_command
};

static ngx_http_module_t ngx_http_poller_module_ctx = {
  NULL,                         /* preconfiguration */
  NULL,                         /* postconfiguration */
  ngx_http_poller_create_conf,  /* create main configuration */
  NULL,                         /* init main configuration */
  NULL,                         /* create server configuration */
  NULL,                         /* merge server configuration */
  NULL,                         /* create location configuration */
  NULL                          /* merge location configuration */
};

ngx_module_t ngx_http_poller_module = {
  NGX_MODULE_V1,
  &ngx_http_poller_module_ctx,  /* module context */
  ngx_http_poller_commands,     /* module directives */
  NGX_HTTP_MODULE,              /* module type */
  NULL,                         /* init master */
  NULL,                         /* init module */
  ngx_http_poller_init_process, /* init process */
  NULL,                         /* init thread */
  NULL,                         /* exit thread */
  NULL,                         /* exit process */
  NULL,                         /* exit master */
  NGX_MODULE_V1_PADDING
};

static void *
ngx_http_poller_create_conf(ngx_conf_t *cf)
{
  ngx_http_poller_conf_t  *pcf;

  pcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_poller_conf_t));
  if (pcf == NULL) {
    return NULL;
  }

  if (ngx_array_init(&pcf->pollers, cf->pool, 1, sizeof(ngx_http_poller_t))
      != NGX_OK) {
    return NULL;
  }

  return pcf;
}

#if NGX_HTTP_SSL

/* lifted almost verbatim from ngx_http_proxy_module.c */

static ngx_int_t
ngx_http_poller_set_ssl(ngx_conf_t *cf, ngx_http_poller_t *poller)
{
  ngx_pool_cleanup_t *cln;
  ngx_uint_t          protocols;

  poller->upstream.ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
  if (poller->upstream.ssl == NULL) {
    return NGX_ERROR;
  }

  poller->upstream.ssl->log = cf->log;
  protocols = NGX_SSL_SSLv2 
    | NGX_SSL_SSLv3
    | NGX_SSL_TLSv1
    | NGX_SSL_TLSv1_1
    | NGX_SSL_TLSv1_2;

  if (ngx_ssl_create(poller->upstream.ssl, protocols, NULL) != NGX_OK) {
    return NGX_ERROR;
  }

  cln = ngx_pool_cleanup_add(cf->pool, 0);
  if (cln == NULL) {
    return NGX_ERROR;
  }

  cln->handler = ngx_ssl_cleanup_ctx;
  cln->data = poller->upstream.ssl;

  return NGX_OK;
}

#endif /* NGX_HTTP_SSL */

static char *
ngx_http_poller_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_poller_conf_ctx_t   ctx;
  ngx_http_poller_conf_t      *pcf = conf;
  ngx_http_poller_t           *poller;
  char                        *rv;
  ngx_str_t                   *value;

  poller = ngx_array_push(&pcf->pollers);
  if (poller == NULL) {
    return NGX_CONF_ERROR;
  }

  ngx_memzero(poller, sizeof(ngx_http_poller_t));

  if (ngx_array_init(&poller->headers, cf->pool, 1,
		     sizeof(ngx_http_poller_header_t)) != NGX_OK) {
    return NGX_CONF_ERROR;
  }

  value = cf->args->elts;
  poller->name = value[1];

  poller->upstream.buffering = 1;
  poller->upstream.connect_timeout = 60000;
  poller->upstream.read_timeout = 60000;
  poller->upstream.send_timeout = 60000;
  poller->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
  poller->upstream.bufs.num = 8;
  poller->upstream.bufs.size = ngx_pagesize;
  poller->upstream.max_temp_file_size = 0;
  poller->upstream.temp_file_write_size = 0;
  poller->upstream.pass_request_headers = 1;
  poller->upstream.pass_request_body = 1;
  poller->upstream.hide_headers = NGX_CONF_UNSET_PTR;
  poller->upstream.pass_headers = NGX_CONF_UNSET_PTR;
#if NGX_HTTP_SSL
  poller->upstream.ssl_session_reuse = 1;
#endif /* NGX_HTTP_SSL */

  poller->pool = cf->pool;

  ctx.cf = *cf;
  ctx.poller = poller;

  cf->ctx = &ctx;
  cf->handler = ngx_http_poller;
  cf->handler_conf = conf;

  rv = ngx_conf_parse(cf, NULL);

  *cf = ctx.cf;

  if (poller->upstream.buffer_size == NGX_CONF_UNSET_SIZE) {
    poller->upstream.buffer_size = ngx_pagesize;
  }

  poller->upstream.busy_buffers_size = 2 * poller->upstream.buffer_size;

  return rv;
}

static char *
ngx_http_poller_set(ngx_conf_t *cf,
		    ngx_str_t *value,
		    ngx_http_complex_value_t *complex)
{
  ngx_http_compile_complex_value_t   ccv;

  if (complex->value.data != NULL) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[poller] duplicate declaration");
    return NGX_CONF_ERROR;
  }

  ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

  ccv.cf = cf;
  ccv.value = value;
  ccv.complex_value = complex;

  if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *
ngx_http_poller_add_header(ngx_conf_t *cf,
			   ngx_http_poller_t *poller,
			   ngx_str_t *name,
			   ngx_str_t *value)
{
  ngx_http_poller_header_t *header;

  header = ngx_array_push(&poller->headers);
  if (header == NULL) {
    return NGX_CONF_ERROR;
  }

  if (ngx_strcasecmp(name->data, (u_char *)"Content-Length") == 0) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		       "[poller] %V: Content-Length header may not be set",
		       &poller->name);
    return NGX_CONF_ERROR;
  }

  header->name = *name;
  ngx_memzero(&header->value, sizeof(ngx_http_complex_value_t));

  return ngx_http_poller_set(cf, value, &header->value);
}

static char *
ngx_http_poller_set_endpoint(ngx_conf_t *cf,
			     ngx_http_poller_t *poller,
			     ngx_str_t *value)
{
  size_t   add;
  u_short  port;

  if (poller->endpoint.data != NULL) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		       "[poller] %V: endpoint already declared",
		       &poller->name);
    return NGX_CONF_ERROR;
  }

  poller->endpoint = *value;

  /* parse the scheme */
  if (poller->endpoint.len > 7 &&
      ngx_strncmp(poller->endpoint.data, "http://", 7) == 0) {
    add = 7;
    port = 80;
  } else if (poller->endpoint.len > 8 &&
	     ngx_strncmp(poller->endpoint.data, "https://", 8) == 0) {
#if NGX_HTTP_SSL
    add = 8;
    port = 443;
    if (ngx_http_poller_set_ssl(cf, poller) != NGX_OK) {
      return NGX_CONF_ERROR;
    }
#else /* !NGX_HTTP_SSL */
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		       "[poller] %V: endpoint %V: requires SSL support",
		       &poller->name, &poller->endpoint);
    return NGX_CONF_ERROR;
#endif /* NGX_HTTP_SSL */
  } else {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		       "[poller] %V: endpoint %V: invalid scheme",
		       &poller->name, &poller->endpoint);
    return NGX_CONF_ERROR;
  }

  poller->scheme.len = add;
  poller->scheme.data = poller->endpoint.data;

  poller->url.url.len = poller->endpoint.len - add;
  poller->url.url.data = poller->endpoint.data + add;
  poller->url.default_port = port;
  poller->url.uri_part = 1;
  poller->url.no_resolve = 1;

  poller->upstream.upstream = ngx_http_upstream_add(cf, &poller->url, 0);
  if (poller->upstream.upstream == NULL) {
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *
ngx_http_poller_set_method(ngx_conf_t *cf,
			   ngx_http_poller_t *poller,
			   ngx_str_t *value)
{
  if (poller->method.data != NULL) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		       "[poller] %V: method already declared",
		       &poller->name);
    return NGX_CONF_ERROR;
  }

  if (ngx_strcmp(value->data, "GET")  != 0 &&
      ngx_strcmp(value->data, "HEAD") != 0 &&
      ngx_strcmp(value->data, "POST") != 0 &&
      ngx_strcmp(value->data, "PUT")  != 0) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		       "[poller] %V: method '%V' invalid",
		       &poller->name, value);
    return NGX_CONF_ERROR;
  }

  if (ngx_strcmp(value->data, "POST") == 0 ||
      ngx_strcmp(value->data, "PUT")  == 0) {
    poller->body_ok = 1;
  }
      
  poller->method = *value;

  return NGX_CONF_OK;
}

static char *
ngx_http_poller(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
  ngx_http_poller_conf_ctx_t  *ctx;
  ngx_http_poller_t           *poller;
  ngx_str_t                   *value;
  char                        *rv;

  ctx = cf->ctx;
  poller = ctx->poller;
  value = cf->args->elts;

  if (cf->args->nelts == 3 &&
      ngx_strcmp(value[0].data, "header") == 0) {
    rv = ngx_http_poller_add_header(&ctx->cf, poller, &value[1], &value[2]);
  } else if (cf->args->nelts != 2) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		       "invalid number of poller parameters");
    rv = NGX_CONF_ERROR;
  } else if (ngx_strcmp(value[0].data, "include") == 0) {
    rv = ngx_conf_include(cf, dummy, conf);
  } else if (ngx_strcmp(value[0].data, "endpoint") == 0) {
    rv = ngx_http_poller_set_endpoint(&ctx->cf, poller, &value[1]);
  } else if (ngx_strcmp(value[0].data, "method") == 0) {
    rv = ngx_http_poller_set_method(&ctx->cf, poller, &value[1]);
  } else if (ngx_strcmp(value[0].data, "uri") == 0) {
    rv = ngx_http_poller_set(&ctx->cf, &value[1], &poller->uri);
  } else if (ngx_strcmp(value[0].data, "body") == 0) {
    rv = ngx_http_poller_set(&ctx->cf, &value[1], &poller->body);
  } else if (ngx_strcmp(value[0].data, "interval") == 0) {
    rv = ngx_http_poller_set(&ctx->cf, &value[1], &poller->interval);
  } else {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		       "invalid poller directive '%V'", &value[0]);
    rv = NGX_CONF_ERROR;
  }

  return rv;
}

/* this should be called after the poller was found in the config. */

ngx_int_t
ngx_http_poller_set_handler(ngx_http_poller_conf_t *conf,
			    ngx_str_t *name,
			    ngx_http_poller_handler_t *handler)
{
  ngx_http_poller_t      *poller;
  ngx_int_t               found;
  ngx_uint_t              i;

  found = 0;
  poller = conf->pollers.elts;
  for (i = 0; i < conf->pollers.nelts; ++i) {
    if (poller[i].name.len == name->len &&
	ngx_strncmp(poller[i].name.data, name->data, name->len) == 0) {
      poller[i].handler = *handler;
      found = 1;
      break;
    }
  }

  return (found) ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
ngx_http_poller_init_process(ngx_cycle_t *cycle)
{
  ngx_http_poller_conf_t *pcf;
  ngx_http_poller_t      *poller;
  ngx_log_t              *log;
  ngx_event_t            *ev;
  ngx_uint_t              i;

  pcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_poller_module);
  if (pcf == NULL) {
    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
		  "[poller] no module context");
    return NGX_ERROR;
  }

  poller = pcf->pollers.elts;
  for (i = 0; i < pcf->pollers.nelts; ++i) {
    log = &poller[i].log;
    log->action = "initializing";
    log->file = cycle->new_log.file;

    /* only install the poll event if the endpoint is defined. */
    if (poller[i].endpoint.data != NULL) {
      ev = &poller[i].poll_event;

      ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
		    "[poller] %V: activated (endpoint %V)",
		    &poller[i].name, &poller[i].endpoint);

      ev->data = &poller[i];
      ev->log = log;
      ev->handler = ngx_http_poller_event;

      ngx_add_timer(ev, 0);
    } else {
      ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
		    "[poller] %V: inactive (no endpoint)",
		    &poller[i].name);
    }
  }

  return NGX_OK;
}

static ngx_int_t
ngx_http_poller_create_request(ngx_http_request_t *r)
{
  ngx_http_poller_t         *poller;
  ngx_http_poller_header_t  *header;
  ngx_str_t                 *value;
  ngx_buf_t                 *b;
  ngx_chain_t               *cl;
  ngx_uint_t                 i;
  size_t                     len;
  ngx_str_t                  uri;
  ngx_str_t                  body;
  ngx_array_t                headers;

  poller = ngx_http_get_module_ctx(r, ngx_http_poller_module);

  if (ngx_http_complex_value(r, &poller->uri, &uri) != NGX_OK) {
    return NGX_ERROR;
  }

  body.len = 0;
  body.data = NULL;
  if (poller->body_ok) {
    if (ngx_http_complex_value(r, &poller->body, &body) != NGX_OK) {
      return NGX_ERROR;
    }
  }

  len  = poller->method.len;
  len += sizeof(" ") - 1;
  len += uri.len;
  len += sizeof(" HTTP/1.0") - 1;
  len += sizeof(CRLF) - 1;

  if (poller->headers.nelts > 0) {
    if (ngx_array_init(&headers, r->pool, poller->headers.nelts,
		       sizeof(ngx_str_t)) != NGX_OK) {
      return NGX_ERROR;
    }

    header = poller->headers.elts;
    for (i = 0; i < poller->headers.nelts; ++i) {
      value = ngx_array_push(&headers);
      if (value == NULL) {
	return NGX_ERROR;
      }
      if (ngx_http_complex_value(r, &header[i].value, value) != NGX_OK) {
	return NGX_ERROR;
      }

      len += header[i].name.len;
      len += sizeof(": ") - 1;
      len += value->len;
      len += sizeof(CRLF) - 1;
    }    
  }

  if (poller->body_ok) {
    len += sizeof("Content-Length: ") - 1 + NGX_OFF_T_LEN + 2;
  }

  len += sizeof(CRLF) - 1;

  b = ngx_create_temp_buf(r->pool, len);
  if (b == NULL) {
    return NGX_ERROR;
  }

#define DO_CPYMEM(x, y) x = ngx_cpymem(x, y, sizeof(y) - 1)
#define DO_CPYSTR(x, y) x = ngx_cpymem(x, y.data, y.len)

  DO_CPYSTR(b->last, poller->method);
  DO_CPYMEM(b->last, " ");
  DO_CPYSTR(b->last, uri);
  DO_CPYMEM(b->last, " HTTP/1.0");
  DO_CPYMEM(b->last, CRLF);

  if (poller->headers.nelts > 0) {
    header = poller->headers.elts;
    value = headers.elts;
    for (i = 0; i < poller->headers.nelts; ++i) {
      DO_CPYSTR(b->last, header[i].name);
      DO_CPYMEM(b->last, ": ");
      DO_CPYSTR(b->last, value[i]);
      DO_CPYMEM(b->last, CRLF);
    }
  }

  if (poller->body_ok) {
    b->last = ngx_sprintf(b->last, "Content-Length: %O", (off_t)body.len);
    DO_CPYMEM(b->last, CRLF);
  }

  DO_CPYMEM(b->last, CRLF);

  if (poller->body_ok && body.len > 0) {
    DO_CPYSTR(b->last, body);
  }

#undef DO_CPYMEM
#undef DO_CPYSTR

  cl = ngx_alloc_chain_link(r->pool);
  if (cl == NULL) {
    return NGX_ERROR;
  }

  cl->buf = b;
  cl->next = NULL;

  r->upstream->request_bufs = cl;
  r->subrequest_in_memory = 1;
  b->last_buf = 1;

  return NGX_OK;
}

static ngx_int_t
ngx_http_poller_process_header(ngx_http_request_t *r)
{
  static ngx_str_t      content_length = ngx_string("Content-Length");
  ngx_http_poller_t    *poller;
  ngx_http_upstream_t  *u;
  ngx_int_t             rc;
  ngx_str_t             name;
  ngx_str_t             value;

  poller = ngx_http_get_module_ctx(r, ngx_http_poller_module);
  if (poller == NULL) {
    return NGX_ERROR;
  }

  u = r->upstream;

  for ( ;; ) {
    rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);

    if (rc == NGX_OK) {
      name.len = r->header_name_end - r->header_name_start;
      name.data = r->header_name_start;

      value.len = r->header_end - r->header_start;
      value.data = r->header_start;

      if (name.len == content_length.len &&
          ngx_strncasecmp(name.data, content_length.data, name.len) == 0) {
        u->headers_in.content_length_n = ngx_atoof(value.data, value.len);
      }

      if (poller->handler.header != NULL) {
	poller->handler.header(r, &name, &value);
      }

      continue;
    }

    if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
      return NGX_OK;
    }

    if (rc == NGX_AGAIN) {
      return NGX_AGAIN;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "upstream sent invalid header");

    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
  }
}

static ngx_int_t
ngx_http_poller_process_status_line(ngx_http_request_t *r)
{
  ngx_int_t             rc;
  ngx_http_upstream_t  *u;
  ngx_http_poller_t    *poller;

  poller = ngx_http_get_module_ctx(r, ngx_http_poller_module);
  if (poller == NULL) {
    return NGX_ERROR;
  }

  u = r->upstream;

  rc = ngx_http_parse_status_line(r, &u->buffer, &poller->status);
  if (rc == NGX_AGAIN) {
    return rc;
  }

  if (rc == NGX_ERROR) {
    if (u->state) {
      u->state->status = NGX_HTTP_OK;
    }
    u->headers_in.connection_close = 1;

    return NGX_OK;
  }

  if (u->state) {
    u->state->status = poller->status.code;
  }
  u->headers_in.connection_close = 1;

  if (poller->handler.status != NULL) {
    poller->handler.status(r, &poller->status);
  }

  ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		 "[poller] %V: status = %uD",
		 &poller->name, (uint32_t)poller->status.code);

  r->upstream->process_header = ngx_http_poller_process_header;

  return ngx_http_poller_process_header(r);
}

static ngx_int_t
ngx_http_poller_reinit_request(ngx_http_request_t *r)
{
  ngx_http_poller_t *poller;

  poller = ngx_http_get_module_ctx(r, ngx_http_poller_module);
  if (poller == NULL) {
    return NGX_OK;
  }

  ngx_memzero(&poller->status, sizeof(ngx_http_status_t));
  r->upstream->process_header = ngx_http_poller_process_status_line;

  return NGX_OK;
}

static ngx_int_t
ngx_http_poller_filter_init(void *data)
{
  ngx_http_request_t   *r = data;
  ngx_http_upstream_t  *u;
  ngx_http_poller_t    *poller;

  u = r->upstream;
  u->length = u->headers_in.content_length_n;

  poller = ngx_http_get_module_ctx(r, ngx_http_poller_module);
  if (poller == NULL) {
    return NGX_ERROR;
  }

  ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		 "[poller] %V: response length = %d",
		 &poller->name, (int)u->length);

  return NGX_OK;
}

static ngx_int_t
ngx_http_poller_filter(void *data, ssize_t bytes)
{
  ngx_http_request_t   *r = data;
  ngx_http_upstream_t  *u;
  ngx_http_poller_t    *poller;
  ngx_str_t             body;

  poller = ngx_http_get_module_ctx(r, ngx_http_poller_module);
  if (poller == NULL) {
    return NGX_ERROR;
  }

  u = r->upstream;

  ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		 "[poller] %V: received %d bytes, length = %d",
		 &poller->name, (int)bytes, (int)u->length);

  if (bytes > 0) {
    if (poller->handler.body != NULL) {
      body.data = u->buffer.last;
      body.len = bytes;
      poller->handler.body(r, &body);
    }
  }

  if (u->length == -1) {
    return NGX_OK;
  }

  u->length -= bytes;

  return NGX_OK;
}

static void
ngx_http_poller_abort_request(ngx_http_request_t *r)
{
  ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                "[poller] aborted upstream request");

  return;
}

static void
ngx_http_poller_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
  ngx_http_poller_t  *poller;
  ngx_str_t           interval;
  ngx_time_t         *tp;
  ngx_msec_t          msec;
  uint64_t            now;

  poller = ngx_http_get_module_ctx(r, ngx_http_poller_module);
  if (poller->handler.finalize != NULL) {
    poller->handler.finalize(r, rc);
  }

  if (ngx_http_complex_value(r, &poller->interval, &interval) != NGX_OK) {
    return;
  }

  msec = ngx_parse_time(&interval, 0);
  if (msec == (ngx_msec_t)NGX_ERROR) {
    return;
  }

  tp = ngx_timeofday();
  now = tp->sec * 1000 + tp->msec;
  if (now > poller->poll_start) {
    if (now - poller->poll_start < msec) {
      msec -= (now - poller->poll_start);
    } else {
      msec = 0;
    }
  }

  ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		 "[poller] %V: calling again in %uD ms",
		 &poller->name, (uint32_t)msec);

  ngx_add_timer(&poller->poll_event, msec);

  r->connection->log->log_level = NGX_LOG_EMERG;
}

static void *
ngx_http_poller_destroy_pools(ngx_pool_t *cpool, ngx_pool_t *rpool)
{
  if (cpool != NULL) {
    ngx_destroy_pool(cpool);
  }
  if (rpool != NULL) {
    ngx_destroy_pool(rpool);
  }

  return NULL;
}

static ngx_http_request_t *
ngx_http_poller_request(ngx_http_poller_t *poller)
{
  ngx_connection_t           *c;
  ngx_http_request_t         *r;
  ngx_http_upstream_t        *u;
  ngx_log_t                  *log;
  ngx_http_log_ctx_t         *ctx;
  ngx_http_core_main_conf_t  *cmcf;
  ngx_http_conf_ctx_t        *cctx;
  ngx_pool_t                 *cpool = NULL;
  ngx_pool_t                 *rpool = NULL;
  ngx_time_t                 *tp;
  struct sockaddr_in         *sin;

  log = &poller->log;
  log->log_level = NGX_LOG_DEBUG_CONNECTION | NGX_LOG_DEBUG_ALL;

  /* using connection_pool_size default */
  cpool = ngx_create_pool(256, log);
  if (cpool == NULL) {
    return ngx_http_poller_destroy_pools(cpool, rpool);
  }

  c = ngx_pcalloc(poller->pool, sizeof(ngx_connection_t));
  if (c == NULL) {
    return ngx_http_poller_destroy_pools(cpool, rpool);
  }

  c->read = ngx_pcalloc(cpool, sizeof(ngx_event_t));
  if (c->read == NULL) {
    return ngx_http_poller_destroy_pools(cpool, rpool);
  }

  c->write = ngx_pcalloc(cpool, sizeof(ngx_event_t));
  if (c->write == NULL) {
    return ngx_http_poller_destroy_pools(cpool, rpool);
  }

  c->local_sockaddr = ngx_pcalloc(cpool, sizeof(struct sockaddr_in));
  if (c->local_sockaddr == NULL) {
    return ngx_http_poller_destroy_pools(cpool, rpool);
  }

  c->pool = cpool;
  c->log = log;

  c->local_sockaddr->sa_family = AF_INET;
  sin = (struct sockaddr_in *)c->local_sockaddr;
  sin->sin_addr.s_addr = 0x0100007f;

  c->read->log = log;
  c->write->log = log;

  c->log->log_level = NGX_LOG_DEBUG_CONNECTION | NGX_LOG_DEBUG_ALL;
  c->requests++;

  /* using request_pool_size default */
  rpool = ngx_create_pool(4096, log);
  if (rpool == NULL) {
    return ngx_http_poller_destroy_pools(cpool, rpool);
  }

  r = ngx_pcalloc(rpool, sizeof(ngx_http_request_t));
  if (r == NULL) {
    return ngx_http_poller_destroy_pools(cpool, rpool);
  }

  r->pool = rpool;
  r->connection = c;

  cctx = (ngx_http_conf_ctx_t *)ngx_cycle->conf_ctx[ngx_http_module.index];

  r->main_conf = cctx->main_conf;
  r->srv_conf = cctx->srv_conf;
  r->loc_conf = cctx->loc_conf;

  if (ngx_list_init(&r->headers_out.headers, r->pool, 20,
                    sizeof(ngx_table_elt_t)) != NGX_OK) {
    return ngx_http_poller_destroy_pools(cpool, rpool);
  }

  r->ctx = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
  if (r->ctx == NULL) {
    return ngx_http_poller_destroy_pools(cpool, rpool);
  }

  cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

  r->variables = ngx_pcalloc(r->pool, cmcf->variables.nelts
                             * sizeof(ngx_http_variable_value_t));
  if (r->variables == NULL) {
    return ngx_http_poller_destroy_pools(cpool, rpool);
  }

  r->main = r;
  r->count = 1;

  tp = ngx_timeofday();
  r->start_sec = tp->sec;
  r->start_msec = tp->msec;

  ctx = ngx_palloc(c->pool, sizeof(ngx_http_log_ctx_t));
  if (ctx == NULL) {
    return ngx_http_poller_destroy_pools(cpool, rpool);
  }

  ctx->connection = c;
  ctx->request = r;
  ctx->current_request = r;

  c->log->data = ctx;
  c->log->action = "polling";
  c->log_error = NGX_ERROR_INFO;
  c->write->active = 1;
  c->fd = -1;
  c->data = r;

  if (ngx_http_upstream_create(r) != NGX_OK) {
    return ngx_http_poller_destroy_pools(cpool, rpool);
  }

  ngx_http_set_ctx(r, poller, ngx_http_poller_module);

  u = r->upstream;

#if (NGX_HTTP_SSL)
  if (conf->upstream.ssl != NULL) {
    u->ssl = 1;
  }
#endif

  u->output.tag = (ngx_buf_tag_t)&ngx_http_poller_module;
  u->headers_in.content_length_n = -1;
  u->conf = &poller->upstream;

  ngx_memzero(&poller->status, sizeof(ngx_http_status_t));

  u->create_request = ngx_http_poller_create_request;
  u->reinit_request = ngx_http_poller_reinit_request;
  u->process_header = ngx_http_poller_process_status_line;
  u->abort_request = ngx_http_poller_abort_request;
  u->finalize_request = ngx_http_poller_finalize_request;

  u->buffering = 1;
  u->input_filter_init = ngx_http_poller_filter_init;
  u->input_filter = ngx_http_poller_filter;
  u->input_filter_ctx = r;

  return r;
}

static void
ngx_http_poller_event(ngx_event_t *ev)
{
  ngx_http_poller_t   *poller = ev->data;
  ngx_http_request_t  *r;
  ngx_time_t          *tp;

  if (ngx_exiting) {
    return;
  }

  tp = ngx_timeofday();
  poller->poll_start = tp->sec * 1000 + tp->msec;

  r = ngx_http_poller_request(poller);
  if (r != NULL) {
    ngx_http_upstream_init(r);
  }
}
