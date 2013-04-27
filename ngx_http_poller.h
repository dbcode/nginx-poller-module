#ifndef _NGX_HTTP_POLLER_H_INCLUDED_
#define _NGX_HTTP_POLLER_H_INCLUDED_

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_config.h>

typedef ngx_int_t (*ngx_http_poller_status_pt)(ngx_http_request_t *r,
					       ngx_http_status_t *status);
typedef ngx_int_t (*ngx_http_poller_header_pt)(ngx_http_request_t *r,
					       ngx_str_t *name,
					       ngx_str_t *value);
typedef ngx_int_t (*ngx_http_poller_body_pt)(ngx_http_request_t *r,
					     ngx_str_t *data);
typedef void (*ngx_http_poller_finalize_pt)(ngx_http_request_t *r,
					    ngx_int_t rc);

typedef struct {
  ngx_http_poller_status_pt    status;
  ngx_http_poller_header_pt    header;
  ngx_http_poller_body_pt      body;
  ngx_http_poller_finalize_pt  finalize;
} ngx_http_poller_handler_t;

typedef struct {
  ngx_array_t                  pollers;    /* ngx_http_poller_t */
} ngx_http_poller_conf_t;

typedef struct {
  ngx_str_t                   name;
  ngx_http_complex_value_t    value;
} ngx_http_poller_header_t;

typedef struct {
  ngx_str_t                   name;
  ngx_str_t                   endpoint;
  ngx_url_t                   url;
  ngx_str_t                   scheme;
  ngx_str_t                   method;
  ngx_flag_t                  body_ok;     /* method = POST or PUT */
  ngx_array_t                 headers;     /* ngx_http_poller_header_t */
  ngx_http_complex_value_t    uri;
  ngx_http_complex_value_t    body;
  ngx_http_complex_value_t    interval;
  ngx_event_t                 poll_event;
  uint64_t                    poll_start;
  ngx_http_upstream_conf_t    upstream;
  ngx_log_t                   log;
  ngx_pool_t                 *pool;
  ngx_http_status_t           status;
  ngx_http_poller_handler_t   handler;
} ngx_http_poller_t;

/* A handler can be attached to a poller by its (config) name. */

ngx_int_t ngx_http_poller_set_handler(ngx_http_poller_conf_t *conf,
				      ngx_str_t *name,
				      ngx_http_poller_handler_t *handler);

ngx_module_t ngx_http_poller_module;

#endif /* _NGX_HTTP_POLLER_H_INCLUDED_ */
