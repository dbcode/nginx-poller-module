nginx-poller-module - Flexible detached polling requests for nginx workers
==========================================================================

This is nginx-poller-module, an nginx module that lets you configure your
worker process such that they each make detached requests to endpoints of
your choosing at a frequency you can control.

Background and motivation
-------------------------

This work was motivated by my desire to enable nginx worker processes to
do either of the following things:

* Communicate status information to some central location at regular,
  configurable intervals.

* Pull configuration information from some central location at regular,
  configurable intervals.

In a single-worker configuration, the poller module is not as useful,
because you can always set up handlers in your nginx installation that
respond with status information, or accept configuration information
via POST.  However, in a multiple-worker configuration, the workers
share the listening sockets, and it is not possible to pull from or
push to an individual worker.

A simple example
----------------

The following is an example nginx configuration snippet that one might
use with this module:

    # upstreams for status and config pollers

    upstream status { server 10.20.30.40:2000; }
    upstream config { server 10.20.30.40:3000; }

    # poller block for the status poller

    poller status {
      endpoint http://status;
      method   POST;
      header   Host status;
      header   User-Agent nginx;
      uri      /status;
      body     $my_worker_status;
      interval 100ms;
    }

    # poller block for the config poller

    poller config {
      endpoint http://config;
      method   GET;
      header   Host config;
      header   User-Agent nginx;
      uri      $my_config_uri;
      interval $my_config_interval;
    }

Pollers are configured in blocks within the main HTTP block, at the
same level as upstream directives.  Within a poller block, one must
define an **endpoint**, a **method**, a **uri**, and an **interval**.
One may also include any number of **header** directives, specifying
the header name and value as arguments.  Finally, for POST and PUT
requests, one must define a **body**.

It is permissible to use variables in the header value, the **uri**,
the **body**, and the **interval**.  The interval value must evaluate
to a time value; e.g. "1s" or "100ms", etc.  In a typical usage, the
URI and/or body might be furnished from some other module, which might
also provide the request interval.  So, for example, if you set up a
poller to request configuration updates, and your request comes back
with updates that need to be applied, you may set the interval such
that your next request is made immediately, so as to check right away
for further updates.  Once your configuration is caught up, you can
then restore the default interval.

For application of configuration updates, it is important to receive
the response body and do something with it.  To this end, you can
register a set of handlers that will process the response to your
poller requests.  Here is an example:

````c
static ngx_http_poller_handler_t my_config_handler = {
  my_config_handle_status,
  my_config_handle_header,
  my_config_handle_body,
  my_config_finalize
};

static ngx_int_t
my_config_postconf(ngx_conf_t *cf)
{
  static ngx_str_t         config = ngx_string("config");
  ngx_http_poller_conf_t  *conf;

  conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_poller_module);
  ngx_http_poller_set_handler(conf, &config, &my_config_handler);

  return NGX_OK;
}
````

The poller handler is a set of functions with the following signatures:

````c
typedef ngx_int_t (*ngx_http_poller_status_pt)(ngx_http_request_t *r,
					       ngx_http_status_t *status);
typedef ngx_int_t (*ngx_http_poller_header_pt)(ngx_http_request_t *r,
					       ngx_str_t *name,
					       ngx_str_t *value);
typedef ngx_int_t (*ngx_http_poller_body_pt)(ngx_http_request_t *r,
					     ngx_str_t *data);
typedef void (*ngx_http_poller_finalize_pt)(ngx_http_request_t *r,
					    ngx_int_t rc);
````

In this way, you can inject your module's processing into the poller's
handling of the HTTP response from the endpoint.

How to use this module
----------------------

Like all other third party modules, this module needs to be compiled
into your nginx binary.  First, you may wish to install the module
in your /usr/local/share (or $PREFIX/share):

    ./configure
    make install

This will copy the following files to $PREFIX/share/nginx-poller-module:

    config
    ngx_http_poller.c
    ngx_http_poller.h

You can add the module to your nginx build by configuring nginx like so,
assuming you had installed nginx-poller-module to /usr/local:

    ./configure --add-module=/usr/local/share/nginx-poller-module

If you wish to call ngx_http_poller_set_handler, you will also need to
add the same directory to your includes:

    ./configure \
      --with-cc-opt="-I/usr/local/share/nginx-poller-module" \
      --add-module=/usr/local/share/nginx-poller-module

26 April 2013

Dave Bailey <dave@daveb.net>

