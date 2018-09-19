# A Prolog HTTP/2 Client

**This library is a work in progress**

It currently does not support server push and assumes correct input from servers -- it is not robust in the face of server errors or invalid data being sent.

Only HTTP/2 over TLS is supported, which requires SWI-Prolog 7.7.19 or greater for TLS-ALPN support.

It is available [as an SWI pack](http://www.swi-prolog.org/pack/list?p=http2_client) and can be installed by running `?- pack_install(http2_client)`.

**Contributions extremely welcome**

Requires the `list_util` and `delay` packs.

Uses the [reif](http://www.complang.tuwien.ac.at/ulrich/Prolog-inedit/swi/reif.pl) library.

## Example

```prolog
:- use_module(library(http2_client)).

test_close_cb(Ctx, Data) :-
    debug(xxx, ">>> server closed ~w", [Data]),
    http2_close(Ctx).
test_cb(Ident, Headers, Body) :-
    debug(xxx, ">>>>> ~w~n>>> headers ~w~n>>>body ~s...", [Ident, Headers, Body]).
test(Ctx) :-
    debug(xxx),
    http2_open('https://nghttp2.org', Ctx, [close_cb(http2_test:test_close_cb(Ctx))]),
    http2_request(Ctx, [':method'-'GET', ':path'-'/httpbin/ip'], [], test_cb(ip)),
    http2_request(Ctx, [':method'-'GET', ':path'-'/httpbin/headers'], [], test_cb(headers)),
    http2_request(Ctx, [':method'-'GET', ':path'-'/httpbin/get'], [], test_cb(get)).

?- test(Ctx).
```
