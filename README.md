# A Prolog HTTP/2 Client

**This library is a work in progress**

It currently does not support server push and assumes correct input from servers -- it is not robust in the face of server errors or invalid data being sent.

Only HTTP/2 over TLS is supported, which requires SWI-Prolog 7.7.19 or greater for TLS-ALPN support.

**Contributions extremely welcome**

Requires the `list_util` and `delay` packs.

Uses the [reif](http://www.complang.tuwien.ac.at/ulrich/Prolog-inedit/swi/reif.pl) library.


## Example

```prolog
:- use_module(http2_client).

test_cb(Ctx, Headers, Body) :-
    length(Body, BodyCount),
    debug(xxx, "Got response! ~w ~w", [Headers, BodyCount]),
    http2_close(Ctx).

test_stuff :-
    debug(xxx),
    debug(http2_client(open)),
    debug(http2_client(request)),
    debug(http2_client(response)),
    http2_open('https://http2.akamai.com', Ctx, []),
    debug(http2_client(open), "Opened ctx ~w", [Ctx]),
    http2_request(Ctx,
                  [':method'-'GET', ':path'-'/', 'user-agent'-'swi-prolog'],
                  [],
                  test_cb(Ctx)).
```
