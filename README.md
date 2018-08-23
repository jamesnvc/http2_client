# A Prolog HTTP/2 Client

Requires the `list_util` and `delay` packs.

Uses the [reif](http://www.complang.tuwien.ac.at/ulrich/Prolog-inedit/swi/reif.pl) library.


## Example

```prolog
test_cb(Ctx, Headers, Body) :-
    length(Body, BodyCount),
    debug(xxx, "Got response! ~w ~w", [Headers, BodyCount]),
    http2_close(Ctx).

test_stuff :-
    debug(xxx),
    http2_open('https://http2.akamai.com', Ctx, []),
    debug(http2_client(open), "Opened ctx ~w", [Ctx]),
    http2_request(Ctx, 'GET', '/', ['user-agent'-'swi-prolog'], [],
                 test_cb(Ctx)).
```
