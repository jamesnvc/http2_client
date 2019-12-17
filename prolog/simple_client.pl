:- module(simple_client, [http2_simple_open/4]).

:- use_module(http2_client, [http2_close/1,
                             http2_open/3,
                             http2_request/4]).
:- use_module(library(unix), [pipe/2]).
:- use_module(library(url), [parse_url/2]).

simple_complete_cb(OutStream, RespHeaders, RespHeaders, Body) :-
    debug(xxx, "complete ~w ~w", [RespHeaders, Body]),
    format(OutStream, "~s", [Body]),
    close(OutStream).

close_cb(Ctx, _Data) :-
    debug(xxx, "closed", []).

url_base_path(URL, Base, Path) :-
    parse_url(URL, [protocol(Proto), host(Host)|URLAttrs]),
    ( memberchk(port(PortN), URLAttrs)
    -> format(string(Port), ":~w", [PortN])
    ;  Port = ""
    ),
    format(string(Base), "~w://~w~w", [Proto, Host, Port]),
    memberchk(path(Path_), URLAttrs),
    ( memberchk(search(Search), URLAttrs)
    -> ( parse_url_search(Qcs, Search),
         format(string(Query), "?~s", [Qcs]) )
    ;  Query = "" ),
    ( memberchk(fragment(Frag), URLAttrs)
    -> format(string(Fragment), "#~w", [Frag])
    ;  Fragment = "" ),
    atomic_list_concat([Path_, Query, Fragment], '', Path).

http2_simple_open(Ctx, URL, Read, Options) :-
    url_base_path(URL, BaseURL, Path),
    debug(xxx, "opening ~w", [BaseURL]),
    http2_open(BaseURL, Ctx, [close_cb(simple_client:close_cb(Ctx))]),
    pipe(Read, Write),

    ( memberchk(method(Meth), Options) ; Meth = get ),
    ( memberchk(headers(RespHeaders), Options) ; RespHeaders = _ ),
    string_upper(Meth, Method),
    debug(xxx, "Requesting ~w ~w", [Method, Path]),
    http2_request(Ctx, [':method'-Method, ':path'-Path|Opts],
                  [],
                  simple_complete_cb(Write, RespHeaders)).

test :-
    debug(xxx),
    http2_simple_open(Ctx,
                      'https://nghttp2.org/httpbin/ip',
                      Stream,
                      []),
    read_string(Stream, _, Body),
    debug(xxx, "body ~w", [Body]),
    close(Stream),
    http2_close(Ctx).
