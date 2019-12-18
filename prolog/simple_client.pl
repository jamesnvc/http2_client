:- module(simple_client, [http2_simple_open/3]).

:- use_module(http2_client, [http2_close/1,
                             http2_open/3,
                             http2_request/4]).
:- use_module(library(unix), [pipe/2]).
:- use_module(library(url), [parse_url/2]).
:- use_module(library(pcre), [re_replace/4]).

:- dynamic existing_url_context/2.

unwrap_header(Wrapped, Unwrapped) :-
    Wrapped =.. [_, Unwrapped].

simple_complete_cb(ThreadId, OutStream, WrappedHeaders, Body) :-
    format(OutStream, "~s", [Body]),
    close(OutStream),
    maplist(unwrap_header, WrappedHeaders, Headers),
    thread_send_message(ThreadId, finished(Headers)).

close_cb(BaseURL, _Ctx, _Data) :-
    debug(xxx, "Closing ~w", [BaseURL]),
    retractall(existing_url_context(BaseURL, _)).

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

canonical_header(Header, CanonicalHeader) :-
    string_lower(Header, HeaderLower),
    re_replace("-"/g, "_", HeaderLower, CanonicalHeader).

extract_headers(Options, Headers) :-
    bagof(CKey-Value,
          Key^( member(header(Key, Value), Options),
            canonical_header(Key, CKey) ),
         WantHeaders),
    maplist({Headers}/[CKey-Value]>>(
                ( member(Header-V, Headers),
                  canonical_header(Header, CKey),
                  Value = V
                ) ; Value = ''
            ),
            WantHeaders).

build_options(_OpenOptions, []).

url_context(BaseURL, Ctx) :-
    existing_url_context(BaseURL, Ctx), !.
url_context(BaseURL, Ctx) :-
    debug(xxx, "Opening new connection ~w", [BaseURL]),
    http2_open(BaseURL, Ctx, [close_cb(simple_client:close_cb(BaseURL, Ctx))]),
    assertz(existing_url_context(BaseURL, Ctx)).

http2_simple_open(URL, Read, Options) :-
    url_base_path(URL, BaseURL, Path),

    url_context(BaseURL, Ctx),

    pipe(Read, Write),

    ( memberchk(method(Meth), Options) ; Meth = get ),
    ( memberchk(headers(RespHeaders), Options) ; RespHeaders = _ ),
    string_upper(Meth, Method),
    thread_self(ThisId),

    build_options(Options, Opts),

    http2_request(Ctx, [':method'-Method, ':path'-Path|Opts],
                  [],
                  simple_complete_cb(ThisId, Write)),
    thread_get_message(finished(RespHeaders)),
    extract_headers(Options, RespHeaders).

http2_simple_close(URL) :-
    url_base_path(URL, Base, _),
    existing_url_context(Base, Ctx), !,
    http2_close(Ctx).
http2_simple_close(_).

test :-
    debug(xxx),
    http2_simple_open('https://nghttp2.org/httpbin/ip',
                      Stream,
                      [headers(Headers),
                       header('Content-Length', ContentLen),
                       header(x_frame_options, FrameOpts),
                       header(some_other_thing, Nope)
                      ]),
    read_string(Stream, _, Body),
    debug(xxx, "body ~w", [Body]),
    debug(xxx, "response headers ~w", [Headers]),
    debug(xxx, "Frame opts ~w", [FrameOpts]),
    debug(xxx, "content len ~w", [ContentLen]),
    debug(xxx, "nonexistant header ~k", [Nope]),
    close(Stream),
    %% http2_close(Ctx).
    true.
