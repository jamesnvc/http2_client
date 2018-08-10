:- module(http2_client, [http2_open/3,
                         http2_close/1,
                         http2_request/5]).
/** <module> HTTP/2 client

@author James Cash
*/
:- use_module(library(predicate_options)).
:- use_module(library(ssl), [ssl_context/3,
                             ssl_negotiate/5,
                             ssl_set_alpn_protos/3,
                             cert_accept_any/5]).
:- use_module(library(socket), [tcp_connect/3,
                                tcp_select/3,
                                tcp_host_to_address/2]).
:- use_module(frames).
:- use_module(library(url), [parse_url/2]).

%% :- use_foreign_library(ssl_alpns).

connection_preface(`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`).

:- predicate_options(http2_open/3, 3, [pass_to(ssl_context/3)]).

%! http2_open(+URL, -Stream, +Options) is det.
%  Open =Stream= as an HTTP/2 connection to =URL='s host.
http2_open(URL, Stream, Options) :-
    % Open TLS connection
    parse_url(URL, [protocol(https),host(Host)|Attrs]),
    (memberchk(port(Port), Attrs) ; Port = 443), !,
    debug(http2_client(open), "URL ~w -> Host ~w:~w", [URL, Host, Port]),
    ssl_context(client, Ctx0, [host(Host),
                               close_parent(true),
                               % TODO: use actual ssl certs
                               cert_verify_hook(cert_accept_any)
                               |Options]),
    ssl_set_alpn_protos(Ctx0, Ctx, [h2]),
    tcp_host_to_address(Host, Address),
    debug(http2_client(open), "Host ~w -> Address ~w", [Host, Address]),
    tcp_connect(Address:Port, PlainStreamPair, []),
    debug(http2_client(open), "Connected", []),
    stream_pair(PlainStreamPair, PlainRead, PlainWrite),
    ssl_negotiate(Ctx, PlainRead, PlainWrite,
                  SSLRead, SSLWrite),
    debug(http2_client(open), "Negotiated", []),
    stream_pair(Stream, SSLRead, SSLWrite),
    % HTTP/2 connection starts with preface...
    connection_preface(ConnectionPreface),
    put_codes(Stream, ConnectionPreface),
    % ...then SETTINGS frame
    phrase(settings_frame([]), SettingsCodes),
    put_codes(Stream, SettingsCodes),

    phrase(header_frame(3, [indexed(':method'-'GET'),
                            indexed(':path'-'/'),
                            indexed(':scheme'-'https'),
                            literal_inc(':authority'-Host)],
                        4096-[]-HTable, [end_stream(true),
                                         end_headers(true)]),
           HeaderCodes),
    put_codes(Stream, HeaderCodes),

    % ...then we read a SETTINGS from from server & ACK it
    tcp_select([Stream], _, 50),
    debug(http2_client(open), "Data ready", []),
    phrase_from_stream(frames:frame(Type, Flags, Ident, Payload), Stream),
    debug(http2_client(open), "Frame ~w ~w ~w ~w", [Type, Flags, Ident, Payload]).
    %% debug(http2_client(open), "Server settings ~w", [Settings]),
    %% phrase(settings_ack_frame, AckCodes),
    %% put_codes(Stream, AckCodes),

    %% copy_stream_data(Stream, user_output).

%! http2_close(+Stream) is det.
%  Close the given stream.
http2_close(_Stream).

%! http2_request(+Stream, +Method, +Headers, +Body, -Response) is det.
%  Send an HTTP/2 request using the previously-opened HTTP/2
%  connection =Stream=.
%  @see http2_open/2
http2_request(_Stream, _Method, _Headers, _Body, _Response).

put_codes(Stream, Codes) :-
    open_codes_stream(Codes, CodesStream),
    copy_stream_data(CodesStream, Stream).
