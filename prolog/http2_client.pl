:- module(http2_client, [http2_open/3,
                         http2_close/1,
                         http2_request/5]).
/** <module> HTTP/2 client

@author James Cash
*/
:- use_module(library(predicate_options)).
:- use_module(library(ssl), [ssl_context/3,
                             ssl_negotiate/5,
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
    ssl_context(client, Ctx, [host(Host),
                               close_parent(true),
                               alpn_protocols([h2]),
                               % TODO: use actual ssl certs
                               cert_verify_hook(cert_accept_any)
                               |Options]),
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
    send_frame(Stream, settings_frame([])),

    send_frame(Stream,
               header_frame(5, [indexed(':method'-'GET'),
                                indexed(':scheme'-'https'),
                                literal_inc(':authority'-Host),
                                indexed(':path'-'/'),
                                literal_inc('user-agent'-'swi-prolog')],
                            4096-[]-HTable, [end_stream(true),
                                             end_headers(true)])),
    flush_output(Stream),

    % ...then we read a SETTINGS from from server & ACK it
    tcp_select([Stream], _, 50),
    debug(http2_client(open), "Data ready", []),
    stream_to_lazy_list(Stream, StreamList),
    read_frames(Stream, HTable, StreamList).

    %% debug(http2_client(open), "Server settings ~w", [Settings]),
    %% phrase(settings_ack_frame, AckCodes),
    %% put_codes(Stream, AckCodes),

    %% copy_stream_data(Stream, user_output).

read_frames(Stream, HTable, In) :-
    debug(http2_client(open), "try Settings frame", []),
    phrase(settings_frame(Settings), In, Rest), !,
    debug(http2_client(open), "Got settings ~w", [Settings]),
    send_frame(Stream, settings_ack_frame),
    flush_output(Stream),
    read_frames(Stream, HTable, Rest).
read_frames(Stream, HTable, In) :-
    debug(http2_client(open), "try Settings ack frame", []),
    phrase(settings_ack_frame, In, Rest), !,
    debug(http2_client(open), "Got settings ack", []),
    read_frames(Stream, HTable, Rest).
%% read_frames(Stream, HTable, In) :-
%%     debug(http2_client(open), "try headers frame with ~w", [HTable]),
%%     phrase(header_frame(Ident, Headers, 4096-HTable-HTableOut, Opts),
%%           In, Rest), !,
%%     debug(http2_client(open), "Headers ~w ~w ~w ~w", [Ident, Headers,
%%                                                       HTableOut, Opts]),
%%     memberchk(end_stream(End), Opts),
%%     (End
%%     -> close(Stream)
%%     ; read_frames(Stream, HTableOut, Rest)).
read_frames(Stream, HTable, In) :-
    debug(http2_client(open), "try data frame", []),
    catch(phrase(data_frame(Ident, Data, Opts), In, Rest),
          _, false), !,
    debug(http2_client(open), "Data ~w ~s ~w", [Ident, Data, Opts]),
    memberchk(end_stream(End), Opts),
    (End -> close(Stream) ; read_frames(Stream, HTable, Rest)).
read_frames(Stream, HTable, In) :-
    debug(http2_client(open), "try push promise frame", []),
    phrase(push_promise_frame(Ident, NewIdent,
                              4096-HTable-HTableOut-Headers,
                              Opts),
           In, Rest), !,
    debug(http2_client(open), "Got push promise ~w ~w ~w ~w ~w", [Ident, NewIdent, HTableOut, Headers, Opts]),
    read_frames(Stream, HTableOut, Rest).
read_frames(Stream, HTable, In) :-
    debug(http2_client(open), "try other frame", []),
    phrase(frames:frame(Type, Flags, Ident, Payload),
           In, Rest), !,
    debug(http2_client(open), "Other frame ~w ~w ~w ~w",
          [Type, Flags, Ident, Payload]),
    read_frames(Stream, HTable, Rest).

%! http2_close(+Stream) is det.
%  Close the given stream.
http2_close(_Stream).

%! http2_request(+Stream, +Method, +Headers, +Body, -Response) is det.
%  Send an HTTP/2 request using the previously-opened HTTP/2
%  connection =Stream=.
%  @see http2_open/2
http2_request(_Stream, _Method, _Headers, _Body, _Response).

:- meta_predicate send_frame(+, :).
send_frame(Stream, Frame) :-
    phrase(Frame, FrameCodes),
    debug(http2_client(open), "Sending data ~w", [FrameCodes]),
    put_codes(Stream, FrameCodes).

put_codes(Stream, Codes) :-
    open_codes_stream(Codes, CodesStream),
    copy_stream_data(CodesStream, Stream).
