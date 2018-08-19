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
:- use_module(library(url), [parse_url/2]).
:- use_module(library(record)).
:- use_module(frames).

%% :- use_foreign_library(ssl_alpns).

connection_preface(`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`).

:- predicate_options(http2_open/3, 3, [pass_to(ssl_context/3)]).

:- record http2_ctx(stream=false,
                    worker_thread_id=false).

% TODO: store state of connection, to determine what's valid to recieve/send
:- record http_stream(headers=[],
                      data=[],
                      done=false,
                      header_table=[],
                      header_table_size=4096).

:- record http2_state(authority=false,
                      stream=false,
                      settings=settings{header_table_size: 4096,
                                        enable_push: 1,
                                        max_concurrent_streams: unlimited,
                                        initial_window_size: 65535,
                                        max_frame_size: 16384,
                                        max_header_list_size: unlimited},
                      next_stream_id=1,
                      substreams=streams{}).

%! http2_open(+URL, -HTTP2Ctx, +Options) is det.
%  Open =Stream= as an HTTP/2 connection to =URL='s host.
http2_open(URL, Http2Ctx, Options) :-
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
    % XXX: ...then we read a SETTINGS from from server & ACK it
    make_http2_state(State, [authority(Host), stream(Stream)]),
    thread_create(listen_socket(State), WorkerThreadId, []),
    make_http2_ctx(Http2Ctx, [stream(Stream),
                              worker_thread_id(WorkerThreadId)]).

/*
    send_frame(Stream,
               header_frame(5, [indexed(':method'-'GET'),
                                indexed(':scheme'-'https'),
                                literal_inc(':authority'-Host),
                                indexed(':path'-'/'),
                                literal_inc('user-agent'-'swi-prolog')],
                            4096-[]-HTable, [end_stream(true),
                                             end_headers(true)])),
    flush_output(Stream),
*/


listen_socket(State) :-
    http2_state_stream(State, Stream),
    tcp_select([Stream], _, 50),
    debug(http2_client(open), "Data ready", []),
    stream_to_lazy_list(Stream, StreamList),
    read_frames(State, StreamList).

    %% debug(http2_client(open), "Server settings ~w", [Settings]),
    %% phrase(settings_ack_frame, AckCodes),
    %% put_codes(Stream, AckCodes),

    %% copy_stream_data(Stream, user_output).

update_settings(New, [], New).
update_settings(Old, [K-V|Rest], New) :-
    put_dict(K, Old, V, Update),
    update_settings(Update, Rest, New).

read_frame(State0, In, State1, Rest) :-
    phrase(frames:frame(Type, Flags, Ident, Payload),
           In, Rest), !,
    phrase(frames:frame(Type, Flags, Ident, Payload), Bytes),
    handle_frame(Type, Ident, State0, Bytes, State1, Rest).

handle_frame(0x0, _, State0, In, State1, Rest) :-
    phrase(data_frame(Ident, Data, [end_stream(End)]), In, Rest),
    debug(http2_client(open), "Data ~w ~s ~w", [Ident, Data, End]),
    stream_info(State0, Ident, StreamInfo0),
    http2_stream_data(StreamInfo0, OldData),
    append(OldData, Data, NewData),
    set_http2_stream_fields([data(NewData), done(End)],
                            StreamInfo0, StreamInfo1),
    % TODO: if End, notify client
    update_state_substream(Ident, StreamInfo1, State0, State1).
handle_frame(0x1, Ident, State0, In, State1, Rest) :-
    stream_info(State0, Ident, StreamInfo),
    http2_stream_header_table(StreamInfo, HeaderTable0),
    http2_stream_header_table_size(StreamInfo, TableSize),
    phrase(headers_frame(Ident,
                         Headers,
                         TableSize-HeaderTable0-HeaderTable1,
                         % Ignoring priority
                         [end_stream(EndStream),
                          end_headers(EndHeaders)]),
          In, Rest),
    % XXX: what to do about EndHeaders? Should affect state or
    % something
    http2_stream_headers(StreamInfo, PreviousHeaders),
    append(PreviousHeaders, Headers, NewHeaders),
    % TODO: if End, notify client
    set_http2_stream_fields([header_table(HeaderTable1),
                             done(EndStream),
                             headers(NewHeaders)],
                            StreamInfo, StreamInfo1),
    update_state_substream(Ident, StreamInfo1, State0, State1).

stream_info(State, Ident, Stream) :-
    http2_state_substreams(State, Streams),
    (get_dict(Ident, Streams, Stream)
    ; (http2_state_settings(State, Settings),
       get_dict(header_table_size, Settings, TableSize),
       make_http2_stream(Stream, [header_table_size(TableSize)]))).

update_state_substream(Ident, StreamInfo, State0, State1) :-
    http2_state_substreams(STate0, Streams0),
    put_dict(Ident, Streams0, StreamInfo, Streams1),
    set_substreams_of_http2_state(Streams1, State0, State1).

read_frames(State, In) :-
    phrase(settings_frame(RecievedSettings), In, Rest), !,
    debug(http2_client(open), "Got settings ~w", [RecievedSettings]),
    http2_state_settings(State, Settings),
    update_settings(Settings, RecievedSettings, NewSettings),
    debug(http2_client(open), "Settings ~w + ~w -> ~w",
          [Settings, RecievedSettings, NewSettings]),
    set_settings_of_http2_state(NewSettings, State, NewState),
    http2_state_stream(State, Stream),
    send_frame(Stream, settings_ack_frame),
    flush_output(Stream),
    read_frames(NewState, Rest).
read_frames(State, In) :-
    phrase(settings_ack_frame, In, Rest), !,
    debug(http2_client(open), "Got settings ack", []),
    read_frames(State, Rest).
read_frames(State, In) :-
    phrase(header_frame(Ident, Headers, 4096-HTable-HTableOut, [end_stream(End)]),
          In, Rest), !,
    debug(http2_client(open), "Headers ~w ~w ~w ~w", [Ident, Headers,
                                                      HTableOut, End]),
    (End
    -> close(Stream)
    ; read_frames(Stream, HTableOut, Rest)).
read_frames(Stream, HTable, In) :-
    catch(phrase(data_frame(Ident, Data, [end_stream(End)]), In, Rest),
          _, false), !,
    debug(http2_client(open), "Data ~w ~s ~w", [Ident, Data, End]),
    (End -> close(Stream) ; read_frames(Stream, HTable, Rest)).
read_frames(Stream, HTable, In) :-
    phrase(push_promise_frame(Ident, NewIdent,
                              4096-HTable-HTableOut-Headers,
                              Opts),
           In, Rest), !,
    debug(http2_client(open), "Got push promise ~w ~w ~w ~w ~w",
          [Ident, NewIdent, HTableOut, Headers, Opts]),
    read_frames(Stream, HTableOut, Rest).
read_frames(Stream, HTable, In) :-
    phrase(frames:frame(Type, Flags, Ident, Payload),
           In, Rest), !,
    debug(http2_client(open), "Other frame Type ~w flags ~w ident ~w payload ~w",
          [Type, Flags, Ident, Payload]),
    read_frames(Stream, HTable, Rest).

%! http2_close(+Ctx) is det.
%  Close the given stream.
http2_close(Http2Ctx) :-
    http2_ctx_stream(Stream),
    http2_ctx_worker_thread_id(ThreadId),
    thread_signal(ThreadId, exit),
    close(Stream).

%! http2_request(+Stream, +Method, +Headers, +Body, -Response) is det.
%  Send an HTTP/2 request using the previously-opened HTTP/2
%  connection =Stream=.
%  @see http2_open/2
http2_request(Ctx, Method, Path, Headers, Body, Response) :-
    http2_ctx_worker_thread_id(ThreadId),
    http2_ctx_authority(Authority),
    FullHeaders = [':method'-Method,
                   ':path'-Path,
                   ':authority'-Authority,
                   ':scheme'-https
                   |Headers],
    true.

:- meta_predicate send_frame(+, :).
send_frame(Stream, Frame) :-
    phrase(Frame, FrameCodes),
    debug(http2_client(open), "Sending data ~w", [FrameCodes]),
    put_codes(Stream, FrameCodes).

put_codes(Stream, Codes) :-
    open_codes_stream(Codes, CodesStream),
    copy_stream_data(CodesStream, Stream).
