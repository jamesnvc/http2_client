:- module(http2_client, [http2_open/3,
                         http2_close/1,
                         http2_request/6]).
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
                    message_queue=false,
                    worker_thread_id=false).

% TODO: store state of connection, to determine what's valid to recieve/send
:- record http_stream(headers=[],
                      data=[],
                      done=false,
                      header_table=[],
                      header_table_size=4096,
                      complete_cb=false).

:- record http2_state(authority=false,
                      stream=false,
                      message_queue=false,
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
    message_queue_create(Queue, [alias(http2_msg_queue)]),
    make_http2_state(State, [authority(Host),
                             stream(Stream),
                             message_queue(Queue)]),
    thread_create(listen_socket(State), WorkerThreadId, []),
    make_http2_ctx(Http2Ctx, [stream(Stream),
                              message_queue(Queue),
                              worker_thread_id(WorkerThreadId)]).

% Worker thread

listen_socket(State0) :-
    http2_state_stream(State0, Stream),
    http2_state_message_queue(State0, Queue),
    (thread_get_message(Queue, Msg, [timeout(0)])
    -> (debug(http2_client(open), "Client msg ~w", [Msg]),
        handle_client_request(Msg, State0, State1))
    ;  State1 = State0),
    tcp_select([Stream], Inputs, 50),
    (Inputs = [Stream]
    -> (debug(http2_client(open), "Data ready", []),
        stream_to_lazy_list(Stream, StreamList),
        % XXX: can we just recreate the lazy list? will that work?
        read_frame(State1, StreamList, State2, _StreamListRest))
    ;  State2 = State1),
    listen_socket(State2).

handle_client_request(done, _, _) :- throw(finished).
handle_client_request(Msg, State0, State2) :-
    Msg = request{headers: Headers_,
                  body: Body,
                  on_complete: ResponseCb},
    http2_state_authority(State0, Authority),
    Headers = [':authority'-Authority|Headers_],
    http2_state_next_stream_id(State0, Ident),
    stream_info(State, Ident, StreamInfo0),
    set_complete_cb_of_http2_stream(ResponseCb, StreamInfo0, StreamInfo1),
    update_state_substream(Ident, StreamInfo1, State0, State1),
    NextIdent is Ident + 2,
    set_next_stream_id_of_http2_state(NextIdent, State1, State2),
    % TODO: break headers & body into frames, send, set callback
    true.

read_frame(State0, In, State1, Rest) :-
    phrase(frames:frame(Type, Flags, Ident, Payload),
           In, Rest), !,
    phrase(frames:frame(Type, Flags, Ident, Payload), Bytes),
    handle_frame(Type, Ident, State0, Bytes, State1, Rest).

handle_frame(0x0, _, State0, In, State1, Rest) :- % data frame
    phrase(data_frame(Ident, Data, [end_stream(End)]), In, Rest), !,
    debug(http2_client(open), "Data ~w ~s ~w", [Ident, Data, End]),
    stream_info(State0, Ident, StreamInfo0),
    http2_stream_data(StreamInfo0, OldData),
    append(OldData, Data, NewData),
    set_http2_stream_fields([data(NewData), done(End)],
                            StreamInfo0, StreamInfo1),
    % TODO: if End, notify client
    update_state_substream(Ident, StreamInfo1, State0, State1).
handle_frame(0x1, Ident, State0, In, State1, Rest) :- % headers frame
    stream_info(State0, Ident, StreamInfo),
    http2_stream_header_table(StreamInfo, HeaderTable0),
    http2_stream_header_table_size(StreamInfo, TableSize),
    phrase(headers_frame(Ident,
                         Headers,
                         TableSize-HeaderTable0-HeaderTable1,
                         % Ignoring priority
                         [end_stream(EndStream),
                          end_headers(EndHeaders)]),
          In, Rest), !,
    % XXX: what to do about EndHeaders? Should affect state or
    % something
    http2_stream_headers(StreamInfo, PreviousHeaders),
    append(PreviousHeaders, Headers, NewHeaders),
    % TODO: if End, notify client
    % TODO: if EndStream is true but EndHeaders isn't, then wait for
    % more continuation frames
    set_http2_stream_fields([header_table(HeaderTable1),
                             done(EndStream),
                             headers(NewHeaders)],
                            StreamInfo, StreamInfo1),
    update_state_substream(Ident, StreamInfo1, State0, State1).
handle_frame(0x2, _Ident, State0, _In, State0, _Rest). % priority frame
handle_frame(0x3, Ident, State0, In, State1, Rest) :- % rst frame
    phrase(rst_frame(Ident, ErrCode), In, Rest), !,
    debug(http2_client(open), "Rst frame ~w ~w", [Ident, ErrCode]),
    stream_info(State0, Ident, StreamInfo0),
    set_done_of_http2_stream(true, StreamInfo0, StreamInfo1),
    % TODO: indicate error to client
    update_state_substream(Ident, StreamInfo1, State0, State1).
handle_frame(0x4, _, State0, In, State1, Rest) :- % settings frame
    phrase(settings_frame(UpdateSettings), In, Rest), !,
    http2_state_settings(State0, Settings),
    update_settings(Settings, UpdateSettings, NewSettings),
    set_settings_of_http2_state(NewSettings, State0, State1),
    % send ACK
    http2_state_stream(State1, Stream),
    send_frame(Stream, settings_ack_frame), flush_output(Stream).
handle_frame(0x4, _, State0, In, State0, Rest) :- % settings ack frame
    phrase(settings_frame_ack, In, Rest), !.
handle_frame(0x5, Ident, State0, In, State1, Rest) :- % push promise frame
    http2_state_settings(State0, Settings),
    get_dict(header_table_size, Settings, TableSize),
    phrase(push_promise_frame(Ident, NewIdent, TableSize-[]-TableOut-Headers,
                              [end_headers(EndHeaders)]),
          In, Rest), !,
    stream_info(State0, NewIdent, StreamInfo0),
    % TODO: as in headers frame, do something with EndHeaders?
    set_http2_stream_fields([headers(Headers),
                             header_table(TableOut)],
                            StreamInfo0, StreamInfo1),
    update_state_substream(NewIdent, StreamInfo1, State0, State1).
handle_frame(0x6, _, State, In, State, Rest) :- % ping frame
    phrase(ping_frame(_, Ack), In, Rest), !,
    (Ack
    ; (http2_state_stream(State, Stream),
       send_frame(Stream, ping_frame(`12345678`, true)))).
handle_frame(0x7, _, State0, In, State0, Rest) :- % goaway frame
    phrase(goaway_frame(LastStreamId, Error, Data), In, Rest),
    debug(http2_client(open), "GOAWAY frame: ~w ~w ~w", [LastStreamId, Error, Data]),
    % TODO: need to stop stuff now
    true.
handle_frame(0x8, _, State0, In, State0, Rest) :- % window frame
    phrase(window_update_frame(Ident, Increment), In, Rest), !,
    % TODO: update flow control state for the stream
    true.
handle_frame(0x9, Ident, State0, In, State1, Rest) :- % continuation frame
    stream_info(State0, Ident, StreamInfo),
    http2_stream_header_table(StreamInfo, HeaderTable0),
    http2_stream_header_table_size(StreamInfo, TableSize),
    phrase(continuation_frame(Ident,
                              TableSize-HeaderTable0-HeaderTable1-Headers,
                              EndHeaders),
          In, Rest),
    http2_stream_headers(StreamInfo, PreviousHeaders),
    append(PreviousHeaders, Headers, NewHeaders),
    % Handle EndHeaders? (end of headers = means end of stream if the
    % previous header frame was end-of-stream but not end-of-headers)
    set_http2_stream_fields([header_table(HeaderTable1),
                             headers(NewHeaders)],
                            StreamInfo, StreamInfo1),
    update_state_substream(Ident, StreamInfo1, State0, State1).

%! http2_close(+Ctx) is det.
%  Close the given stream.
http2_close(Http2Ctx) :-
    http2_ctx_worker_thread_id(Http2Ctx, ThreadId),
    http2_ctx_message_queue(Http2Ctx, Queue),
    thread_send_message(Queue, done),
    thread_join(ThreadId, Status),
    debug(http2_client(open), "Joined worker thread ~w", [Status]),
    Status = exception(finished).

%! http2_request(+Stream, +Method, +Headers, +Body, :Response) is det.
%  Send an HTTP/2 request using the previously-opened HTTP/2
%  connection =Stream=.
%  @see http2_open/2
http2_request(Ctx, Method, Path, Headers, Body, ResponseCb) :-
    http2_ctx_message_queue(Ctx, Queue),
    FullHeaders = [':method'-Method,
                   ':path'-Path
                   |Headers],
    Msg = request{headers: FullHeaders,
                  body: Body,
                  on_complete: ResponseCb},
    thread_send_message(Queue, Msg).

% Helper predicates

:- meta_predicate send_frame(+, :).
send_frame(Stream, Frame) :-
    phrase(Frame, FrameCodes),
    debug(http2_client(open), "Sending data ~w", [FrameCodes]),
    put_codes(Stream, FrameCodes).

put_codes(Stream, Codes) :-
    open_codes_stream(Codes, CodesStream),
    copy_stream_data(CodesStream, Stream).

update_settings(New, [], New).
update_settings(Old, [K-V|Rest], New) :-
    put_dict(K, Old, V, Update),
    update_settings(Update, Rest, New).

stream_info(State, Ident, Stream) :-
    http2_state_substreams(State, Streams),
    (get_dict(Ident, Streams, Stream)
    ; (http2_state_settings(State, Settings),
       get_dict(header_table_size, Settings, TableSize),
       make_http2_stream(Stream, [header_table_size(TableSize)]))).

update_state_substream(Ident, StreamInfo, State0, State1) :-
    http2_state_substreams(State0, Streams0),
    put_dict(Ident, Streams0, StreamInfo, Streams1),
    set_substreams_of_http2_state(Streams1, State0, State1).
