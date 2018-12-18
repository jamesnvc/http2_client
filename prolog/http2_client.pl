:- module(http2_client, [http2_open/3,
                         http2_close/1,
                         http2_request/4]).
/** <module> HTTP/2 client

@author James Cash
*/

:- use_module(library(predicate_options)).
:- use_module(library(list_util), [split_at/4]).
:- use_module(library(ssl), [ssl_context/3,
                             ssl_negotiate/5,
                             cert_accept_any/5]).
:- use_module(library(socket), [tcp_connect/3,
                                tcp_select/3,
                                tcp_host_to_address/2]).
:- use_module(library(url), [parse_url/2]).
:- use_module(library(record)).
:- use_module(frames).
:- use_module(hpack, [lookup_header/3]).

:- multifile prolog:message//1.
prolog:message(unknown_frame(Code, In, State)) -->
    [ "Unknown HTTP/2 frame ~w: ~w~nState: ~w"-[Code, In, State] ].
prolog:message(bad_frame(State, In)) -->
    [ "Couldn't read frame from ~w~nState: ~w"-[In, State] ].
prolog:message(connection_closed(Error, Data, State)) -->
    [ "Connection closed with error code ~w: ~w~nClient state: ~w"-[Error, Data, State] ].
prolog:message(worker_died) --> [ "HTTP/2 client worker thread died"-[] ].

connection_preface(`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`).

default_complete_cb(Headers, _Body) :-
    debug(http2_client(open), "Complete without callback set ~w", [Headers]).
% [TODO] store state of connection, to determine what's valid to recieve/send
:- record http2_stream(headers=[],
                       data=[],
                       done=false,
                       complete_cb=default_complete_cb).

default_close_cb(Data) :-
    debug(http2_client(open), "Connection closed without callback set ~w", [Data]).

:- record http2_state(authority=false,
                      stream=false,
                      settings=settings{header_table_size: 4096,
                                        enable_push: 0, %1,
                                        max_concurrent_streams: unlimited,
                                        initial_window_size: 65535,
                                        max_frame_size: 16384,
                                        max_header_list_size: unlimited},
                      recv_header_table=[],
                      recv_header_table_size=4096,
                      send_header_table=[],
                      send_header_table_size=4096,
                      next_stream_id=1,
                      last_stream_id=0,
                      substreams=streams{},
                      close_cb=default_close_cb).

:- predicate_options(http2_open/3, 3, [close_cb(callable),
                                       pass_to(ssl_context/3)]).
:- record http2_ctx(stream=false,
                    worker_thread_id=false).
%! http2_open(+URL, -HTTP2Ctx, +Options) is det.
%  Open =Stream= as an HTTP/2 connection to =URL='s host.
%
%   @arg Options passed to ssl_context/3. http2_open-specific options:
%         * close_cb(Callable)
%           Predicate to be called when the connection receives a GOAWAY frame.
http2_open(URL, Http2Ctx, Options) :-
    % Open TLS connection
    parse_url(URL, [protocol(https),host(Host)|Attrs]),
    (memberchk(port(Port), Attrs) ; Port = 443), !,
    debug(http2_client(open), "URL ~w -> Host ~w:~w", [URL, Host, Port]),
    ssl_context(client, Ctx, [host(Host),
                              close_parent(true),
                              alpn_protocols([h2]),
                              cacert_file(system(root_certificates))
                              |Options]),
    tcp_host_to_address(Host, Address),
    debug(http2_client(open), "Host ~w -> Address ~w", [Host, Address]),
    tcp_connect(Address:Port, PlainStreamPair, []),
    debug(http2_client(open), "Connected", []),
    stream_pair(PlainStreamPair, PlainRead, PlainWrite),
    set_stream(PlainRead, buffer(false)),
    ssl_negotiate(Ctx, PlainRead, PlainWrite,
                  SSLRead, SSLWrite),
    debug(http2_client(open), "Negotiated", []),
    stream_pair(Stream, SSLRead, SSLWrite),
    % HTTP/2 connection starts with preface...
    connection_preface(ConnectionPreface),
    format(Stream, "~s", [ConnectionPreface]),
    % ...then SETTINGS frame
    send_frame(Stream, settings_frame([enable_push-0])),
    flush_output(Stream),
    % XXX: ...then we read a SETTINGS from from server & ACK it
    (memberchk(close_cb(CloseCb), Options), ! ; CloseCb = default_close_cb),
    make_http2_state([authority(Host),
                      stream(Stream),
                      close_cb(CloseCb)],
                     State),
    thread_create(listen_socket(State), WorkerThreadId, [at_exit(warn_worker_died(Stream, CloseCb))]),
    make_http2_ctx([stream(Stream), worker_thread_id(WorkerThreadId)],
                   Http2Ctx).

warn_worker_died(Stream, CloseCb) :-
    thread_self(ThreadId),
    (thread_property(ThreadId, status(exception(finished)))
    -> debug(http2_client(open), "Worker thread exited normally", [])
    ;  (print_message(warning, worker_died),
        close(Stream),
        thread_property(ThreadId, status(Status)),
        call(CloseCb, _{cause: Status,
                        msg: "Worker thread died"}))).


%! http2_close(+Ctx) is det.
%  Close the given stream.
http2_close(Http2Ctx) :-
    http2_ctx_worker_thread_id(Http2Ctx, ThreadId),
    thread_send_message(ThreadId, done).

:- meta_predicate http2_request(+, +, +, 2).
%! http2_request(+Stream, +Headers, +Body, :Response) is det.
%  Send an HTTP/2 request using the previously-opened HTTP/2
%  connection =Stream=.
%
%  @see http2_open/3
http2_request(Ctx, Headers, Body, ResponseCb) :-
    debug(http2_client(request), "Sending request ~w", [Ctx]),
    http2_ctx_worker_thread_id(Ctx, WorkerId),
    Msg = request{headers: Headers,
                  body: Body,
                  on_complete: ResponseCb},
    thread_send_message(WorkerId, Msg).

% Worker thread

listen_socket(State0) :-
    http2_state_stream(State0, Stream),
    stream_to_lazy_list(Stream, StreamList),
    listen_socket(State0, StreamList).
listen_socket(State0, StreamList0) :-
    thread_self(ThreadId),
    (thread_get_message(ThreadId, Msg, [timeout(0)])
    -> (debug(http2_client(request), "Client msg ~k", [Msg]),
        handle_client_request(Msg, State0, State1),
        debug(http2_client(request), "Msg sent new state ~w", [State1]))
    ;  State1 = State0), !,

    http2_state_stream(State1, Stream),
    tcp_select([Stream], Input, 0),
    (( Input = [Stream] ; \+ attvar(StreamList0) )
    -> (debug(http2_client(response), "Data available", []),
        read_frame(State1, StreamList0, State2, StreamList1),
        debug(http2_client(response), "Read data, rest ~w", [StreamList1]))
    ; (State1 = State2, StreamList1 = StreamList0)),

    listen_socket(State2, StreamList1).

worker_shutdown(State, Cause) :-
    http2_state_stream(State, Stream),
    close(Stream),
    debug(http2_client(open), "...closed", []),

    http2_state_close_cb(State, CloseCb),
    http2_state_last_stream_id(State, LastStreamId),
    call(CloseCb, _{last_stream_id: LastStreamId,
                    cause: Cause}),
    throw(finished).

% Worker thread - sending requests

handle_client_request(done, State, _) :-
    http2_state_stream(State, Stream),
    http2_state_last_stream_id(State, LastId),
    debug(http2_client(open), "Closing connection ~w...", [LastId]),
    send_frame(Stream, goaway_frame(LastId, 0, [])),
    flush_output(Stream),
    worker_shutdown(State, "Client closed").
handle_client_request(Msg, State0, State4) :-
    Msg = request{headers: Headers_,
                  body: Body,
                  on_complete: ResponseCb},
    http2_state_authority(State0, Authority),
    Headers = [':authority'-Authority,':scheme'-https|Headers_],
    http2_state_next_stream_id(State0, Ident),
    stream_info(State0, Ident, StreamInfo0),
    set_complete_cb_of_http2_stream(ResponseCb, StreamInfo0, StreamInfo1),
    update_state_substream(Ident, StreamInfo1, State0, State1),
    NextIdent is Ident + 2,
    set_next_stream_id_of_http2_state(NextIdent, State1, State2),
    debug(http2_client(request), "Sending headers ~w ~w", [Headers, State1]),
    (Body = [] -> HeadersEnd = true ; HeadersEnd = false),
    send_request_headers(Headers, Ident, HeadersEnd, State2, State3),
    send_request_body(Body, Ident, State3, State4),
    http2_state_stream(State4, Stream),
    flush_output(Stream).

send_request_headers(Headers_, Ident, EndStream, State0, State1) :-
    http2_state_send_header_table(State0, Table0),
    wrapped_headers(Table0, Headers_, Headers),
    http2_state_send_header_table_size(State0, TableSize),
    http2_state_stream(State0, Stream),
    % [TODO] check size of header frame & split into header +
    % continuation if too large
    send_frame(Stream,
               header_frame(Ident, Headers, TableSize-Table0-TableSize1-Table1,
                            [end_headers(true), end_stream(EndStream)])),
    debug(http2_client(request), "Sent headers", []),
    set_http2_state_fields(
        [send_header_table(Table1),
         send_header_table_size(TableSize1)],
        State0, State1).

send_request_body([], _, State, State) :- !.
send_request_body(Body, Ident, State0, State0) :-
    % [TODO] make end_stream configurable? If wanting to do streaming
    % or something?
    http2_state_stream(State0, Stream),
    http2_state_settings(State0, Settings),
    MaxSize = Settings.max_frame_size,
    send_body_parts(Stream, Ident, MaxSize, Body).

send_body_parts(_, _, _, []) :- !.
send_body_parts(Stream, Ident, MaxSize, Body) :-
    length(Body, BodyL),
    BodyL =< MaxSize, !,
    send_frame(Stream,
              data_frame(Ident, Body, [end_stream(true)])).
send_body_parts(Stream, Ident, MaxSize, Body) :-
    split_at(MaxSize, Body, ToSend, Rest),
    send_frame(Stream, data_frame(Ident, ToSend, [])),
    send_body_parts(Stream, Ident, MaxSize, Rest).

wrapped_headers(_, [], []) :- !.
wrapped_headers(Table, [K-V|RestH], [indexed(K-V)|RestW]) :-
    lookup_header(Table, K-V, _), !,
    wrapped_headers(Table, RestH, RestW).
wrapped_headers(Table, [K-V|RestH], [literal_inc(K-V)|RestW]) :-
    !, wrapped_headers(Table, RestH, RestW).
wrapped_headers(Table, [KV|RestH], [KV|RestW]) :-
    wrapped_headers(Table, RestH, RestW).

% Worker thread - recieving data from server

read_frame(State0, In, State2, Rest) :-
    phrase(frames:frame(Type, Flags, Ident, Payload),
           In, Rest), !,
    debug(http2_client(response), "Read frame type ~w", [Type]),
    phrase(frames:frame(Type, Flags, Ident, Payload), Bytes),
    http2_state_last_stream_id(State0, LastIdent),
    NewLastIdent is max(LastIdent, Ident),
    set_last_stream_id_of_http2_state(NewLastIdent, State0, State1),
    debug(http2_client(response), "Update last seen frame ~w", [NewLastIdent]),
    handle_frame(Type, Ident, State1, Bytes, State2),
    debug(http2_client(response), "Handled frame", []).
read_frame(State, In, _, _) :-
    print_message(warning, bad_frame(State, In)),
    !, fail.

handle_frame(0x0, _, State0, In, State2) :- % data frame
    phrase(data_frame(Ident, Data, [end_stream(End)]), In), !,
    length(Data, DataL),
    debug(http2_client(response), "Data on stream ~w # = ~w end? ~w", [Ident, DataL, End]),
    stream_info(State0, Ident, StreamInfo0),
    http2_stream_data(StreamInfo0, OldData),
    append(OldData, Data, NewData),
    set_http2_stream_fields([data(NewData), done(End)],
                            StreamInfo0, StreamInfo1),
    update_state_substream(Ident, StreamInfo1, State0, State1),
    (End -> complete_client(Ident, State1, State2) ; State2 = State1).
handle_frame(0x1, Ident, State0, In, State3) :- % headers frame
    http2_state_recv_header_table(State0, HeaderTable0),
    http2_state_recv_header_table_size(State0, TableSize),
    phrase(header_frame(Ident,
                        Headers,
                        TableSize-HeaderTable0-TableSize1-HeaderTable1,
                        % Ignoring priority
                        [end_stream(EndStream),
                         end_headers(EndHeaders)]),
          In), !,
    debug(http2_client(response), "Header frame ~w", [Headers]),
    stream_info(State0, Ident, StreamInfo),
    http2_stream_headers(StreamInfo, PreviousHeaders),
    append(PreviousHeaders, Headers, NewHeaders),
    debug(http2_client(response), "NEW HEADERS ~w", [NewHeaders]),
    set_http2_stream_fields([done(EndStream),
                             headers(NewHeaders)],
                            StreamInfo, StreamInfo1),
    update_state_substream(Ident, StreamInfo1, State0, State1),
    set_http2_state_fields([recv_header_table(HeaderTable1),
                            recv_header_table_size(TableSize1)],
                           State1, State2),
    ((EndStream, EndHeaders)
    -> complete_client(Ident, State2, State3)
    ;  State3 = State2).
handle_frame(0x2, _Ident, State0, _In, State0). % priority frame
handle_frame(0x3, Ident, State0, In, State2) :- % rst frame
    phrase(rst_frame(Ident, ErrCode), In), !,
    debug(http2_client(response), "Rst frame ~w ~w", [Ident, ErrCode]),
    stream_info(State0, Ident, StreamInfo0),
    set_done_of_http2_stream(true, StreamInfo0, StreamInfo1),
    update_state_substream(Ident, StreamInfo1, State0, State1),
    complete_client(Ident, State1, State2).
handle_frame(0x4, _, State0, In, State0) :- % settings ack frame
    phrase(settings_ack_frame, In), !.
handle_frame(0x4, _, State0, In, State1) :- % settings frame
    debug(http2_client(response), "read settings ~w", [In]),
    phrase(settings_frame(UpdateSettings), In), !,
    debug(http2_client(response), "Settings ~w", [UpdateSettings]),
    http2_state_settings(State0, Settings),
    update_settings(Settings, UpdateSettings, NewSettings),
    NewTableSize = NewSettings.header_table_size,
    http2_state_recv_header_table(State0, OldTable),
    hpack:keep_fitting(NewTableSize, OldTable, NewTable),
    set_http2_state_fields([settings(NewSettings),
                            recv_header_table(NewTable),
                            recv_header_table_size(NewTableSize)],
                           State0, State1),
    % [TODO] validate new size
    % send ACK
    http2_state_stream(State1, Stream),
    send_frame(Stream, settings_ack_frame), flush_output(Stream).
handle_frame(0x5, Ident, State0, In, State2) :- % push promise frame
    http2_state_recv_header_table(State0, TableIn),
    http2_state_recv_header_table_size(State0, TableSize),
    phrase(push_promise_frame(Ident, NewIdent, TableSize-TableIn-TableSizeOut-TableOut-Headers,
                              [end_headers(_EndHeaders)]),
          In), !,
    debug(http2_client(response), "Push promise Stream ~w headers ~w", [NewIdent, Headers]),

    stream_info(State0, NewIdent, StreamInfo0),
    set_headers_of_http2_stream(Headers, StreamInfo0, StreamInfo1),
    update_state_substream(NewIdent, StreamInfo1, State0, State1),

    http2_state_last_stream_id(State1, LastStreamId),
    NewLastId is max(LastStreamId, NewIdent),
    set_http2_state_fields([last_stream_id(NewLastId),
                            recv_header_table(TableOut),
                            recv_header_table_size(TableSizeOut)],
                           State1, State2).
handle_frame(0x6, _, State, In, State) :- % ping frame
    phrase(ping_frame(_, Ack), In), !,
    (Ack
    ; (http2_state_stream(State, Stream),
       send_frame(Stream, ping_frame(`12345678`, true)))).
handle_frame(0x7, _, State0, In, State0) :- % goaway frame
    phrase(goaway_frame(LastStreamId, Error, Data), In),
    debug(http2_client(response), "GOAWAY frame: ~w ~w ~w", [LastStreamId, Error, Data]),
    (Error = 0 ; print_message(warning, connection_closed(Error, Data, State0))),
    worker_shutdown(State0, _{msg: "goaway frame",
                              error: Error,
                              data: Data}).
handle_frame(0x8, _, State0, In, State0) :- % window frame
    phrase(window_update_frame(Ident, Increment), In), !,
    debug(http2_client(response), "window frame ~w ~w", [Ident, Increment]),
    % [TODO] update flow control state for the stream
    true.
handle_frame(0x9, Ident, State0, In, State3) :- % continuation frame
    http2_state_recv_header_table(State0, HeaderTable0),
    http2_state_recv_header_table_size(State0, TableSize),
    phrase(continuation_frame(Ident,
                              TableSize-HeaderTable0-TableSizeOut-HeaderTable1-Headers,
                              EndHeaders),
          In),
    stream_info(State0, Ident, StreamInfo),
    http2_stream_headers(StreamInfo, PreviousHeaders),
    append(PreviousHeaders, Headers, NewHeaders),
    % Handle EndHeaders? (end of headers = means end of stream if the
    % previous header frame was end-of-stream but not end-of-headers)
    set_headers_of_http2_stream(NewHeaders, StreamInfo, StreamInfo1),
    update_state_substream(Ident, StreamInfo1, State0, State1),
    set_http2_state_fields([recv_header_table(HeaderTable1),
                            recv_header_table_size(TableSizeOut)],
                           State1, State2),
    http2_stream_done(StreamInfo1, StreamDone),
    ((StreamDone, EndHeaders)
    -> complete_client(Ident, State2, State3)
    ;  State3 = State2).
handle_frame(Code, _, State, In, State) :-
    print_message(warning, unknown_frame(Code, In, State)),
    !, fail.

% Worker thread - Completing a request

complete_client(Ident, State0, State1) :-
    stream_info(State0, Ident, StreamInfo),
    notify_client_done(StreamInfo),
    remove_state_substream(Ident, State0, State1).

notify_client_done(StreamInfo) :-
    http2_stream_complete_cb(StreamInfo, Cb),
    http2_stream_headers(StreamInfo, Headers),
    http2_stream_data(StreamInfo, Body),
    catch(call(Cb, Headers, Body),
          Err,
          debug(http2_client(request), "Error invoking cb ~w", [Err])).

% Other helper predicates

:- meta_predicate send_frame(+, :).
send_frame(Stream, Frame) :-
    debug(http2_client(request), "sending frame ~w", [Frame]),
    phrase(Frame, FrameCodes), !,
    format(Stream, "~s", [FrameCodes]).

update_settings(New, [], New).
update_settings(Old, [K-V|Rest], New) :-
    put_dict(K, Old, V, Update),
    update_settings(Update, Rest, New).

stream_info(State, Ident, Stream) :-
    http2_state_substreams(State, Streams),
    (get_dict(Ident, Streams, Stream) ; make_http2_stream([], Stream)).

update_state_substream(Ident, StreamInfo, State0, State1) :-
    http2_state_substreams(State0, Streams0),
    put_dict(Ident, Streams0, StreamInfo, Streams1),
    set_substreams_of_http2_state(Streams1, State0, State1).

remove_state_substream(Ident, State0, State1) :-
    http2_state_substreams(State0, Streams0),
    del_dict(Ident, Streams0, _, Streams1),
    set_substreams_of_http2_state(Streams1, State0, State1).
