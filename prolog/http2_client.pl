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
:- use_module(hpack, [lookup_header/3]).

%% :- use_foreign_library(ssl_alpns).

connection_preface(`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`).

:- predicate_options(http2_open/3, 3, [pass_to(ssl_context/3)]).

:- record http2_ctx(stream=false,
                    worker_thread_id=false).

default_complete_cb(Headers, _Body) :-
    debug(http2_client(open), "Complete without callback set ~w", [Headers]).
% TODO: store state of connection, to determine what's valid to recieve/send
:- record http2_stream(headers=[],
                       data=[],
                       done=false,
                       header_table=[],
                       header_table_size=4096,
                       complete_cb=default_complete_cb).

:- record http2_state(authority=false,
                      stream=false,
                      settings=settings{header_table_size: 4096,
                                        enable_push: 0, %1,
                                        max_concurrent_streams: unlimited,
                                        initial_window_size: 65535,
                                        max_frame_size: 16384,
                                        max_header_list_size: unlimited},
                      next_stream_id=1,
                      last_stream_id=0,
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
                              cacert_file(system(root_certificates))
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
    send_frame(Stream, settings_frame([enable_push-0])),
    flush_output(Stream),
    % XXX: ...then we read a SETTINGS from from server & ACK it
    make_http2_state([authority(Host), stream(Stream)], State),
    thread_create(listen_socket(State), WorkerThreadId, []),
    make_http2_ctx([stream(Stream), worker_thread_id(WorkerThreadId)],
                   Http2Ctx).

% Worker thread

listen_socket(State0) :-
    http2_state_stream(State0, Stream),
    stream_to_lazy_list(Stream, StreamList),
    listen_socket(State0, StreamList).
listen_socket(State0, StreamList) :-
    thread_self(ThreadId),
    (thread_get_message(ThreadId, Msg, [timeout(0)])
    -> (debug(http2_client(request), "Client msg ~k", [Msg]),
        handle_client_request(Msg, State0, State1))
    ;  State1 = State0), !,

    http2_state_stream(State1, Stream), tcp_select([Stream], Inputs, 0),
    ((Inputs = [Stream] ; \+ attvar(StreamList))
    -> (debug(http2_client(response), "Data ready ~w", [StreamList]),
        % XXX: can we just recreate the lazy list? will that work?
        read_frame(State1, StreamList, State2, StreamListRest),
        debug(http2_client(response), "Stream rest = ~w", [StreamListRest]))
    ;  (State2 = State1, StreamListRest = StreamList)), !,

    listen_socket(State2, StreamListRest).

% Worker thread - sending requests

handle_client_request(done, State, _) :-
    http2_state_stream(State, Stream),
    http2_state_last_stream_id(State, LastId),
    debug(http2_client(open), "Closing connection ~w...", [LastId]),
    send_frame(Stream, goaway_frame(LastId, 0, [])),
    flush_output(Stream),
    debug(http2_client(open), "...closed", []),
    throw(finished).
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
    stream_info(State0, Ident, StreamInfo),
    http2_stream_header_table(StreamInfo, Table0),
    wrapped_headers(Table0, Headers_, Headers),
    http2_stream_header_table_size(StreamInfo, TableSize),
    http2_state_stream(State0, Stream),
    % TODO: check size of header frame & split into header +
    % continuation if too large
    send_frame(Stream,
               header_frame(Ident, Headers, TableSize-Table0-Table1,
                            [end_headers(true), end_stream(EndStream)])),
    debug(http2_client(request), "Sent headers", []),
    set_header_table_of_http2_stream(Table1, StreamInfo, StreamInfo1),
    update_state_substream(Ident, StreamInfo1, State0, State1).

send_request_body([], _, State, State) :- !.
send_request_body(Body, Ident, State0, State0) :-
    % TODO: check size of data frame, possible break it up
    % TODO: make end_stream configurable? If wanting to do streaming
    % or something?
    http2_state_stream(State0, Stream),
    send_frame(Stream,
              data_frame(Ident, Body, [end_stream(true)])).

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
handle_frame(0x1, Ident, State0, In, State2) :- % headers frame
    stream_info(State0, Ident, StreamInfo),
    http2_stream_header_table(StreamInfo, HeaderTable0),
    http2_stream_header_table_size(StreamInfo, TableSize),
    phrase(header_frame(Ident,
                        Headers,
                        TableSize-HeaderTable0-HeaderTable1,
                        % Ignoring priority
                        [end_stream(EndStream),
                         end_headers(EndHeaders)]),
          In), !,
    debug(http2_client(response), "Header frame ~w", [Headers]),
    http2_stream_headers(StreamInfo, PreviousHeaders),
    append(PreviousHeaders, Headers, NewHeaders),
    debug(http2_client(response), "NEW HEADERS ~w", [NewHeaders]),
    set_http2_stream_fields([header_table(HeaderTable1),
                             done(EndStream),
                             headers(NewHeaders)],
                            StreamInfo, StreamInfo1),
    update_state_substream(Ident, StreamInfo1, State0, State1),
    ((EndStream, EndHeaders)
    -> complete_client(Ident, State1, State2)
    ;  State2 = State1).
handle_frame(0x2, _Ident, State0, _In, State0). % priority frame
handle_frame(0x3, Ident, State0, In, State1) :- % rst frame
    phrase(rst_frame(Ident, ErrCode), In), !,
    debug(http2_client(response), "Rst frame ~w ~w", [Ident, ErrCode]),
    stream_info(State0, Ident, StreamInfo0),
    set_done_of_http2_stream(true, StreamInfo0, StreamInfo1),
    % TODO: indicate error to client
    update_state_substream(Ident, StreamInfo1, State0, State1).
handle_frame(0x4, _, State0, In, State0) :- % settings ack frame
    phrase(settings_ack_frame, In), !.
handle_frame(0x4, _, State0, In, State1) :- % settings frame
    debug(http2_client(response), "read settings ~w", [In]),
    phrase(settings_frame(UpdateSettings), In), !,
    debug(http2_client(response), "Settings ~w", [UpdateSettings]),
    http2_state_settings(State0, Settings),
    update_settings(Settings, UpdateSettings, NewSettings),
    set_settings_of_http2_state(NewSettings, State0, State1),
    % send ACK
    http2_state_stream(State1, Stream),
    send_frame(Stream, settings_ack_frame), flush_output(Stream).
handle_frame(0x5, Ident, State0, In, State2) :- % push promise frame
    http2_state_settings(State0, Settings),
    get_dict(header_table_size, Settings, TableSize),
    phrase(push_promise_frame(Ident, NewIdent, TableSize-[]-TableOut-Headers,
                              [end_headers(_EndHeaders)]),
          In), !,
    debug(http2_client(response), "Push promise Stream ~w headers ~w", [NewIdent, Headers]),
    stream_info(State0, NewIdent, StreamInfo0),
    set_http2_stream_fields([headers(Headers),
                             header_table(TableOut)],
                            StreamInfo0, StreamInfo1),
    update_state_substream(NewIdent, StreamInfo1, State0, State1),
    http2_state_last_stream_id(State1, LastStreamId),
    NewLastId is max(LastStreamId, NewIdent),
    set_last_stream_id_of_http2_state(NewLastId, State1, State2).
handle_frame(0x6, _, State, In, State) :- % ping frame
    phrase(ping_frame(_, Ack), In), !,
    (Ack
    ; (http2_state_stream(State, Stream),
       send_frame(Stream, ping_frame(`12345678`, true)))).
handle_frame(0x7, _, State0, In, State0) :- % goaway frame
    phrase(goaway_frame(LastStreamId, Error, Data), In),
    debug(http2_client(response), "GOAWAY frame: ~w ~w ~w", [LastStreamId, Error, Data]),
    % TODO: need to stop stuff now
    true.
handle_frame(0x8, _, State0, In, State0) :- % window frame
    phrase(window_update_frame(Ident, Increment), In), !,
    debug(http2_client(response), "window frame ~w ~w", [Ident, Increment]),
    % TODO: update flow control state for the stream
    true.
handle_frame(0x9, Ident, State0, In, State2) :- % continuation frame
    stream_info(State0, Ident, StreamInfo),
    http2_stream_header_table(StreamInfo, HeaderTable0),
    http2_stream_header_table_size(StreamInfo, TableSize),
    phrase(continuation_frame(Ident,
                              TableSize-HeaderTable0-HeaderTable1-Headers,
                              EndHeaders),
          In),
    http2_stream_headers(StreamInfo, PreviousHeaders),
    append(PreviousHeaders, Headers, NewHeaders),
    % Handle EndHeaders? (end of headers = means end of stream if the
    % previous header frame was end-of-stream but not end-of-headers)
    set_http2_stream_fields([header_table(HeaderTable1),
                             headers(NewHeaders)],
                            StreamInfo, StreamInfo1),
    update_state_substream(Ident, StreamInfo1, State0, State1),
    http2_stream_done(StreamInfo1, StreamDone),
    ((StreamDone, EndHeaders)
    -> complete_client(Ident, State1, State2)
    ;  State2 = State1).
handle_frame(Code, _, State, In, State) :-
    debug(http2_client(response), "Unknown frame ~w: ~w", [Code, In]).

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

%! http2_close(+Ctx) is det.
%  Close the given stream.
http2_close(Http2Ctx) :-
    http2_ctx_worker_thread_id(Http2Ctx, ThreadId),
    thread_send_message(ThreadId, done).

%! http2_request(+Stream, +Method, +Headers, +Body, :Response) is det.
%  Send an HTTP/2 request using the previously-opened HTTP/2
%  connection =Stream=.
%  @see http2_open/2
http2_request(Ctx, Method, Path, Headers, Body, ResponseCb) :-
    debug(http2_client(request), "Sending request ~w", [Ctx]),
    http2_ctx_worker_thread_id(Ctx, WorkerId),
    FullHeaders = [':method'-Method,
                   ':path'-Path
                   |Headers],
    Msg = request{headers: FullHeaders,
                  body: Body,
                  on_complete: ResponseCb},
    thread_send_message(WorkerId, Msg).

% Helper predicates

:- meta_predicate send_frame(+, :).
send_frame(Stream, Frame) :-
    debug(http2_client(request), "sending frame ~w", [Frame]),
    phrase(Frame, FrameCodes), !,
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
       make_http2_stream([header_table_size(TableSize)], Stream))).

update_state_substream(Ident, StreamInfo, State0, State1) :-
    http2_state_substreams(State0, Streams0),
    put_dict(Ident, Streams0, StreamInfo, Streams1),
    set_substreams_of_http2_state(Streams1, State0, State1).

remove_state_substream(Ident, State0, State1) :-
    http2_state_substreams(State0, Streams0),
    del_dict(Ident, Streams0, _, Streams1),
    set_substreams_of_http2_state(Streams1, State0, State1).
