:- module(frames_t, []).

:- use_module(library(plunit)).
:- use_module(frames).
:- begin_tests(frames).

test('Pack data frame without padding or stream end') :-
    phrase(data_frame(12345, `Hello world`, []),
           Cs),
    ground(Cs),
    Cs = [0,0,11,0,0,0,0,48,57,72,101,108,108,111,32,119,111,114,108,100].

test('Pack data frame without padding') :-
    phrase(data_frame(12345, `Hello world`,
                                   [padded(0), end_stream(true)]),
           Cs),
    ground(Cs),
    Cs = [0,0,11,0,1,0,0,48,57,72,101,108,108,111,32,119,111,114,108,100].

test('Pack data fram with padding') :-
    phrase(data_frame(12345, `Hello world`,
                                   [padded(5), end_stream(true)]),
           Cs),
    ground(Cs),
    Cs = [0,0,17,0,9,0,0,48,57,5,72,101,108,108,111,32,119,111,114,108,100,0,0,0,0,0].

test('Unpack data without padding') :-
    Cs = [0,0,11,0,1,0,0,48,57,72,101,108,108,111,32,119,111,114,108,100],
    phrase(data_frame(Stream, Data,
                                   [padded(Padding), end_stream(End)]),
           Cs),
    Stream = 12345,
    Data = `Hello world`,
    Padding = 0,
    End = true.

test('Unpack data with padding') :-
    Cs = [0,0,29,0,8,0,0,212,49,16,72,111,119,32,97,114,101,32,121,111,117,63,0,
          0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    phrase(data_frame(Stream, Data,
                                   [padded(Padding), end_stream(End)]),
           Cs),
    ground(Data), ground(Stream), ground(Padding), ground(End),
    Stream = 54321,
    Data = `How are you?`,
    Padding = 16,
    End = false.

test('Pack headers') :-
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               indexed(':path'-'/')],
    phrase(header_frame(12345, Headers, 4096-[]-_Table, []), Bytes),
    ground(Bytes),
    Bytes = [0,0,3,1,4,0,0,48,57,130,134,132].

test('Pack headers padding') :-
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               indexed(':path'-'/')],
    phrase(header_frame(12345, Headers, 4096-[]-_Table, [padded(7)]), Bytes),
    ground(Bytes),
    Bytes = [0,0,11,1,12,0,0,48,57,7,130,134,132,0,0,0,0,0,0,0].

test('Unpack headers') :-
    Bytes = [0,0,3,1,4,0,0,48,57,130,134,132],
    phrase(header_frame(Stream, Headers, 4096-[]-_Table,
                                     [end_headers(End),
                                      end_stream(EndS),
                                      padded(Padding),
                                      priority(Prior)]),
           Bytes),
    ground(Headers), ground(Stream), ground(End), ground(EndS), ground(Padding),
    ground(Prior),
    Stream = 12345,
    End = true, EndS = false, Padding = 0, Prior = false,
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               indexed(':path'-'/')].

test('Unpack headers padding') :-
    Bytes = [0,0,11,1,12,0,0,48,57,7,130,134,132,0,0,0,0,0,0,0],
    phrase(header_frame(12345, Headers, 4096-[]-_Table, [padded(Pad)]), Bytes),
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               indexed(':path'-'/')],
    Pad = 7.

% TODO: tests for priority frame
% TODO: tests for rst frame

test('Pack settings frame') :-
    phrase(settings_frame([header_table_size-10, max_frame_size-0x2345]),
           Bytes),
    ground(Bytes),
    Bytes = [0, 0, 12,   % length = 6 * nsettings = 12
             4,          % type = 4
             0,          % flags = 0
             0, 0, 0, 0, % stream ident = 0
             0, 1,        % name = 0x1 = header table size
             0, 0, 0, 10, % val = 10
             0, 5,        % name = 0x5, = max frame size
             0, 0, 0x23, 0x45   % val = 0x2345
            ].

test('Unpack settings') :-
    Bytes = [0,0,12,4,0,0,0,0,0,0,1,0,0,0,10,0,5,0,0,35,69],
    phrase(settings_frame(Settings),
           Bytes),
    Settings = [header_table_size-10, max_frame_size-0x2345].

test('Unpack settings with unknown settings') :-
    Bytes = [0,0,12,4,0,0,0,0,0,0,1,0,0,0,10,0,255,0,0,35,69],
    phrase(settings_frame(Settings),
           Bytes),
    Settings = [header_table_size-10, 255-0x2345].

test('Settings ack') :-
    phrase(settings_ack_frame, Bytes),
    ground(Bytes),
    Bytes = [0, 0, 0, 4, 1, 0, 0, 0, 0].

test('Pack push promise frame') :-
    HeaderInfo = 4096-[]-_,
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-https),
               indexed(':path'-'/')],
    phrase(push_promise_frame(0, 1234, HeaderInfo-Headers, []),
           Bytes),
    ground(Bytes),
    Bytes = [0,0,7,5,4,0,0,0,0,0,0,4,210,130,135,132].

test('Unpack push promise frame') :-
    Bytes = [0,0,7,5,4,0,0,0,0,0,0,4,210,130,135,132],
    phrase(
        push_promise_frame(StreamId, PromisedStreamId, HeaderInfo-Headers,
                                        [padded(Pad), end_headers(End)]),
           Bytes),
    StreamId = 0,
    PromisedStreamId = 1234,
    HeaderInfo = 4096-[]-_,
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-https),
               indexed(':path'-'/')],
    Pad = 0,
    End = true.

test('Unpack push promise frame with opts') :-
    Bytes = [0,0,19,5,8,0,0,0,0,11,0,0,4,210,130,135,132,0,0,0,0,0,0,0,0,0,0,0],
    phrase(
        push_promise_frame(StreamId, PromisedStreamId, HeaderInfo-Headers,
                                        [padded(Pad), end_headers(End)]),
           Bytes),
    StreamId = 0,
    PromisedStreamId = 1234,
    HeaderInfo = 4096-[]-_,
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-https),
               indexed(':path'-'/')],
    Pad = 11,
    End = false.

test('Pack ping frame') :-
    phrase(ping_frame([1,2,3,4,5,6,7,8], false), Bytes),
    ground(Bytes),
    Bytes = [0,0,8,6,0,0,0,0,0,1,2,3,4,5,6,7,8].

test('Unpack ping frame') :-
    Bytes = [0,0,8,6,1,0,0,0,0,1,2,3,4,5,6,7,8],
    phrase(ping_frame(Data, Ack), Bytes),
    Ack = true,
    Data = [1,2,3,4,5,6,7,8].

test('Pack goaway frame') :-
    phrase(goaway_frame(1234, 9876, `Some debug info`),
           Bytes),
    ground(Bytes),
    Bytes = [0,0,23,7,0,0,0,0,0,0,0,4,210,0,0,38,148,83,111,109,101,32,100,101,
             98,117,103,32,105,110,102,111].

test('Unpack goaway frame') :-
    Bytes = [0,0,23,7,0,0,0,0,0,0,0,4,210,0,0,38,148,83,111,109,101,32,100,101,
             98,117,103,32,105,110,102,111],
    phrase(goaway_frame(LastId, ErrCode, DebugData),
           Bytes),
    LastId = 1234,
    ErrCode = 9876,
    DebugData = `Some debug info`, true.

test('Pack continuation frame') :-
    Headers = 4096-[]-_Tbl-[indexed(':method'-'GET'),
                            indexed(':path'-'/'),
                            literal_inc('something'-'foobar')],
    phrase(continuation_frame(1234, Headers, false), Bytes),
    ground(Bytes),
    Bytes = [0,0,20,9,0,0,0,4,210,130,132,64,9,115,111,109,101,116,104,105,110,
             103,6,102,111,111,98,97,114].

:- end_tests(frames).