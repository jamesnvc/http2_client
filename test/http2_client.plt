:- module(http2_client_t, []).

:- use_module(library(plunit)).
:- use_module(http2_client).
:- begin_tests(http2_client).

test('Pack data frame without padding or stream end') :-
    phrase(http2_client:data_frame(12345, `Hello world`, []),
           Cs),
    Cs = [0,0,11,0,0,0,0,48,57,72,101,108,108,111,32,119,111,114,108,100].

test('Pack data frame without padding') :-
    phrase(http2_client:data_frame(12345, `Hello world`,
                                   [padded(0), end_stream(true)]),
           Cs),
    Cs = [0,0,11,0,1,0,0,48,57,72,101,108,108,111,32,119,111,114,108,100].

test('Pack data fram with padding') :-
    phrase(http2_client:data_frame(12345, `Hello world`,
                                   [padded(5), end_stream(true)]),
           Cs),
    Cs = [0,0,17,0,9,0,0,48,57,5,72,101,108,108,111,32,119,111,114,108,100,0,0,0,0,0].

test('Unpack data without padding') :-
    Cs = [0,0,11,0,1,0,0,48,57,72,101,108,108,111,32,119,111,114,108,100],
    phrase(http2_client:data_frame(Stream, Data,
                                   [padded(Padding), end_stream(End)]),
           Cs),
    Stream = 12345,
    Data = `Hello world`,
    Padding = 0,
    End = true.

test('Unpack data with padding') :-
    Cs = [0,0,29,0,8,0,0,212,49,16,72,111,119,32,97,114,101,32,121,111,117,63,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    phrase(http2_client:data_frame(Stream, Data,
                                   [padded(Padding), end_stream(End)]),
           Cs),
    Stream = 54321,
    Data = `How are you?`,
    Padding = 16,
    End = false.

test('Pack headers') :-
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               indexed(':path'-'/')],
    phrase(http2_client:header_frame(12345, Headers, 4096-[]-_Table, []), Bytes),
    Bytes = [0,0,3,1,4,0,0,48,57,130,134,132].

test('Pack headers padding') :-
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               indexed(':path'-'/')],
    phrase(http2_client:header_frame(12345, Headers, 4096-[]-_Table, [padded(7)]), Bytes),
    Bytes = [0,0,11,1,12,0,0,48,57,7,130,134,132,0,0,0,0,0,0,0].

test('Unpack headers') :-
    Bytes = [0,0,3,1,4,0,0,48,57,130,134,132],
    phrase(http2_client:header_frame(12345, Headers, 4096-[]-_Table, [end_headers(End)]), Bytes),
    End = true,
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               indexed(':path'-'/')].

test('Unpack headers padding') :-
    Bytes = [0,0,11,1,12,0,0,48,57,7,130,134,132,0,0,0,0,0,0,0],
    phrase(http2_client:header_frame(12345, Headers, 4096-[]-_Table, [padded(Pad)]), Bytes),
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               indexed(':path'-'/')],
    Pad = 7.

test('Pack settings frame') :-
    phrase(http2_client:settings_frame([header_table_size-10, max_frame_size-0x2345]),
           Bytes),
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
    phrase(http2_client:settings_frame(Settings),
           Bytes),
    Settings = [header_table_size-10, max_frame_size-0x2345].

test('Unpack settings with unknown settings') :-
    Bytes = [0,0,12,4,0,0,0,0,0,0,1,0,0,0,10,0,255,0,0,35,69],
    phrase(http2_client:settings_frame(Settings),
           Bytes),
    Settings = [header_table_size-10, 255-0x2345].

test('Settings ack') :-
    phrase(http2_client:settings_ack_frame, Bytes),
    Bytes = [0, 0, 0, 4, 1, 0, 0, 0, 0].

:- end_tests(http2_client).
