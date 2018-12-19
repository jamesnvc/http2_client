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
    phrase(data_frame(Stream, Data, [padded(Padding), end_stream(End)]),
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
    phrase(header_frame(12345, Headers, 4096-[]-4096-_Table, []), Bytes),
    ground(Bytes),
    Bytes = [0,0,3,1,4,0,0,48,57,130,134,132].

test('Pack headers padding') :-
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               indexed(':path'-'/')],
    phrase(header_frame(12345, Headers, 4096-[]-4096-_Table, [padded(7)]), Bytes),
    ground(Bytes),
    Bytes = [0,0,11,1,12,0,0,48,57,7,130,134,132,0,0,0,0,0,0,0].

test('Pack headers priority') :-
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               indexed(':path'-'/')],
    phrase(header_frame(12345, Headers, 4096-[]-4096-_Table,
                        [padded(7),
                         priority(true),
                         is_exclusive(false),
                         stream_dependency(0x50),
                         weight(69)]),
           Bytes),
    ground(Bytes),
    Bytes = [0,0,16,
             1,
             44,
             0,0,48,57,
             7,
             0, 0, 0, 0x50,
             69,
             130,134,132,0,0,0,0,0,0,0].

test('Unpack headers') :-
    Bytes = [0,0,3,1,4,0,0,48,57,130,134,132],
    phrase(header_frame(Stream, Headers, 4096-[]-4096-_Table,
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
    phrase(header_frame(12345, Headers, 4096-[]-4096-_Table, [padded(Pad)]), Bytes),
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               indexed(':path'-'/')],
    Pad = 7.

test('Unpack headers priority') :-
    Bytes = [0,0,16,
             1,
             44,
             0,0,48,57,
             7,
             0, 0, 0, 0x50,
             69,
             130,134,132,0,0,0,0,0,0,0],
    phrase(header_frame(Ident, Headers, 4096-[]-4096-_Table,
                        [padded(Pad),
                         priority(Priority),
                         is_exclusive(Exclusive),
                         stream_dependency(StreamDep),
                         weight(Weight)]),
           Bytes),
    Ident = 12345,
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               indexed(':path'-'/')],
    Pad = 7,
    Priority = true,
    Exclusive = false,
    StreamDep = 0x50,
    Weight = 69.

% [TODO] tests for priority frame
% [TODO] tests for rst frame

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
    HeaderInfo = 4096-[]-_-_,
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
    ground(PromisedStreamId),
    StreamId = 0,
    PromisedStreamId = 1234,
    HeaderInfo = 4096-[]-4096-_,
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
    HeaderInfo = 4096-[]-4096-_,
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
    Headers = 4096-[]-4096-_Tbl-[indexed(':method'-'GET'),
                                 indexed(':path'-'/'),
                                 literal_inc('something'-'foobar')],
    phrase(continuation_frame(1234, Headers, false), Bytes),
    ground(Bytes),
    Bytes = [0,0,20,9,0,0,0,4,210,130,132,64,9,115,111,109,101,116,104,105,110,
             103,6,102,111,111,98,97,114].

test('Pack continuation end frame') :-
    Headers = 4096-[]-4096-_Tbl-[indexed(':method'-'GET'),
                                 indexed(':path'-'/'),
                                 literal_inc('something'-'foobar')],
    phrase(continuation_frame(1234, Headers, true), Bytes),
    ground(Bytes),
    Bytes = [0,0,20,9,4,0,0,4,210,130,132,64,9,115,111,109,101,116,104,105,110,
             103,6,102,111,111,98,97,114].

test('Unpack continuation frame') :-
    Bytes = [0,0,20,9,4,0,0,4,210,130,132,64,9,115,111,109,101,116,104,105,110,
             103,6,102,111,111,98,97,114],
    phrase(continuation_frame(1234, 4096-[]-4096-_Tbl-Headers, End), Bytes),
    maplist(ground, [Headers, End]),
    End = true,
    Headers = [indexed(':method'-'GET'),
               indexed(':path'-'/'),
               literal_inc('something'-'foobar')].

test('unpacking header') :-
    % 1 4 5
    Bytes = [0, 0x01, 0xe9,
             1,
             4,
             0, 0, 0, 5,
             24,130,16,1,31,39,133,134,177,146,114,255,31,16,145,73,124,165,137,211,77,31,100,156,118,32,169,131,134,252,43,61,31,19,161,254,95,3,143,16,64,148,36,116,78,188,38,223,11,242,182,244,161,101,194,73,44,111,134,224,91,3,141,182,211,77,11,249,31,41,154,164,126,86,28,197,129,144,182,203,128,0,20,251,80,213,18,139,100,46,235,99,190,122,70,106,145,31,5,1,42,16,148,25,8,84,33,98,30,164,216,122,22,29,20,31,194,212,149,51,158,68,127,140,197,131,127,214,60,16,223,250,215,171,118,255,16,148,25,8,84,33,98,30,164,216,122,22,29,20,31,194,211,148,114,22,196,127,1,42,16,150,25,8,84,33,98,30,164,216,122,22,29,20,31,194,196,176,178,22,164,152,116,35,132,148,116,32,191,16,143,25,8,84,33,98,30,164,216,122,22,164,126,86,28,197,132,121,198,128,15,16,134,25,8,90,210,177,39,164,191,175,111,210,156,141,34,103,250,83,137,139,226,179,216,149,185,26,68,207,244,165,243,248,170,131,85,215,233,77,195,238,85,175,141,35,16,142,174,195,164,228,61,17,84,89,142,147,13,38,61,95,2,104,50,16,133,167,213,118,29,39,2,104,50,16,135,37,6,45,73,136,213,255,138,113,197,196,7,87,16,130,184,153,7,16,138,37,6,45,73,138,194,142,136,141,95,138,113,197,196,7,87,16,130,184,153,7,16,139,154,115,161,49,32,182,119,49,11,17,171,138,116,75,137,167,23,105,149,196,33,127,16,134,154,115,161,49,26,191,138,11,205,46,243,139,178,202,225,120,31,16,130,177,41,1,51,16,131,174,212,79,131,77,150,151,16,143,242,176,250,142,145,153,100,216,58,145,41,236,164,178,127,143,125,64,129,240,62,160,20,174,152,224,167,111,13,31,65,31,9,138,164,126,86,28,197,129,166,68,0,127,31,21,150,228,89,62,148,11,106,67,108,202,8,1,121,64,63,113,167,174,8,74,98,209,191,31,18,150,223,105,126,148,11,74,67,108,202,8,1,121,65,6,227,79,92,16,148,197,163,127,31,13,132,8,95,100,63],
    DTable = ['user-agent'-'swi-prolog',
              accept- '*/*',
              host-'http2.akamai.com',
              ':authority'-'http2.akamai.com',
              ':path'-'/resources/push.css',
              'user-agent'-'swi-prolog',
              ':authority'-'http2.akamai.com'],
    phrase(header_frame(Ident, Headers, 4096-DTable-4096-DTableOut, [padded(Pad),
                                                                end_stream(EndStream),
                                                                end_headers(EndHeaders),
                                                                priority(Priority)]),
           Bytes),
    ground(Headers), ground(Ident), ground(DTableOut), ground(EndStream),
    ground(EndHeaders), ground(Priority),
    Ident = 5,
    Headers = [literal_never(':status'-'200'),
               literal_never(server-'Apache'),
               literal_never('content-type'-'text/html;charset=UTF-8'),
               literal_never(etag-'"9068c20f1c727825919f58f136cdfb91:1506554442"'),
               literal_never('strict-transport-security'-'max-age=31536000 ; includeSubDomains'),
               literal_never('access-control-allow-origin'-'*'),
               literal_never('access-control-allow-methods'-'GET,HEAD,POST'),
               literal_never('access-control-allow-headers'-'*'),
               literal_never('access-control-allow-credentials'-'false'),
               literal_never('access-control-max-age'-'86400'),
               literal_never('accept-ch'-'DPR, Width, Viewport-Width, Downlink, Save-Data'),
               literal_never('protocol_negotiation'-h2),
               literal_never(myproto-h2),
               literal_never('client_ip'-'66.207.221.230'),
               literal_never(client_real_ip-'66.207.221.230'),
               literal_never(ghost_service_ip-'72.246.43.222'),
               literal_never(ghost_ip-'184.86.33.180'),
               literal_never(rtt-'3'),
               literal_never(push-'true'),
               literal_never('x-akamai-transformed'-'9 10909 0 pmb=mRUM,1'),
               literal_never('cache-control'-'max-age=43200'),
               literal_never(expires-'Wed, 15 Aug 2018 09:48:22 GMT'),
               literal_never(date-'Tue, 14 Aug 2018 21:48:22 GMT'),
               literal_never('content-length'-'11931')],
    DTableOut = [-('user-agent','swi-prolog'),
                 -(accept,'*/*'),
                 -(host,'http2.akamai.com'),
                 -(':authority','http2.akamai.com'),
                 -(':path','/resources/push.css'),
                 -('user-agent','swi-prolog'),
                 -(':authority','http2.akamai.com')],
    Pad = 0,
    EndStream = false,
    EndHeaders = true,
    Priority = false.

test('pack header with size change') :-
    phrase(header_frame(123,
                        [indexed(':method'-'GET'),
                         indexed(':scheme'-'http'),
                         size_update(0),
                         indexed(':path'-'/'),
                         literal_inc(':authority'-'www.example.com')],
                        4096-[]-SizeOut-TableOut,
                        [padded(0),
                         end_stream(true),
                         end_headers(true)]),
           Bytes),
    ground(Bytes), ground(TableOut), ground(SizeOut),
    TableOut = [], SizeOut = 0,
    hex_bytes(Hex, Bytes),
    Hex = '00001501050000007b82862084410f7777772e6578616d706c652e636f6d'.

test('unpack header with size change') :-
    Bytes = [0,0,21,1,5,0,0,0,123,130,134,32,132,65,15,119,119,119,46,101,120,97,109,112,108,101,46,99,111,109],
    phrase(header_frame(Ident, Headers, 4096-[]-SizeOut-TableOut,
                        [padded(Pad),
                         end_stream(EndStream),
                         end_headers(EndHeader)]),
           Bytes),
    maplist(ground, [Ident, Headers, SizeOut, TableOut, Pad, EndStream, EndHeader]),
    Pad = 0,
    EndStream = true,
    EndHeader = true,
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               size_update(0),
               indexed(':path'-'/'),
               literal_inc(':authority'-'www.example.com')],
    SizeOut = 0, TableOut = [].

test('Pack headers across multiple frames') :-
    phrase(header_frames(100, 123,
                         [indexed(':method'-'GET'),
                          indexed(':scheme'-'http'),
                          indexed(':path'-'/'),
                          literal_inc(':authority'-'www.example.com'),
                          literal_never(push-'true'),
                          literal_never('strict-transport-security'-'max-age=31536000 ; includeSubDomains'),
                          literal_never('access-control-allow-origin'-'*'),
                          literal_never('access-control-allow-methods'-'GET,HEAD,POST'),
                          literal_never('access-control-allow-headers'-'*'),
                          literal_never('access-control-max-age'-'86400'),
                          literal_never('access-control-allow-credentials'-'false'),
                          literal_never('protocol_negotiation'-h2),
                          literal_never(myproto-h2),
                          literal_never(rtt-'3')],
                         4096-[]-_SizeOut-_TableOut,
                         [padded(0), end_stream(true)]),
           Bytes),
    ground(Bytes),
    phrase(header_frame(123, Headers1, 4096-[]-4096-Table1, [padded(0),
                                                            end_stream(EndS),
                                                            end_headers(EndH)]),
           Bytes, Bytes1),
    maplist(ground, [Table1, Headers1, EndS, EndH]),
    Headers1 = [indexed(':method'-'GET'),
                indexed(':scheme'-'http'),
                indexed(':path'-'/'),
                literal_inc(':authority'-'www.example.com'),
                literal_never(push-'true'),
                literal_never('strict-transport-security'-'max-age=31536000 ; includeSubDomains'),
                literal_never('access-control-allow-origin'-'*')],
    EndS = true,
    EndH = false,

    phrase(continuation_frame(123, (4096-Table1-4096-Table2)-Headers2, End1),
           Bytes1, Bytes2),
    maplist(ground, [Table2, Headers2, End1]),
    End1 = false,
    Headers2 = [literal_never('access-control-allow-methods'-'GET,HEAD,POST'),
                literal_never('access-control-allow-headers'-'*')],

    phrase(continuation_frame(123, (4096-Table2-4096-Table3)-Headers3, End2),
           Bytes2, Bytes3),
    maplist(ground, [Table3, Headers3, End2]),
    End2 = false,
    Headers3 = [literal_never('access-control-max-age'-'86400'),
                literal_never('access-control-allow-credentials'-'false'),
                literal_never('protocol_negotiation'-h2)],

    phrase(continuation_frame(123, (4096-Table3-4096-Table4)-Headers4, End3),
           Bytes3),
    maplist(ground, [Table4, Headers4, End3]),
    End3 = true,
    Headers4 = [literal_never(myproto-h2),
                literal_never(rtt-'3')].


:- end_tests(frames).
