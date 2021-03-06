:- module(hpack_t, []).

:- use_module(library(plunit)).
:- use_module(hpack).
:- begin_tests(hpack).

% Source:
% https://httpwg.org/specs/rfc7541.html#header.field.representation.examples

test('Literal header inc index new key') :-
    phrase(hpack:literal_header_inc_idx('custom-key'-'custom-header', 4096, _, [], _),
           Bytes),
    ground(Bytes),
    hex_bytes(Hex, Bytes),
    Hex = '400a637573746f6d2d6b65790d637573746f6d2d686561646572'.

test('Parse literal header inc index new key') :-
    Hex = '400a637573746f6d2d6b65790d637573746f6d2d686561646572',
    hex_bytes(Hex, Bytes),
    phrase(hpack:literal_header_inc_idx(Header, 4096, _, [], Table),
           Bytes),
    ground(Header), ground(Table),
    Header = 'custom-key'-'custom-header',
    Table = ['custom-key'-'custom-header'].

test('Literal field w/o indexing') :-
    phrase(hpack:literal_header_wo_idx(':path'-'/sample/path', []),
           Bytes),
    hex_bytes(Hex, Bytes),
    Hex = '040c2f73616d706c652f70617468'.

test('Parse literal field w/o indexing') :-
    Hex = '040c2f73616d706c652f70617468',
    hex_bytes(Hex, Bytes),
    phrase(hpack:literal_header_wo_idx(Header, []), Bytes),
    Header = ':path'-'/sample/path'.

test('Parse literal field w/o indexing for new field') :-
    Bytes = [0,11,99,117,115,116,111,109,45,110,97,109,101,12,99,117,115,116,111,
             109,45,118,97,108,117,101],
    phrase(hpack:literal_header_wo_idx(Header, []), Bytes),
    Header = 'custom-name'-'custom-value'.

test('Literal field never indexed') :-
    phrase(hpack:literal_header_never_idx('password'-'secret', []),
           Bytes),
    hex_bytes(Hex, Bytes),
    Hex = '100870617373776f726406736563726574'.

test('Indexed header') :-
    phrase(hpack:indexed_header(':method'-'GET', []), Bytes),
    hex_bytes(Hex, Bytes),
    Hex = '82'.

test('Request') :-
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               indexed(':path'-'/'),
               literal_inc(':authority'-'www.example.com')],
    phrase(hpack(Headers, 4096, _, [], DynTable), Bytes),
    hex_bytes(Hex, Bytes),
    Hex = '828684410f7777772e6578616d706c652e636f6d',
    DynTable = [':authority'-'www.example.com'],

    Headers2 = [indexed(':method'-'GET'),
                indexed(':scheme'-'http'),
                indexed(':path'-'/'),
                indexed(':authority'-'www.example.com'),
                literal_inc('cache-control'-'no-cache')],
    phrase(hpack(Headers2, 4096, _, DynTable, DynTable2), Bytes2),
    hex_bytes(Hex2, Bytes2),
    Hex2 = '828684be58086e6f2d6361636865',

    Headers3 = [indexed(':method'-'GET'),
                indexed(':scheme'-'https'),
                indexed(':path'-'/index.html'),
                indexed(':authority'-'www.example.com'),
                literal_inc('custom-key'-'custom-value')],
    phrase(hpack(Headers3, 4096, _, DynTable2, _), Bytes3),
    hex_bytes(Hex3, Bytes3),
    Hex3 = '828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565'.

test('Parse request from data') :-
    Hex = '828684410f7777772e6578616d706c652e636f6d',
    hex_bytes(Hex, Bytes),
    phrase(hpack(Headers, 4096, _, [], DynTable), Bytes),
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               indexed(':path'-'/'),
               literal_inc(':authority'-'www.example.com')],

    Hex2 = '828684be58086e6f2d6361636865',
    hex_bytes(Hex2, Bytes2),
    phrase(hpack(Headers2, 4096, _, DynTable, DynTable2), Bytes2),
    Headers2 = [indexed(':method'-'GET'),
                indexed(':scheme'-'http'),
                indexed(':path'-'/'),
                indexed(':authority'-'www.example.com'),
                literal_inc('cache-control'-'no-cache')],

    Hex3 = '828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565',
    hex_bytes(Hex3, Bytes3),
    phrase(hpack(Headers3, 4096, _, DynTable2, _DynTable3), Bytes3),
    Headers3 = [indexed(':method'-'GET'),
                indexed(':scheme'-'https'),
                indexed(':path'-'/index.html'),
                indexed(':authority'-'www.example.com'),
                literal_inc('custom-key'-'custom-value')].

test('Huffman encode atom') :-
    phrase(hpack:huffstr('www.example.com'), HuffCodes), !,
    hex_bytes(Hex, HuffCodes),
    Hex = '8cf1e3c2e5f23a6ba0ab90f4ff'.

test('Huffman decode atom') :-
    Hex = '8cf1e3c2e5f23a6ba0ab90f4ff',
    hex_bytes(Hex, HuffCodes),
    phrase(hpack:str(S), HuffCodes), !,
    S = 'www.example.com'.

test('Huff decode') :-
    Hex = '828684418cf1e3c2e5f23a6ba0ab90f4ff',
    hex_bytes(Hex, Bytes),
    phrase(hpack(Headers, 4096, _, [], Table1), Bytes), !,
    Headers = [
        indexed(':method'-'GET'),
        indexed(':scheme'-'http'),
        indexed(':path'-'/'),
        literal_inc(':authority'-'www.example.com')
    ],

    Hex2 = '828684be5886a8eb10649cbf',
    hex_bytes(Hex2, Bytes2),
    phrase(hpack(Headers2, 4096, _, Table1, Table2), Bytes2),
    Headers2 = [
        indexed(':method'-'GET'),
        indexed(':scheme'-http),
        indexed(':path'-'/'),
        indexed(':authority'-'www.example.com'),
        literal_inc('cache-control'-'no-cache')
    ],

    Hex3 = '828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf',
    hex_bytes(Hex3, Bytes3),
    phrase(hpack(Headers3, 4096, _, Table2, _Table3), Bytes3),
    Headers3 = [
        indexed(':method'-'GET'),
        indexed(':scheme'-https),
        indexed(':path'-'/index.html'),
        indexed(':authority'-'www.example.com'),
        literal_inc('custom-key'-'custom-value')
    ].

test('Decoding responses') :-
    Hex1 = '4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d',
    hex_bytes(Hex1, Bytes1),
    phrase(hpack(Headers1, 256, _, [], Table1), Bytes1),
    Headers1 = [
        literal_inc(':status'-'302'),
        literal_inc('cache-control'-'private'),
        literal_inc('date'-'Mon, 21 Oct 2013 20:13:21 GMT'),
        literal_inc('location'-'https://www.example.com')
    ],
    Table1 = ['location'-'https://www.example.com',
              'date'-'Mon, 21 Oct 2013 20:13:21 GMT',
              'cache-control'-'private',
              ':status'-'302'],

    Hex2 = '4803333037c1c0bf',
    hex_bytes(Hex2, Bytes2),
    phrase(hpack(Headers2, 256, _, Table1, Table2), Bytes2),
    Headers2 = [
        literal_inc(':status'-'307'),
        indexed('cache-control'-'private'),
        indexed('date'-'Mon, 21 Oct 2013 20:13:21 GMT'),
        indexed('location'-'https://www.example.com')
    ],
    Table2 = [':status'-'307',
              'location'-'https://www.example.com',
              'date'-'Mon, 21 Oct 2013 20:13:21 GMT',
              'cache-control'-'private'],

    Hex3 = '88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31',
    hex_bytes(Hex3, Bytes3),
    phrase(hpack(Headers3, 256, _, Table2, Table3), Bytes3),
    Headers3 = [
        indexed(':status'-'200'),
        indexed('cache-control'-'private'),
        literal_inc('date'-'Mon, 21 Oct 2013 20:13:22 GMT'),
        indexed('location'-'https://www.example.com'),
        literal_inc('content-encoding'-gzip),
        literal_inc('set-cookie'-'foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1')
    ],
    Table3 = [
        'set-cookie'-'foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1',
        'content-encoding'-gzip,
        'date'-'Mon, 21 Oct 2013 20:13:22 GMT'].

test('Decoding response with Huffman') :-
    Hex1 = '488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3',
    hex_bytes(Hex1, Bytes1),
    phrase(hpack(Headers1, 256, _, [], Table1), Bytes1),
    Headers1 = [
        literal_inc(':status'-'302'),
        literal_inc('cache-control'-private),
        literal_inc(date-'Mon, 21 Oct 2013 20:13:21 GMT'),
        literal_inc(location-'https://www.example.com')
    ],
    Table1 = [
        location-'https://www.example.com',
        date-'Mon, 21 Oct 2013 20:13:21 GMT',
        'cache-control'-private,
        ':status'-'302'
    ],

    Hex2 = '4883640effc1c0bf',
    hex_bytes(Hex2, Bytes2),
    phrase(hpack(Headers2, 256, _, Table1, Table2), Bytes2),
    Headers2 = [
        literal_inc(':status'-'307'),
        indexed('cache-control'-private),
        indexed(date-'Mon, 21 Oct 2013 20:13:21 GMT'),
        indexed(location-'https://www.example.com')
    ],
    Table2 = [
        ':status'-'307',
        location-'https://www.example.com',
        date-'Mon, 21 Oct 2013 20:13:21 GMT',
        'cache-control'-private
    ],

    Hex3 = '88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007',
    hex_bytes(Hex3, Bytes3),
    phrase(hpack(Headers3, 256, _, Table2, Table3), Bytes3),
    Headers3 = [
        indexed(':status'-'200'),
        indexed('cache-control'-private),
        literal_inc(date-'Mon, 21 Oct 2013 20:13:22 GMT'),
        indexed('location'-'https://www.example.com'),
        literal_inc('content-encoding'-gzip),
        literal_inc('set-cookie'-'foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1')
    ],
    Table3 = [
        'set-cookie'-'foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1',
        'content-encoding'-gzip,
        date-'Mon, 21 Oct 2013 20:13:22 GMT'
    ].

test('Request with without indexed headers') :-
    Headers = [literal_without(':path'-'/sample/path')],
    phrase(hpack(Headers, 4096, _, [], Out), Bytes),
    ground(Out), ground(Bytes),
    Out = [],
    hex_bytes(Hex, Bytes),
    Hex='040c2f73616d706c652f70617468'.

test('Request with without indexed headers unpack') :-
    Hex='040c2f73616d706c652f70617468',
    hex_bytes(Hex, Bytes),
    phrase(hpack(Headers, 4096, _, [], Out), Bytes),
    ground(Out), ground(Headers),
    Out = [],
    Headers = [literal_without(':path'-'/sample/path')].

test('Can encode dynamic change of the header table size') :-
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               size_update(256),
               indexed(':path'-'/'),
               literal_inc(':authority'-'www.example.com')],
    phrase(hpack(Headers, 0, Size, [], DynTable), Bytes),
    hex_bytes(Hex, Bytes),
    Hex = '82863fe184410f7777772e6578616d706c652e636f6d',
    DynTable = [':authority'-'www.example.com'],
    Size = 256.

test('Can decode dynamic change of the header table size') :-
    Hex = '82863fe184410f7777772e6578616d706c652e636f6d',
    hex_bytes(Hex, Bytes),
    phrase(hpack(Headers, 0, Size, [], DynTable), Bytes),
    ground(Headers), ground(DynTable), ground(Size),
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               size_update(256),
               indexed(':path'-'/'),
               literal_inc(':authority'-'www.example.com')],
    DynTable = [':authority'-'www.example.com'],
    Size = 256.

test('can generate hpack with a maximum length') :-
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               size_update(256),
               indexed(':path'-'/'),
               literal_inc(':authority'-'www.example.com')],
    phrase(hpack:hpack_max(5, Headers, 0-[]-Size-Table, Leftover, 0),
           Bytes),
    Bytes = [130, 134, 63, 225, 132],
    Leftover = [literal_inc(':authority'-'www.example.com')],
    Size = 256, Table = [].

test('can generate hpack with a maximum length 2') :-
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               size_update(256),
               indexed(':path'-'/'),
               literal_inc(':authority'-'www.example.com')],
    phrase(hpack:hpack_max(200, Headers, 0-[]-Size-Table, Leftover, 0),
           Bytes),
    Bytes = [130,134,63,225,132,65,15,119,119,119,46,101,120,97,109,112,108,101,46,99,111,109],
    Leftover = [],
    Size = 256, Table = [':authority'-'www.example.com'].

:- end_tests(hpack).
