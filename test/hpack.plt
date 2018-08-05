:- module(hpack_t, []).

:- use_module(library(plunit)).
:- use_module(hpack).
:- begin_tests(hpack).

% Source:
% https://httpwg.org/specs/rfc7541.html#header.field.representation.examples

test('Literal header inc index new key') :-
    phrase(hpack:literal_header_inc_idx(4096-[]-_, 'custom-key'-'custom-header'),
           Bytes),
    hex_bytes(Hex, Bytes),
    Hex = '400a637573746f6d2d6b65790d637573746f6d2d686561646572'.

test('Parse literal header inc index new key') :-
    Hex = '400a637573746f6d2d6b65790d637573746f6d2d686561646572',
    hex_bytes(Hex, Bytes),
    phrase(hpack:literal_header_inc_idx(4096-[]-Table, Header),
           Bytes),
    Header = 'custom-key'-'custom-header',
    Table = ['custom-key'-'custom-header'].

test('Literal field w/o indexing') :-
    phrase(hpack:literal_header_wo_idx([], ':path'-'/sample/path'),
           Bytes),
    hex_bytes(Hex, Bytes),
    Hex = '040c2f73616d706c652f70617468'.

test('Parse literal field w/o indexing') :-
    Hex = '040c2f73616d706c652f70617468',
    hex_bytes(Hex, Bytes),
    phrase(hpack:literal_header_wo_idx([], Header), Bytes),
    Header = ':path'-'/sample/path'.

test('Parse literal field w/o indexing for new field') :-
    Bytes = [0,11,99,117,115,116,111,109,45,110,97,109,101,12,99,117,115,116,111,
             109,45,118,97,108,117,101],
    phrase(hpack:literal_header_wo_idx([], Header), Bytes),
    Header = 'custom-name'-'custom-value'.

test('Literal field never indexed') :-
    phrase(hpack:literal_header_never_idx([], 'password'-'secret'),
           Bytes),
    hex_bytes(Hex, Bytes),
    Hex = '100870617373776f726406736563726574'.

test('Indexed header') :-
    phrase(hpack:indexed_header([], ':method'-'GET'), Bytes),
    hex_bytes(Hex, Bytes),
    Hex = '82'.

test('Request') :-
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               indexed(':path'-'/'),
               literal_inc(':authority'-'www.example.com')],
    phrase(hpack(4096-[]-DynTable, Headers), Bytes),
    hex_bytes(Hex, Bytes),
    Hex = '828684410f7777772e6578616d706c652e636f6d',
    DynTable = [':authority'-'www.example.com'],

    Headers2 = [indexed(':method'-'GET'),
                indexed(':scheme'-'http'),
                indexed(':path'-'/'),
                indexed(':authority'-'www.example.com'),
                literal_inc('cache-control'-'no-cache')],
    phrase(hpack(4096-DynTable-DynTable2, Headers2), Bytes2),
    hex_bytes(Hex2, Bytes2),
    Hex2 = '828684be58086e6f2d6361636865',

    Headers3 = [indexed(':method'-'GET'),
                indexed(':scheme'-'https'),
                indexed(':path'-'/index.html'),
                indexed(':authority'-'www.example.com'),
                literal_inc('custom-key'-'custom-value')],
    phrase(hpack(4096-DynTable2-_, Headers3), Bytes3),
    hex_bytes(Hex3, Bytes3),
    Hex3 = '828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565'.

test('Parse request from data') :-
    Hex = '828684410f7777772e6578616d706c652e636f6d',
    hex_bytes(Hex, Bytes),
    phrase(hpack(4096-[]-DynTable, Headers), Bytes),
    Headers = [indexed(':method'-'GET'),
               indexed(':scheme'-'http'),
               indexed(':path'-'/'),
               literal_inc(':authority'-'www.example.com')],

    Hex2 = '828684be58086e6f2d6361636865',
    hex_bytes(Hex2, Bytes2),
    phrase(hpack(4096-DynTable-DynTable2, Headers2), Bytes2),
    Headers2 = [indexed(':method'-'GET'),
                indexed(':scheme'-'http'),
                indexed(':path'-'/'),
                indexed(':authority'-'www.example.com'),
                literal_inc('cache-control'-'no-cache')],

    Hex3 = '828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565',
    hex_bytes(Hex3, Bytes3),
    phrase(hpack(4096-DynTable2-_DynTable3, Headers3), Bytes3),
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
    phrase(hpack(4096-[]-Table1, Headers), Bytes), !,
    Headers = [
        indexed(':method'-'GET'),
        indexed(':scheme'-'http'),
        indexed(':path'-'/'),
        literal_inc(':authority'-'www.example.com')
    ],

    Hex2 = '828684be5886a8eb10649cbf',
    hex_bytes(Hex2, Bytes2),
    phrase(hpack(4096-Table1-Table2, Headers2), Bytes2),
    Headers2 = [
        indexed(':method'-'GET'),
        indexed(':scheme'-http),
        indexed(':path'-'/'),
        indexed(':authority'-'www.example.com'),
        literal_inc('cache-control'-'no-cache')
    ],

    Hex3 = '828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf',
    hex_bytes(Hex3, Bytes3),
    phrase(hpack(4096-Table2-_Table3, Headers3), Bytes3),
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
    phrase(hpack(256-[]-Table1, Headers1), Bytes1),
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
    phrase(hpack(256-Table1-Table2, Headers2), Bytes2),
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
    phrase(hpack(256-Table2-Table3, Headers3), Bytes3),
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
    phrase(hpack(256-[]-Table1, Headers1), Bytes1),
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
    phrase(hpack(256-Table1-Table2, Headers2), Bytes2),
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
    phrase(hpack(256-Table2-Table3, Headers3), Bytes3),
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

:- end_tests(hpack).
