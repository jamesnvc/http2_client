:- module(huffman, [atom_huffcodes/2]).
/** <module> hpack/huffman, HPACK's implementation of Huffman encoding

@author James Cash
*/

:- use_module(library(clpfd)).
:- use_module(library(delay), [delay/1]).

%! atom_huffcodes(?Atom, ?Codes) is det.
%  True when =Atom= Huffman-encodes to =Codes=.
atom_huffcodes(Atom, HuffCodes) :-
    atom(Atom), !,
    atom_codes(Atom, Codes),
    maplist(huff_sym_code, Codes, HuffCodes_, Lens),
    sum_symbol_codes(Combined_, HuffCodes_, Lens),
    sumlist(Lens, TotalLen),
    padded(Combined_, TotalLen, Combined),
    once(bytes_sum(HuffCodes, Combined)).
atom_huffcodes(Atom, HuffCodes) :-
    ground(HuffCodes), !,
    bytes_sum(HuffCodes, Combined),
    length(HuffCodes, CodesL),
    BitLen #= CodesL * 8,
    decoded(Combined, BitLen, Codes),
    atom_codes(Atom, Codes).

% if I was smarter, I'd combine these two different approachs for
% encoding versus decoding...

% helper for huffman decoding

decoded(N, BitL, [C|Cs]) :-
    huff_sym_code(C, NCode, CodeBits),
    NCode #= N >> (BitL - CodeBits),
    N1 #= N mod (2^(BitL - CodeBits)),
    BitL1 #= BitL - CodeBits,
    decoded(N1, BitL1, Cs).
decoded(_, _, []).

% helpers for huffman encoding

%! bytes_sum(+Bytes:list, -N:integer) is det.
%! bytes_sum(-Bytes:list, +N:integer) is multi.
%  True when =Bytes= is big-endian representation of the integer =N=.
bytes_sum(Bs, N) :- bytes_sum(Bs, 0, N).
bytes_sum([], N, N).
bytes_sum([B|Bs], N0, N2) :-
    B in 0..255,
    N1 #= (N0 * 256) + B,
    bytes_sum(Bs, N1, N2).

%! sum_symbol_codes(-N:integer, +HuffCodes:list, +CodeLengths:list) is det.
%  True when =N= is a number representing the bitwise concatenation of
%  the numbers in the list =HuffCodes=, where the bit length of nth
%  member of =Codes= is given by the nth member of =CodeLengths=.
sum_symbol_codes(N, Cs, Lens) :-
    sum_symbol_codes(0, N, Cs, Lens).
sum_symbol_codes(N, N, [], []).
sum_symbol_codes(N0, N2, [C|Cs], [Len|Lens]) :-
    N1 #= (N0 * 2^Len) + C,
    sum_symbol_codes(N1, N2, Cs, Lens).

%! padded(+N:integer, +Len:integer, -M:integer) is det.
%  True when =M= is the =Len=-bits number =N= padded on the right with
%  1 bits to make the bit length a multiple of 8.
padded(N, Len, N) :-
    Len mod 8 #= 0, !.
padded(N, Len, M) :-
    Bits #= 8 - (Len mod 8),
    M #= (N << Bits) + (2^Bits - 1).

% Huffman symbol table:

%! huf_sym_code(?Symbol, ?Code, ?CodeLen) is det.
%  True when the byte =Symbol= is Huffman-encoded to the
%  =CodeLen=-bits number =Code=.
huff_sym_code(  0, 0x1ff8, 13).
huff_sym_code(  1, 0x7fffd8, 23).
huff_sym_code(  2, 0xfffffe2, 28).
huff_sym_code(  3, 0xfffffe3, 28).
huff_sym_code(  4, 0xfffffe4, 28).
huff_sym_code(  5, 0xfffffe5, 28).
huff_sym_code(  6, 0xfffffe6, 28).
huff_sym_code(  7, 0xfffffe7, 28).
huff_sym_code(  8, 0xfffffe8, 28).
huff_sym_code(  9, 0xffffea, 24).
huff_sym_code( 10, 0x3ffffffc, 30).
huff_sym_code( 11, 0xfffffe9, 28).
huff_sym_code( 12, 0xfffffea, 28).
huff_sym_code( 13, 0x3ffffffd, 30).
huff_sym_code( 14, 0xfffffeb, 28).
huff_sym_code( 15, 0xfffffec, 28).
huff_sym_code( 16, 0xfffffed, 28).
huff_sym_code( 17, 0xfffffee, 28).
huff_sym_code( 18, 0xfffffef, 28).
huff_sym_code( 19, 0xffffff0, 28).
huff_sym_code( 20, 0xffffff1, 28).
huff_sym_code( 21, 0xffffff2, 28).
huff_sym_code( 22, 0x3ffffffe, 30).
huff_sym_code( 23, 0xffffff3, 28).
huff_sym_code( 24, 0xffffff4, 28).
huff_sym_code( 25, 0xffffff5, 28).
huff_sym_code( 26, 0xffffff6, 28).
huff_sym_code( 27, 0xffffff7, 28).
huff_sym_code( 28, 0xffffff8, 28).
huff_sym_code( 29, 0xffffff9, 28).
huff_sym_code( 30, 0xffffffa, 28).
huff_sym_code( 31, 0xffffffb, 28).
huff_sym_code( 32, 0x14,  6).
huff_sym_code( 33, 0x3f8, 10).
huff_sym_code( 34, 0x3f9, 10).
huff_sym_code( 35, 0xffa, 12).
huff_sym_code( 36, 0x1ff9, 13).
huff_sym_code( 37, 0x15,  6).
huff_sym_code( 38, 0xf8,  8).
huff_sym_code( 39, 0x7fa, 11).
huff_sym_code( 40, 0x3fa, 10).
huff_sym_code( 41, 0x3fb, 10).
huff_sym_code( 42, 0xf9,  8).
huff_sym_code( 43, 0x7fb, 11).
huff_sym_code( 44, 0xfa,  8).
huff_sym_code( 45, 0x16,  6).
huff_sym_code( 46, 0x17,  6).
huff_sym_code( 47, 0x18,  6).
huff_sym_code( 48, 0x0,  5).
huff_sym_code( 49, 0x1,  5).
huff_sym_code( 50, 0x2,  5).
huff_sym_code( 51, 0x19,  6).
huff_sym_code( 52, 0x1a,  6).
huff_sym_code( 53, 0x1b,  6).
huff_sym_code( 54, 0x1c,  6).
huff_sym_code( 55, 0x1d,  6).
huff_sym_code( 56, 0x1e,  6).
huff_sym_code( 57, 0x1f,  6).
huff_sym_code( 58, 0x5c,  7).
huff_sym_code( 59, 0xfb,  8).
huff_sym_code( 60, 0x7ffc, 15).
huff_sym_code( 61, 0x20,  6).
huff_sym_code( 62, 0xffb, 12).
huff_sym_code( 63, 0x3fc, 10).
huff_sym_code( 64, 0x1ffa, 13).
huff_sym_code( 65, 0x21,  6).
huff_sym_code( 66, 0x5d,  7).
huff_sym_code( 67, 0x5e,  7).
huff_sym_code( 68, 0x5f,  7).
huff_sym_code( 69, 0x60,  7).
huff_sym_code( 70, 0x61,  7).
huff_sym_code( 71, 0x62,  7).
huff_sym_code( 72, 0x63,  7).
huff_sym_code( 73, 0x64,  7).
huff_sym_code( 74, 0x65,  7).
huff_sym_code( 75, 0x66,  7).
huff_sym_code( 76, 0x67,  7).
huff_sym_code( 77, 0x68,  7).
huff_sym_code( 78, 0x69,  7).
huff_sym_code( 79, 0x6a,  7).
huff_sym_code( 80, 0x6b,  7).
huff_sym_code( 81, 0x6c,  7).
huff_sym_code( 82, 0x6d,  7).
huff_sym_code( 83, 0x6e,  7).
huff_sym_code( 84, 0x6f,  7).
huff_sym_code( 85, 0x70,  7).
huff_sym_code( 86, 0x71,  7).
huff_sym_code( 87, 0x72,  7).
huff_sym_code( 88, 0xfc,  8).
huff_sym_code( 89, 0x73,  7).
huff_sym_code( 90, 0xfd,  8).
huff_sym_code( 91, 0x1ffb, 13).
huff_sym_code( 92, 0x7fff0, 19).
huff_sym_code( 93, 0x1ffc, 13).
huff_sym_code( 94, 0x3ffc, 14).
huff_sym_code( 95, 0x22,  6).
huff_sym_code( 96, 0x7ffd, 15).
huff_sym_code( 97, 0x3,  5).
huff_sym_code( 98, 0x23,  6).
huff_sym_code( 99, 0x4,  5).
huff_sym_code(100, 0x24,  6).
huff_sym_code(101, 0x5,  5).
huff_sym_code(102, 0x25,  6).
huff_sym_code(103, 0x26,  6).
huff_sym_code(104, 0x27,  6).
huff_sym_code(105, 0x6,  5).
huff_sym_code(106, 0x74,  7).
huff_sym_code(107, 0x75,  7).
huff_sym_code(108, 0x28,  6).
huff_sym_code(109, 0x29,  6).
huff_sym_code(110, 0x2a,  6).
huff_sym_code(111, 0x7,  5).
huff_sym_code(112, 0x2b,  6).
huff_sym_code(113, 0x76,  7).
huff_sym_code(114, 0x2c,  6).
huff_sym_code(115, 0x8,  5).
huff_sym_code(116, 0x9,  5).
huff_sym_code(117, 0x2d,  6).
huff_sym_code(118, 0x77,  7).
huff_sym_code(119, 0x78,  7).
huff_sym_code(120, 0x79,  7).
huff_sym_code(121, 0x7a,  7).
huff_sym_code(122, 0x7b,  7).
huff_sym_code(123, 0x7ffe, 15).
huff_sym_code(124, 0x7fc, 11).
huff_sym_code(125, 0x3ffd, 14).
huff_sym_code(126, 0x1ffd, 13).
huff_sym_code(127, 0xffffffc, 28).
huff_sym_code(128, 0xfffe6, 20).
huff_sym_code(129, 0x3fffd2, 22).
huff_sym_code(130, 0xfffe7, 20).
huff_sym_code(131, 0xfffe8, 20).
huff_sym_code(132, 0x3fffd3, 22).
huff_sym_code(133, 0x3fffd4, 22).
huff_sym_code(134, 0x3fffd5, 22).
huff_sym_code(135, 0x7fffd9, 23).
huff_sym_code(136, 0x3fffd6, 22).
huff_sym_code(137, 0x7fffda, 23).
huff_sym_code(138, 0x7fffdb, 23).
huff_sym_code(139, 0x7fffdc, 23).
huff_sym_code(140, 0x7fffdd, 23).
huff_sym_code(141, 0x7fffde, 23).
huff_sym_code(142, 0xffffeb, 24).
huff_sym_code(143, 0x7fffdf, 23).
huff_sym_code(144, 0xffffec, 24).
huff_sym_code(145, 0xffffed, 24).
huff_sym_code(146, 0x3fffd7, 22).
huff_sym_code(147, 0x7fffe0, 23).
huff_sym_code(148, 0xffffee, 24).
huff_sym_code(149, 0x7fffe1, 23).
huff_sym_code(150, 0x7fffe2, 23).
huff_sym_code(151, 0x7fffe3, 23).
huff_sym_code(152, 0x7fffe4, 23).
huff_sym_code(153, 0x1fffdc, 21).
huff_sym_code(154, 0x3fffd8, 22).
huff_sym_code(155, 0x7fffe5, 23).
huff_sym_code(156, 0x3fffd9, 22).
huff_sym_code(157, 0x7fffe6, 23).
huff_sym_code(158, 0x7fffe7, 23).
huff_sym_code(159, 0xffffef, 24).
huff_sym_code(160, 0x3fffda, 22).
huff_sym_code(161, 0x1fffdd, 21).
huff_sym_code(162, 0xfffe9, 20).
huff_sym_code(163, 0x3fffdb, 22).
huff_sym_code(164, 0x3fffdc, 22).
huff_sym_code(165, 0x7fffe8, 23).
huff_sym_code(166, 0x7fffe9, 23).
huff_sym_code(167, 0x1fffde, 21).
huff_sym_code(168, 0x7fffea, 23).
huff_sym_code(169, 0x3fffdd, 22).
huff_sym_code(170, 0x3fffde, 22).
huff_sym_code(171, 0xfffff0, 24).
huff_sym_code(172, 0x1fffdf, 21).
huff_sym_code(173, 0x3fffdf, 22).
huff_sym_code(174, 0x7fffeb, 23).
huff_sym_code(175, 0x7fffec, 23).
huff_sym_code(176, 0x1fffe0, 21).
huff_sym_code(177, 0x1fffe1, 21).
huff_sym_code(178, 0x3fffe0, 22).
huff_sym_code(179, 0x1fffe2, 21).
huff_sym_code(180, 0x7fffed, 23).
huff_sym_code(181, 0x3fffe1, 22).
huff_sym_code(182, 0x7fffee, 23).
huff_sym_code(183, 0x7fffef, 23).
huff_sym_code(184, 0xfffea, 20).
huff_sym_code(185, 0x3fffe2, 22).
huff_sym_code(186, 0x3fffe3, 22).
huff_sym_code(187, 0x3fffe4, 22).
huff_sym_code(188, 0x7ffff0, 23).
huff_sym_code(189, 0x3fffe5, 22).
huff_sym_code(190, 0x3fffe6, 22).
huff_sym_code(191, 0x7ffff1, 23).
huff_sym_code(192, 0x3ffffe0, 26).
huff_sym_code(193, 0x3ffffe1, 26).
huff_sym_code(194, 0xfffeb, 20).
huff_sym_code(195, 0x7fff1, 19).
huff_sym_code(196, 0x3fffe7, 22).
huff_sym_code(197, 0x7ffff2, 23).
huff_sym_code(198, 0x3fffe8, 22).
huff_sym_code(199, 0x1ffffec, 25).
huff_sym_code(200, 0x3ffffe2, 26).
huff_sym_code(201, 0x3ffffe3, 26).
huff_sym_code(202, 0x3ffffe4, 26).
huff_sym_code(203, 0x7ffffde, 27).
huff_sym_code(204, 0x7ffffdf, 27).
huff_sym_code(205, 0x3ffffe5, 26).
huff_sym_code(206, 0xfffff1, 24).
huff_sym_code(207, 0x1ffffed, 25).
huff_sym_code(208, 0x7fff2, 19).
huff_sym_code(209, 0x1fffe3, 21).
huff_sym_code(210, 0x3ffffe6, 26).
huff_sym_code(211, 0x7ffffe0, 27).
huff_sym_code(212, 0x7ffffe1, 27).
huff_sym_code(213, 0x3ffffe7, 26).
huff_sym_code(214, 0x7ffffe2, 27).
huff_sym_code(215, 0xfffff2, 24).
huff_sym_code(216, 0x1fffe4, 21).
huff_sym_code(217, 0x1fffe5, 21).
huff_sym_code(218, 0x3ffffe8, 26).
huff_sym_code(219, 0x3ffffe9, 26).
huff_sym_code(220, 0xffffffd, 28).
huff_sym_code(221, 0x7ffffe3, 27).
huff_sym_code(222, 0x7ffffe4, 27).
huff_sym_code(223, 0x7ffffe5, 27).
huff_sym_code(224, 0xfffec, 20).
huff_sym_code(225, 0xfffff3, 24).
huff_sym_code(226, 0xfffed, 20).
huff_sym_code(227, 0x1fffe6, 21).
huff_sym_code(228, 0x3fffe9, 22).
huff_sym_code(229, 0x1fffe7, 21).
huff_sym_code(230, 0x1fffe8, 21).
huff_sym_code(231, 0x7ffff3, 23).
huff_sym_code(232, 0x3fffea, 22).
huff_sym_code(233, 0x3fffeb, 22).
huff_sym_code(234, 0x1ffffee, 25).
huff_sym_code(235, 0x1ffffef, 25).
huff_sym_code(236, 0xfffff4, 24).
huff_sym_code(237, 0xfffff5, 24).
huff_sym_code(238, 0x3ffffea, 26).
huff_sym_code(239, 0x7ffff4, 23).
huff_sym_code(240, 0x3ffffeb, 26).
huff_sym_code(241, 0x7ffffe6, 27).
huff_sym_code(242, 0x3ffffec, 26).
huff_sym_code(243, 0x3ffffed, 26).
huff_sym_code(244, 0x7ffffe7, 27).
huff_sym_code(245, 0x7ffffe8, 27).
huff_sym_code(246, 0x7ffffe9, 27).
huff_sym_code(247, 0x7ffffea, 27).
huff_sym_code(248, 0x7ffffeb, 27).
huff_sym_code(249, 0xffffffe, 28).
huff_sym_code(250, 0x7ffffec, 27).
huff_sym_code(251, 0x7ffffed, 27).
huff_sym_code(252, 0x7ffffee, 27).
huff_sym_code(253, 0x7ffffef, 27).
huff_sym_code(254, 0x7fffff0, 27).
huff_sym_code(255, 0x3ffffee, 26).
