:- module(hpack, [hpack//2,
                  lookup_header/3]).
/** <module> HPACK, library for parsing RFC 7541 HPACK headers

@author James Cash
*/

:- use_module(library(clpfd)).
:- use_module(library(when), [when/2]).
:- use_module(library(delay), [delay/1]).
:- use_module(library(list_util), [take/3]).

:- use_module(hpack/static_headers, [static_header/2]).
:- use_module(hpack/huffman, [atom_huffcodes/2]).

% Encoding primitives

int(Prefix, PrefixL, N) -->
    { PrefixShift #= 2^(8 - PrefixL),
      N #>= 0,
      N #< PrefixShift - 1,
      Header #= (Prefix * PrefixShift) + N,
      Header in 0..0xFF },
    [Header].
int(Prefix, PrefixL, N) -->
    { PrefixShift #= 2^(8 - PrefixL),
      N #>= (PrefixShift - 1),
      Nn #= N - (PrefixShift - 1),
      Header in 0..0xFF,
      Header #= (Prefix * PrefixShift) + (PrefixShift - 1) },
    [Header], !, int_(Nn).
int_(N) -->
    { N #< 2^8 - 1 },
    [N], !.
int_(N) -->
    { N #>= 2^8 - 1,
      LSB #= N mod 0b1000_0000,
      LSBEncode #= 0b1000_0000 + LSB,
      LSBEncode in 0..255,
      MSB #= (N - LSB) >> 7 },
    [LSBEncode], int_(MSB).

has_prefix(Prefix, PrefixL), [C] -->
    [C],
    { Prefix #= C div (2^(8 - PrefixL)) }.

str(S) --> % Literal string
    has_prefix(0, 1),
    { when(ground(S);ground(Codes), atom_codes(S, Codes)),
      delay(length(Codes, L)) },
    % parsing hufman-encoded strings gets messed up now, because L is
    % unbound, so it will just keep trying increasing values of L but
    % it will never work.
    % How do we indicate that no value of L can make this work?
    int(0, 1, L), Codes, !.
str(S) --> % Huffman-encoded string
    has_prefix(1, 1),
    { when(ground(S);ground(HuffmanCodes), atom_huffcodes(S, HuffmanCodes)),
      delay(length(HuffmanCodes, L)) },
    int(1, 1, L), HuffmanCodes.

% just for testing
huffstr(S) --> % Huffman-encoded string
    has_prefix(1, 1),
    { when(ground(S);ground(HuffmanCodes), atom_huffcodes(S, HuffmanCodes)),
      delay(length(HuffmanCodes, L)) },
    int(1, 1, L), HuffmanCodes.

% Encoding headers

indexed_header(Dt, K-V) -->
    { when(ground(K-V);ground(Idx), lookup_header(Dt, K-V, Idx)) },
    int(1, 1, Idx), !.

literal_header_inc_idx(Ts-Dt0-Dt1, K-V) -->
    { when(ground(K-V);ground(KeyIdx), lookup_header(Dt0, K-_, KeyIdx)),
      KeyIdx #> 0,
      insert_header(Ts, Dt0, K-V, Dt1) },
    int(1, 2, KeyIdx), str(V), !.
literal_header_inc_idx(Ts-Dt0-Dt1, K-V) -->
    { insert_header(Ts, Dt0, K-V, Dt1) },
    int(1, 2, 0), str(K), str(V), !.

literal_header_wo_idx(Dt, K-V) -->
    { when(ground(K-V);ground(KeyIdx), lookup_header(Dt, K-_, KeyIdx)),
      KeyIdx #> 0 },
    int(0, 4, KeyIdx), str(V), !.
literal_header_wo_idx(_, K-V) -->
    int(0, 4, 0), str(K), str(V), !.

literal_header_never_idx(Dt, K-V) -->
    { when(ground(K-V);ground(KeyIdx), lookup_header(Dt, K-_, KeyIdx)) },
    int(1, 4, KeyIdx), str(V), !.
literal_header_never_idx(_, K-V) -->
    int(1, 4, 0), str(K), str(V), !.

% Header lookups

lookup_header(_Dt, KV, Idx) :-
    static_header(Idx, KV).
lookup_header(Dt, KV, Idx) :-
    DIdx #= Idx - 61,
    nth1(DIdx, Dt, KV), !.

insert_header(MaxSize, Dt0, K-V, Dt1) :-
    when(ground(K-V),
         keep_fitting(MaxSize, [K-V|Dt0], Dt1)).

keep_fitting(Max, Lst, Fitting) :-
    keep_fitting(Max, 0, Lst, Fitting).
keep_fitting(_, _, [], []).
keep_fitting(Max, Cur, [K-V|Rst], [K-V|FitRest]) :-
    write_length(K, Kl, []), write_length(V, Vl, []),
    S #= Kl + Vl + 32, % "size" = # of bytes + 32 for some reason
    NewCur #= Cur + S,
    NewCur #=< Max,
    keep_fitting(Max, NewCur, Rst, FitRest).
keep_fitting(_, _, _, []).

dynamic_size_update(DT0-DT1, NewSize) -->
    { take(NewSize, DT0, DT1) },
    int(1, 3, NewSize).

header(_-DT0-DT0, indexed(H)) --> indexed_header(DT0, H).
header(Ts-DT0-DT1, literal_inc(H)) --> literal_header_inc_idx(Ts-DT0-DT1, H).
header(_-DT0-DT0, literal_without(H)) --> literal_header_wo_idx(DT0, H).
header(_-DT0-DT0, literal_never(H)) --> literal_header_never_idx(DT0, H).

%! hpack(?Tables, ?Headers:list)//
%  DCG for recognizing an HPACK header.
%
%  @arg Tables =| = TableSize-InTable-OutTable|=
%        =TableSize= is the maximum size of the dynamic table, =InTable= is
%        the dynamic table before recognizing =Headers= and =OutTable= is
%        the dynamic table after.
%  @arg Headers the list of HTTP headers.
%        Headers are in the format =|Type(Name-Value)|=, where =Type= is
%        one of =indexed=, =literal_inc=, =literal_without=, and
%        =literal_never=, depending on how the header is to be indexed.
%  @see https://httpwg.org/specs/rfc7541.html
%  @tbd Make headers more ergonomic -- maybe not wrapped in a functor
%        indicating the mode, but not sure how else to allow control of
%        what's indexed & what isn't?
hpack(Ts-DT0-DTn, [Header|Headers]) -->
    header(Ts-DT0-DT1, Header), !, hpack(Ts-DT1-DTn, Headers).
hpack(_-DT0-DT0, []) --> [].
