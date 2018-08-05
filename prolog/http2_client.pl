:- module(http2_client, [http2_open/3]).
/** <module> HTTP/2 client

@author James Cash
*/

:- use_module(library(clpfd)).
:- use_module(library(record)).
:- use_module(library(predicate_options)).
:- use_module(library(delay), [delay/1]).
:- use_module(library(list_util), [replicate/3]).
:- use_module(hpack, [hpack//2]).
:- use_module(reif).

int16(I) -->
    { [A, B] ins 0..255,
      I #= A * (2^8) + B },
    [A, B].

int24(I) -->
    { [A, B, C] ins 0..255,
      I #= A * (2^16) + B * (2^8) + C },
    [A, B, C].

int32(I) -->
    { [A, B, C, D] ins 0..255,
      I #= A * (2^24) + B * (2^16) + C * (2^8) + D },
    [A, B, C, D].

/*
 +-----------------------------------------------+
 |                 Length (24)                   |
 +---------------+---------------+---------------+
 |   Type (8)    |   Flags (8)   |
 +-+-------------+---------------+-------------------------------+
 |R|                 Stream Identifier (31)                      |
 +=+=============================================================+
 |                   Frame Payload (0...)                      ...
 +---------------------------------------------------------------+
*/
frame(Type, Flags, Ident, Payload) -->
    { delay(length(Payload, Length)),
      [Type, Flags] ins 0..255,
      IdentMax #= 2^32 - 1, % high bit is reserved
      Ident in 0..IdentMax },
    int24(Length),
    [Type, Flags],
    int32(Ident),
    Payload.

% https://httpwg.org/specs/rfc7540.html#FrameTypes
% TODO: need to ensure that each frame is less than
% SETTINGS_MAX_FRAME_SIZE
% (default 2^14 octets)

:- record data_opts(padded=0, end_stream=false).
:- predicate_options(data_frame//3, 3, [padded(integer),
                                        end_stream(boolean)]).
%! data_frame(?StreamIdent:integer, ?Data:list, ?Opts)//
%  DCG for an HTTP/2 data frame
%
%  Options:
%   * padded(PadLength)
%     If non-zero, the stream will be padded with that many zero bytes.
%   * end_stream(End)
%     If =true=, this frame indicates the end of the stream
data_frame(StreamIdent, Data, Options) -->
    { make_data_opts(Options, Opts),

      StreamIdent #> 0,

      delay(length(Data, DataLength)),
      data_opts_padded(Opts, PadLen),
      zcompare(Comp, PadLen, 0),
      if_(Comp = (=),
          (PadFlag = 0x0,
           Length #= DataLength,
           PadLenBytes = [], PadBytes = []),
          (PadFlag = 0x8,
           PadLenBytes = [PadLen],
           replicate(PadLen, 0, PadBytes),
           Length #= PadLen + DataLength + 1)),

      % need to check this after, so on backtracking we can flip this
      % boolean instead of trying all possible lengths
      data_opts_end_stream(Opts, StreamEnd),
      if_(StreamEnd = true, EndFlag #= 0x1, EndFlag #= 0x0),

      Flags #= EndFlag \/ PadFlag },
    int24(Length), [0x0, Flags], int32(StreamIdent),
    PadLenBytes, Data, PadBytes, !.

:- record header_opts(end_stream=false,
                      end_headers=true,
                      padded=0,
                      priority=false).
:- predicate_options(header_frame//3, 3,
                     [end_stream(boolean),
                      end_headers(boolean),
                      padded(integer),
                      priority(boolean)]).

%! header_frame(?StreamIdent:integer, ?Headers:list, ?TableSizeInOut, ?Opts)//
%  DCG for an HTTP/2 header frame.
%  =|TableSizeInOut|= is the header table configuration
%  information that is passed to the hpack:hpack//2 DCG.
%
%  Options:
%
%   * padded(PadLength)
%     If non-zero, the stream will be padded with that many zero bytes.
%   * end_stream(EndStream)
%     If true, this frame indicates the end of the stream
%   * end_headers(End)
%     If true, this frame indicates the end of the headers
%
%  @see hpack:hpack//2
%  @tbd Support for stream-priority flag
%  @tbd Headers need to fit in a particular size, or needs to use
%        CONTINUATION frames.
header_frame(StreamIdent, Headers, Size-Table0-Table1, Options) -->
    { make_header_opts(Options, Opts),
      header_opts_padded(Opts, PadLen),
      header_opts_end_stream(Opts, EndStream),
      % XXX: Not supporting steam priority for now
      header_opts_priority(Opts, IsPriority), IsPriority = false,
      header_opts_end_headers(Opts, EndHeaders),

      % dumb that we have to call phrase/2 inside a DCG, but we need
      % to know the length of the output & I'm not sure how else to do
      % this
      when(nonvar(Headers);ground(Data),
           phrase(hpack(Size-Table0-Table1, Headers), Data)),

      delay(length(Data, DataLength)),
      zcompare(Comp, PadLen, 0),
      if_(Comp = (=),
          (PadFlag = 0x0,
           Length #= DataLength,
           PadLenBytes = [], PadBytes = []),
          (PadFlag = 0x8,
           PadLenBytes = [PadLen],
           replicate(PadLen, 0, PadBytes),
           Length #= PadLen + DataLength + 1)),

      if_(EndStream = true, EndStreamFlag #= 0x1, EndStreamFlag #= 0),
      if_(EndHeaders = true, EndHeadersFlag #= 0x4, EndHeadersFlag #= 0),
      if_(IsPriority = true, IsPriorityFlag #= 0x20, IsPriorityFlag #= 0),

      Flags #= EndStreamFlag \/ EndHeadersFlag \/ IsPriorityFlag \/ PadFlag },
    int24(Length), [0x1, Flags],
    int32(StreamIdent),
    PadLenBytes, Data, PadBytes, !.

%! priority_frame(?StreamIdent:integer, ?Exclusive:boolean, ?StreamDep:integer, ?Weight:integer)//
priority_frame(StreamIdent, Exclusive, StreamDep, Weight) -->
    { Weight in 0..255,
      if_(Exclusive = true, ExclusiveFlag #= 0x8000_0000, ExclusiveFlag #= 0),
      StreamDep #< 2^31,
      E_StreamDep #= ExclusiveFlag \/ StreamDep },
    int24(5), [0x02, 0],
    int32(StreamIdent),
    int32(E_StreamDep), [Weight].

%! rst_frame(?StreamIdent:integer, ?ErrorCode:integer)//
rst_frame(StreamIdent, ErrCode) -->
    int24(4), [0x3, 0], int32(StreamIdent), int32(ErrCode).

%! settings_frame(?Settings:list)//
settings_frame(Settings) -->
    { delay(length(Settings, SettingsLength)),
      Length #= SettingsLength * 6 },
    int24(Length),
    [0x4, 0x0], int32(0),
    settings_params(Settings).

settings_params([K-V|Settings]) -->
    { setting_name_num(K, KNum) },
    int16(KNum), int32(V),
    settings_params(Settings), !.
settings_params([]) --> [].

setting_name_num(header_table_size, 0x1).
setting_name_num(enable_push, 0x2).
setting_name_num(max_concurrent_streams, 0x3).
setting_name_num(initial_window_size, 0x4).
setting_name_num(max_frame_size, 0x5).
setting_name_num(max_header_list_size, 0x6).
setting_name_num(N, N).

%! settings_ack_frame//
%  Special case of settings_frame//1 to acknowledge the reciept of
%  headers.
settings_ack_frame -->
    int24(0), [0x4, 0x1], int32(0).

:- record push_promise_opts(end_headers=true,
                            padded=0).
:- predicate_options(push_promise_frame//4, 4,
                     [end_headers(boolean),
                      padded(integer)]).

%! push_promise_frame(?StreamIdent, ?NewStreamID, ?Headers, ?Options)//
push_promise_frame(StreamIdent, NewStreamIdent, HeaderTableInfo-Headers, Options) -->
    { make_push_promise_opts(Options, Opts),
      push_promise_opts_padded(Opts, PadLen),
      push_promise_opts_end_headers(Opts, EndHeaders),

      R_NewStreamIdent #= NewStreamIdent mod 2^32,

      % As noted in header_frame//4, it would be nice if we could do
      % this in a better way...
      when(nonvar(Headers);ground(Data),
           phrase(hpack(HeaderTableInfo, Headers), Data)),

      delay(length(Data, DataLength)),
      zcompare(Comp, PadLen, 0),
      if_(Comp = (=),
          (PadFlag #= 0,
           Length #= 4 + DataLength,
           PadLenBytes = [], PadBytes = []),
          (PadFlag #= 0x8,
           Length #= 4 + DataLength + PadLen + 1,
           PadLenBytes = [PadLen],
           replicate(PadLen, 0, PadBytes))),

      if_(EndHeaders = true, EndFlag #= 0x4, EndFlag #= 0x0),

      Flags #= EndFlag \/ PadFlag },
    int24(Length),
    [0x5, Flags],
    int32(StreamIdent),
    PadLenBytes, int32(R_NewStreamIdent), Data, PadBytes, !.

ping_frame(Data, Ack) -->
    { if_(Ack = true, Flags #= 0x1, Flags #= 0x0),
      length(Data, 8) },
    frame(0x6, Flags, 0x0, Data), !.

connection_preface(`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`).

http2_open(_, _, _).
