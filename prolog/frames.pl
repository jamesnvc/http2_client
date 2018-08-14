:- module(frames, [data_frame//3,
                   header_frame//4,
                   priority_frame//4,
                   rst_frame//2,
                   settings_frame//1,
                   settings_ack_frame//0,
                   push_promise_frame//4,
                   ping_frame//2,
                   goaway_frame//3,
                   window_update_frame//2,
                   continuation_frame//3]).
/** <module> DCGs for parsing HTTP/2 frames

@author James Cash
*/

:- use_module(library(clpfd)).
:- use_module(library(record)).
:- use_module(library(predicate_options)).
:- use_module(library(delay), [delay/1]).
:- use_module(library(list_util), [replicate/3]).
:- use_module(hpack, [hpack//2]).
:- use_module(reif).

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
    int31(Ident),
    Payload.

% https://httpwg.org/specs/rfc7540.html#FrameTypes
% TODO: need to ensure that each frame is less than
% SETTINGS_MAX_FRAME_SIZE
% (default 2^14 octets)

:- record data_opts(padded=0, end_stream=false).
:- predicate_options(data_frame//3, 3, [padded(integer),
                                        end_stream(boolean)]).
%! data_frame(?StreamIdent:integer, ?Data:list, ?Options)//
%  DCG for an HTTP/2 data frame
%
%  @arg Options Options list:
%        * padded(PadLength)
%          If non-zero, the stream will be padded with that many zero bytes.
%        * end_stream(End)
%          If =true=, this frame indicates the end of the stream
%
%  @bug Technically, I think having a padding of zero is allowed, but
%        currently that isn't representable
data_frame(StreamIdent, Data, Options) -->
    int24(Length), [0x0],
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
      if_(StreamEnd = true, EndFlag #= 0x1,
          (StreamEnd = false, EndFlag #= 0x0)),

      Flags #= EndFlag \/ PadFlag },
    [Flags], int31(StreamIdent),
    PadLenBytes, Data, PadBytes, !.

:- record header_opts(end_stream=false,
                      end_headers=true,
                      padded=0,
                      priority=false,
                      is_exclusive=false,
                      stream_dependency=0,
                      weight=0).
:- predicate_options(header_frame//3, 3,
                     [end_stream(boolean),
                      end_headers(boolean),
                      padded(integer),
                      priority(boolean),
                      is_exclusive(boolean),
                      stream_dependency(integer),
                      weight(integer)]).

%! header_frame(?StreamIdent:integer, ?Headers:list, ?TableSizeInOut, ?Options)//
%  DCG for an HTTP/2 header frame.
%
%  @arg TableSizeInOut Header table configuration information that is
%        passed to the hpack:hpack//2 DCG.
%  @arg Options Allowed options:
%        * padded(PadLength)
%          If non-zero, the stream will be padded with that many zero bytes.
%        * end_stream(EndStream)
%          If true, this frame indicates the end of the stream
%        * end_headers(End)
%          If true, this frame indicates the end of the headers
%        * priority(Priority)
%          If true, this frame has priority set.
%  @see hpack:hpack//2
%  @bug Technically, I think having a padding of zero is allowed, but
%        currently that isn't representable
%  @tbd Support for stream-priority flag
%  @tbd Headers need to fit in a particular size, or needs to use
%        CONTINUATION frames.
header_frame(StreamIdent, Headers, Size-Table0-Table1, Options) -->
    int24(Length), [0x1],
    { make_header_opts(Options, Opts),
      header_opts_padded(Opts, PadLen),
      header_opts_end_stream(Opts, EndStream),
      header_opts_priority(Opts, IsPriority),
      header_opts_end_headers(Opts, EndHeaders),
      header_opts_is_exclusive(Opts, IsExclusive),
      header_opts_stream_dependency(Opts, StreamDep),
      header_opts_weight(Opts, Weight),

      % dumb that we have to call phrase/2 inside a DCG, but we need
      % to know the length of the output & I'm not sure how else to do
      % this
      when(nonvar(Headers);ground(Data),
           phrase(hpack(Size-Table0-Table1, Headers), Data)),

      DataLength #>= 0,
      delay(length(Data, DataLength)),
      zcompare(Comp, PadLen, 0),
      if_(Comp = (=),
          (PadFlag = 0x0,
           Length_ #= DataLength,
           PadLenBytes = [], PadBytes = []),
          (PadFlag = 0x8,
           PadLenBytes = [PadLen],
           replicate(PadLen, 0, PadBytes),
           Length_ #= PadLen + DataLength + 1)),

      if_(EndStream = true, EndStreamFlag #= 0x1,
          (EndStream = false, EndStreamFlag #= 0)),
      if_(EndHeaders = true, EndHeadersFlag #= 0x4,
          (EndHeaders = false, EndHeadersFlag #= 0)),
      if_(IsPriority = true,
          (IsPriorityFlag #= 0x20,
           StreamDep #> 0,
           if_(IsExclusive = true,
               (EStreamDep #=  StreamDep + 2^31,
                StreamDep #= EStreamDep mod 2^31),
               (IsExclusive = false,
                StreamDep #= EStreamDep)),
           EStreamDepBytes = int32(EStreamDep),
           Length #= Length_ + 5,
           WeightBytes = [Weight]),
          (IsPriority = false,
           IsPriorityFlag #= 0x0,
           Length #= Length_,
           EStreamDepBytes = [], WeightBytes = [])),

      Flags #= EndStreamFlag \/ EndHeadersFlag \/ IsPriorityFlag \/ PadFlag },
    [Flags],
    int31(StreamIdent),
    PadLenBytes,
    EStreamDepBytes, WeightBytes,
    Data, PadBytes, !.

%! priority_frame(?StreamIdent:integer, ?Exclusive:boolean, ?StreamDep:integer, ?Weight:integer)//
priority_frame(StreamIdent, Exclusive, StreamDep, Weight) -->
    int24(5), [0x02, 0],
    { Weight in 0..255,
      if_(Exclusive = true, ExclusiveFlag #= 0x8000_0000,
          (Exclusive = false, ExclusiveFlag #= 0)),
      StreamDep #< 2^31,
      E_StreamDep #= ExclusiveFlag \/ StreamDep },
    int31(StreamIdent),
    int32(E_StreamDep), [Weight].

%! rst_frame(?StreamIdent:integer, ?ErrorCode:integer)//
rst_frame(StreamIdent, ErrCode) -->
    int24(4), [0x3, 0], int31(StreamIdent), int32(ErrCode).

%! settings_frame(?Settings:list)//
settings_frame(Settings) -->
    int24(Length),
    [0x4, 0x0], int32(0),
    { delay(length(Settings, SettingsLength)),
      Length #= SettingsLength * 6 },
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

%! push_promise_frame(?StreamIdent:integer, ?NewStreamID:integer, ?HeaderInfo, ?Options:list)//
%  DCG for a push-promise frame, which is a frame notifying the
%  receiver about a new stream the sender intends to initiate.
%
%  @arg HeaderInfo Information to be passed to hpack:hpack//2, in the
%        form =|TableSizeInOut-HeadersList|=
%  @arg Options Options list:
%        * padded(PadLength)
%           If non-zero, the data will be padded by the indicated number of zero bytes
%        * end_headers(End)
%           If true, this frame is the end of the stream
%  @see hpack:hpack//2
%  @bug Technically, I think having a padding of zero is allowed, but
%        currently that isn't representable
push_promise_frame(StreamIdent, NewStreamIdent, HeaderTableInfo-Headers, Options) -->
    int24(Length), [0x5],
    { make_push_promise_opts(Options, Opts),
      push_promise_opts_padded(Opts, PadLen),
      push_promise_opts_end_headers(Opts, EndHeaders),

      R_NewStreamIdent #= NewStreamIdent mod 2^32,
      NewStreamIdent #= R_NewStreamIdent mod 2^32,

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

      if_(EndHeaders = true, EndFlag #= 0x4,
          (EndHeaders = false, EndFlag #= 0x0)),

      Flags #= EndFlag \/ PadFlag },
    [Flags],
    int31(StreamIdent),
    PadLenBytes, int32(R_NewStreamIdent), Data, PadBytes, !.

%! ping_frame(?Data:list, ?Ack:boolean)//
ping_frame(Data, Ack) -->
    { if_(Ack = true, Flags #= 0x1,
          (Ack = false, Flags #= 0x0)),
      length(Data, 8) },
    frame(0x6, Flags, 0x0, Data), !.

%! goaway_frame(?LastStreamId, ?ErrorCode, ?Data)//
goaway_frame(LastStreamId, Error, Data) -->
    int24(Length), [0x7, 0], int32(0),
    { delay(length(Data, DataLength)),
      Length #= DataLength + 4 + 4 },
    int31(LastStreamId), int32(Error),
    Data.

%! window_update_frame(?StreamIdent, ?Increment)//
window_update_frame(StreamIdent, Increment) -->
    int24(4),  [0x8, 0],
    int31(StreamIdent),
    int31(Increment).

%! continuation_frame(?StreamIdent:integer, ?HeaderInfo, ?End:boolean)//
%  @arg HeaderInfo Information to be passed to hpack:hpack//2
%        =| HeaderInfo = HeaderTableSize-TableIn-TableOut-HeaderList |=
continuation_frame(StreamIdent, HeaderTableInfo-Headers, End) -->
    int24(Length), [0x9],
    { when(nonvar(Headers);ground(Data),
           phrase(hpack(HeaderTableInfo, Headers), Data)),
      delay(length(Data, Length)),
      if_(End = true, Flags #= 0x4,
          (End = false, Flags #= 0x0)) },
    [Flags], int31(StreamIdent),
    Data.

% Helper predicates

int16(I) -->
    { [A, B] ins 0..255,
      I #= A * (2^8) + B },
    [A, B].

int24(I) -->
    { [A, B, C] ins 0..255,
      I #= A * (2^16) + B * (2^8) + C },
    [A, B, C].

int31(I) -->
    { [A, B, C, D] ins 0..255,
      A_ in 0..127,
      A_ #= A mod 128,
      I in 0..0x7fff_ffff,
      I #= A_ * (2^24) + B * (2^16) + C * (2^8) + D,
      % Annoying thing with StreamIdent: we want to ignore the high
      % bit when receiving, but set it to zero when sending
      (ground(I) -> A #= A_ ; true) },
    [A, B, C, D].

int32(I) -->
    { [A, B, C, D] ins 0..255,
      I #= A * (2^24) + B * (2^16) + C * (2^8) + D },
    [A, B, C, D].
