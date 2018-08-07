:- module(http2_client, [http2_open/3,
                         http2_close/1,
                         http2_request/5]).
/** <module> HTTP/2 client

@author James Cash
*/

connection_preface(`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`).

%! http2_open(+Host, -Stream, +Options) is det.
%  Open =Stream= as an HTTP/2 connection to =Host=.
http2_open(_Host, _Stream, _Options).

%! http2_close(+Stream) is det.
%  Close the given stream.
http2_close(_Stream).

%! http2_request(+Stream, +Method, +Headers, +Body, -Response) is det.
%  Send an HTTP/2 request using the previously-opened HTTP/2
%  connection =Stream=.
%  @see http2_open/2
http2_request(_Stream, _Method, _Headers, _Body, _Response).
