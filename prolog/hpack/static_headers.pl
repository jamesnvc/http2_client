:- module(static_headers, [static_header/2]).
/** <module> hpack/static_headers, the RFC-defined static header tables for HPACK

@author James Cash
*/

%! static_header(?Index, ?NameValue) is semidet.
static_header(1,  ':authority'-false).
static_header(2,  ':method'-'GET').
static_header(3,  ':method'-'POST').
static_header(4,  ':path'-'/').
static_header(5,  ':path'-'/index.html').
static_header(6,  ':scheme'-http).
static_header(7,  ':scheme'-https).
static_header(8,  ':status'-'200').
static_header(9,  ':status'-'204').
static_header(10, ':status'-'206').
static_header(11, ':status'-'304').
static_header(12, ':status'-'400').
static_header(13, ':status'-'404').
static_header(14, ':status'-'500').
static_header(15, 'accept-charset'-false).
static_header(16, 'accept-encoding'-'gzip, deflate').
static_header(17, 'accept-language'-false).
static_header(18, 'accept-ranges'-false).
static_header(19, 'accept'-false).
static_header(20, 'access-control-allow-origin'-false).
static_header(21, 'age'-false).
static_header(22, 'allow'-false).
static_header(23, 'authorization'-false).
static_header(24, 'cache-control'-false).
static_header(25, 'content-disposition'-false).
static_header(26, 'content-encoding'-false).
static_header(27, 'content-language'-false).
static_header(28, 'content-length'-false).
static_header(29, 'content-location'-false).
static_header(30, 'content-range'-false).
static_header(31, 'content-type'-false).
static_header(32, 'cookie'-false).
static_header(33, 'date'-false).
static_header(34, 'etag'-false).
static_header(35, 'expect'-false).
static_header(36, 'expires'-false).
static_header(37, 'from'-false).
static_header(38, 'host'-false).
static_header(39, 'if-match'-false).
static_header(40, 'if-modified-since'-false).
static_header(41, 'if-none-match'-false).
static_header(42, 'if-range'-false).
static_header(43, 'if-unmodified-since'-false).
static_header(44, 'last-modified'-false).
static_header(45, 'link'-false).
static_header(46, 'location'-false).
static_header(47, 'max-forwards'-false).
static_header(48, 'proxy-authenticate'-false).
static_header(49, 'proxy-authorization'-false).
static_header(50, 'range'-false).
static_header(51, 'referer'-false).
static_header(52, 'refresh'-false).
static_header(53, 'retry-after'-false).
static_header(54, 'server'-false).
static_header(55, 'set-cookie'-false).
static_header(56, 'strict-transport-security'-false).
static_header(57, 'transfer-encoding'-false).
static_header(58, 'user-agent'-false).
static_header(59, 'vary'-false).
static_header(60, 'via'-false).
static_header(61, 'www-authenticate'-false).
