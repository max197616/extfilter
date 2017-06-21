#pragma once

enum protocol_check_status
{
	DPI_PROTOCOL_MATCHES = 0, /** If the protocol matches for sure. */
	DPI_PROTOCOL_NO_MATCHES, /** If the protocol doesn't matches for sure. */
	DPI_PROTOCOL_MORE_DATA_NEEDED, /** The inspector needs more data to be sure that the protocol matches or to invoke the callback on the complete data. **/
	DPI_PROTOCOL_ERROR
};

enum tcp_protocols
{
	DPI_PROTOCOL_UNKNOWN = 0,
	DPI_PROTOCOL_TCP_HTTP,
	DPI_PROTOCOL_TCP_SSL
};

enum dpi_http_method
{
	HTTP_METHOD_UNKNOWN = 0,
	HTTP_METHOD_OPTIONS,
	HTTP_METHOD_GET,
	HTTP_METHOD_HEAD,
	HTTP_METHOD_POST,
	HTTP_METHOD_PUT,
	HTTP_METHOD_DELETE,
	HTTP_METHOD_TRACE,
	HTTP_METHOD_CONNECT
};

int check_punycode_string(char * buffer , int len);
void stripCertificateTrailer(char *buffer, int buffer_len);

#define ndpi_isalpha(ch) (((ch) >= 'a' && (ch) <= 'z') || ((ch) >= 'A' && (ch) <= 'Z'))
#define ndpi_isdigit(ch) ((ch) >= '0' && (ch) <= '9')
#define ndpi_isspace(ch) (((ch) >= '\t' && (ch) <= '\r') || ((ch) == ' '))
#define ndpi_isprint(ch) ((ch) >= 0x20 && (ch) <= 0x7e)
#define ndpi_ispunct(ch) (((ch) >= '!' && (ch) <= '/') ||	\
			  ((ch) >= ':' && (ch) <= '@') ||	\
			  ((ch) >= '[' && (ch) <= '`') ||	\
			  ((ch) >= '{' && (ch) <= '~'))
