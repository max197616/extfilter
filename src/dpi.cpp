#include "dpi.h"

/* implementation of the punycode check function */
int check_punycode_string(char * buffer , int len)
{
	int i = 0;

	while(i++ < len)
	{
		if( buffer[i] == 'x' && buffer[i+1] == 'n' && buffer[i+2] == '-' && buffer[i+3] == '-' )
			return 1;
	}
	// not a punycode string
	return 0;
}

void stripCertificateTrailer(char *buffer, int buffer_len)
{
	int i, is_puny;
	for(i = 0; i < buffer_len; i++)
	{
		if((buffer[i] != '.')
		&& (buffer[i] != '-')
		&& (buffer[i] != '_')
		&& (buffer[i] != '*')
		&& (!ndpi_isalpha(buffer[i]))
		&& (!ndpi_isdigit(buffer[i])))
		{
			buffer[i] = '\0';
			buffer_len = i;
			break;
		}
	}

	/* check for punycode encoding */
	is_puny = check_punycode_string(buffer, buffer_len);

	// not a punycode string - need more checks
	if(is_puny == 0)
	{
		if(i > 0)
			i--;
		while(i > 0)
		{
			if(!ndpi_isalpha(buffer[i]))
			{
				buffer[i] = '\0';
				buffer_len = i;
				i--;
			} else
				break;
		}
		for(i = buffer_len; i > 0; i--)
		{
			if(buffer[i] == '.')
				break;
			else if(ndpi_isdigit(buffer[i]))
				buffer[i] = '\0', buffer_len = i;
		}
	}
}
