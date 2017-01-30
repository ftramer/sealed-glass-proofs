// Copyright (C) 2003  Davis E. King (davis@dlib.net)
// License: Boost Software License   See LICENSE.txt for the full license.
#ifndef DLIB_SERVER_HTTP_CPp_
#define DLIB_SERVER_HTTP_CPp_

#include <string>
#include "query_parser.h"

inline unsigned char to_hex( unsigned char x )  
{
    return x + (x > 9 ? ('A'-10) : '0');
}

const std::string urlencode( const std::string& s )  
{
    std::string os;

    for ( std::string::const_iterator ci = s.begin(); ci != s.end(); ++ci )
    {
        if ( (*ci >= 'a' && *ci <= 'z') ||
                (*ci >= 'A' && *ci <= 'Z') ||
                (*ci >= '0' && *ci <= '9') )
        { // allowed
            os += *ci;
        }
        else if ( *ci == ' ')
        {
            os += '+';
        }
        else
        {
            os += '%';
			os += to_hex(*ci >> 4);
			os += to_hex(*ci % 16);
        }
    }

    return os;
}

inline unsigned char from_hex( unsigned char ch ) 
{
    if (ch <= '9' && ch >= '0')
        ch -= '0';
    else if (ch <= 'f' && ch >= 'a')
        ch -= 'a' - 10;
    else if (ch <= 'F' && ch >= 'A')
        ch -= 'A' - 10;
    else 
        ch = 0;
    return ch;
}

const std::string urldecode ( const std::string& str ) 
{
    std::string result;
    std::string::size_type i;
    for (i = 0; i < str.size(); ++i)
    {
        if (str[i] == '+')
        {
            result += ' ';
        }
        else if (str[i] == '%' && str.size() > i+2)
        {
            const unsigned char ch1 = from_hex(str[i+1]);
            const unsigned char ch2 = from_hex(str[i+2]);
            const unsigned char ch = (ch1 << 4) | ch2;
            result += ch;
            i += 2;
        }
        else
        {
            result += str[i];
        }
    }
    return result;
}

int parse_url(std::string query, key_value_map& pairs) 
{
    size_t start = 0;
	size_t middle = 0;
	size_t end = 0;
	
	while ( end != std::string::npos ) {
		end = query.find('&', start);
		end = (end == std::string::npos) ? std::string::npos : (end - start);

		middle = query.substr(start, end).find('=');
		if (middle == std::string::npos) {
			return -1;
		}

        std::string key = urldecode(query.substr(start, middle));
        std::string value = urldecode(query.substr(middle+1, end - middle - 1));
		pairs[key] = value;
		query = query.substr(end + 1);
    }

	return 0;
}

#endif // DLIB_SERVER_HTTP_CPp_