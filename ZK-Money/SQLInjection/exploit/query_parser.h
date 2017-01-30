#pragma once

#include <map>
#include <string>

typedef std::map< std::string, std::string > key_value_map;

const std::string urlencode( const std::string& s );
const std::string urldecode ( const std::string& str );
int parse_url(std::string query, key_value_map& pairs);
