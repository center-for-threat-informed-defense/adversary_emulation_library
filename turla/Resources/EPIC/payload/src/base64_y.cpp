/*
   base64.cpp and base64.h
   base64 encoding and decoding with C++.
   More information at
     https://renenyffenegger.ch/notes/development/Base64/Encoding-and-decoding-base-64-with-cpp
   Version: 2.rc.08 (release candidate)
   Copyright (C) 2004-2017, 2020, 2021 René Nyffenegger
   This source code is provided 'as-is', without any express or implied
   warranty. In no event will the author be held liable for any damages
   arising from the use of this software.
   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely, subject to the following restrictions:
   1. The origin of this source code must not be misrepresented; you must not
      claim that you wrote the original source code. If you use this source code
      in a product, an acknowledgment in the product documentation would be
      appreciated but is not required.
   2. Altered source versions must be plainly marked as such, and must not be
      misrepresented as being the original source code.
   3. This notice may not be removed or altered from any source distribution.
   René Nyffenegger rene.nyffenegger@adp-gmbh.ch
*/

#include "base64_y.h"

#include <algorithm>
#include <stdexcept>
#include <vector>

//
// Depending on the url parameter in base64_chars, one of
// two sets of base64 characters needs to be chosen.
// They differ in their last two characters.
//
static const char* base64_chars[2] = {
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789"
             "+/",

             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789"
             "-_" };

static unsigned int pos_of_char(const unsigned char chr) {
    //
    // Return the position of chr within base64_encode()
    //

    if (chr >= 'A' && chr <= 'Z') return chr - 'A';
    else if (chr >= 'a' && chr <= 'z') return chr - 'a' + ('Z' - 'A') + 1;
    else if (chr >= '0' && chr <= '9') return chr - '0' + ('Z' - 'A') + ('z' - 'a') + 2;
    else if (chr == '+' || chr == '-') return 62; // Be liberal with input and accept both url ('-') and non-url ('+') base 64 characters (
    else if (chr == '/' || chr == '_') return 63; // Ditto for '/' and '_'
    else
        //
        // 2020-10-23: Throw std::exception rather than const char*
        //(Pablo Martin-Gomez, https://github.com/Bouska)
        //
        throw std::runtime_error("Input is not valid base64-encoded data.");
}

static std::string insert_linebreaks(std::string str, size_t distance) {
    //
    // Provided by https://github.com/JomaCorpFX, adapted by me.
    //
    if (!str.length()) {
        return "";
    }

    size_t pos = distance;

    while (pos < str.size()) {
        str.insert(pos, "\n");
        pos += distance + 1;
    }

    return str;
}

template <typename String, unsigned int line_length>
static std::string encode_with_line_breaks(String s) {
    return insert_linebreaks(base64_encode(s, false), line_length);
}

template <typename String>
static std::string encode_pem(String s) {
    return encode_with_line_breaks<String, 64>(s);
}

template <typename String>
static std::string encode_mime(String s) {
    return encode_with_line_breaks<String, 76>(s);
}

template <typename String>
static std::string encode(String s, bool url) {
    return base64_encode(reinterpret_cast<const unsigned char*>(s.data()), s.length(), url);
}

std::string base64_encode(unsigned char const* bytes_to_encode, size_t in_len, bool url) {

    size_t len_encoded = (in_len + 2) / 3 * 4;

    unsigned char trailing_char = url ? '.' : '=';

    //
    // Choose set of base64 characters. They differ
    // for the last two positions, depending on the url
    // parameter.
    // A bool (as is the parameter url) is guaranteed
    // to evaluate to either 0 or 1 in C++ therefore,
    // the correct character set is chosen by subscripting
    // base64_chars with url.
    //
    const char* base64_chars_ = base64_chars[url];

    std::string ret;
    ret.reserve(len_encoded);

    unsigned int pos = 0;

    while (pos < in_len) {
        ret.push_back(base64_chars_[(bytes_to_encode[pos + 0] & 0xfc) >> 2]);

        if (pos + 1 < in_len) {
            ret.push_back(base64_chars_[((bytes_to_encode[pos + 0] & 0x03) << 4) + ((bytes_to_encode[pos + 1] & 0xf0) >> 4)]);

            if (pos + 2 < in_len) {
                ret.push_back(base64_chars_[((bytes_to_encode[pos + 1] & 0x0f) << 2) + ((bytes_to_encode[pos + 2] & 0xc0) >> 6)]);
                ret.push_back(base64_chars_[bytes_to_encode[pos + 2] & 0x3f]);
            }
            else {
                ret.push_back(base64_chars_[(bytes_to_encode[pos + 1] & 0x0f) << 2]);
                ret.push_back(trailing_char);
            }
        }
        else {

            ret.push_back(base64_chars_[(bytes_to_encode[pos + 0] & 0x03) << 4]);
            ret.push_back(trailing_char);
            ret.push_back(trailing_char);
        }

        pos += 3;
    }


    return ret;
}


/**
 * Converts a base64 character to the bits that the character encodes, as definedd by RFC 4648 §4.
 * Padding characters (=) are given a return value of 64, and invalid characters are given a value
 * of 65.
 * 
 * @param character Base64 character to be mapped to the bits it represents
 * @return the six-bit value that is represented by the character
 */
unsigned char map_base64_char(char character) {
    if (character >= 'A' && character <= 'Z') {
        return character - 65;
    }
    else if (character >= 'a' && character <= 'z') {
        return character - 71;
    }
    else if (character >= '0' && character <= '9') {
        return character + 4;
    }
    else if (character == '+') {
        return 62;
    }
    else if (character == '/') {
        return 63;
    }
    else if (character == '=') {
        return 64;
    }
    return 65;
}

/**
 * Base64 decode a string. See https://en.wikipedia.org/wiki/Base64#Examples for more info.
 * 
 * @param encoded_string base64 encoded string that should be decoded
 * @return decoded output, NULL if input is invalid
 */
std::vector<unsigned char> decode(std::string const& encoded_string) {
    std::vector<unsigned char> decoded_value;
    if (encoded_string.length() % 4 != 0) {
        // length of encoded string must be divisible by 4
        perror("Invalid base64 encoding length");
        abort();
    }
    // every 4 encoded characters produce 3 decoded characters
    // loop over encoded string here, processing 4 characters at a time
    for (int i = 0; i < encoded_string.length() / 4; i++) {
        unsigned char first_encoded = map_base64_char(encoded_string[4 * i + 0]);
        unsigned char second_encoded = map_base64_char(encoded_string[4 * i + 1]);
        unsigned char third_encoded = map_base64_char(encoded_string[4 * i + 2]);
        unsigned char fourth_encoded = map_base64_char(encoded_string[4 * i + 3]);

        if (first_encoded == 64 || first_encoded == 65 || second_encoded == 64 
            || second_encoded == 65 || third_encoded == 65 || fourth_encoded == 65) {
            // (64) first and second character of a 4 letter set should never have padding (=) character
            // (65) all characters should be a valid Base64 encoding character (A-Za-z0-9/+)
            perror("Invalid base64 encoding");
            abort();
        }

        // get first decoded value
        unsigned char first_decoded = first_encoded << 2 | second_encoded >> 4;
        decoded_value.push_back(first_decoded);

        // if third encoded character is padding, that means we have readed the end of the string
        if (third_encoded == 64) {
            return decoded_value;
        }

        // get second decoded value
        unsigned char second_decoded = (second_encoded & 0b001111) << 4 | third_encoded >> 2;
        decoded_value.push_back(second_decoded);

        // if fourth encoded character is padding, that means we have reached the end of the string
        if (fourth_encoded == 64) {
            return decoded_value;
        }

        // get third decoded value
        unsigned char third_decoded = third_encoded << 6 | fourth_encoded;
        decoded_value.push_back(third_decoded);
    }
    return decoded_value;
}

std::vector<unsigned char> base64_decode(std::string const& s, bool remove_linebreaks) {
    return decode(s);
}

std::string base64_encode(std::string const& s, bool url) {
    return encode(s, url);
}

std::string base64_encode_pem(std::string const& s) {
    return encode_pem(s);
}

std::string base64_encode_mime(std::string const& s) {
    return encode_mime(s);
}
