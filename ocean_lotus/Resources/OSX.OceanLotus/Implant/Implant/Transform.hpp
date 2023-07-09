#ifndef Transform_hpp
#define Transform_hpp

#include <vector>

class Transform{
public:
    /*
    scrambleBytes
        About:
            Modeled after Parser::inBytes. Performs data transformation scrambling
            against a sequence of bytes.
        Result:
            Vector of unsigned char - scrambled sequence of bytes
        MITRE ATT&CK Techniques:
        CTI:
            https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
        References:
    */
    static std::vector<unsigned char> scrambleBytes();

    /*
    scrambleByte
        About:
            Modeled after Parser::inByte. Performs data transformation scrambling
            against a single byte.
        Result:
            Vector of unsigned char - scrambled byte in array
        MITRE ATT&CK Techniques:
        CTI:
            https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
        References:
    */
    static std::vector<unsigned char> scrambleByte();

    /*
    scrambleString
        About:
            Modeled after Parser::inString. Performs data transformation scrambling
            against a string.
        Result:
            Vector of unsigned char - scrambled string
        MITRE ATT&CK Techniques:
        CTI:
            https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
        References:
    */
    static std::vector<unsigned char> scrambleString();

    /*
    scrambleInt
        About:
            Modeled after Parser::inInt. Performs data transformation scrambling
            against an int.
        Result:
            Vector of unsigned char - scrambled int
        MITRE ATT&CK Techniques:
        CTI:
            https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
        References:
    */
    static std::vector<unsigned char> scrambleInt();

    /*
    unscrambleString
        About:
            Modeled after Converter::outString. Performs data transformation
            unscrambling against a string.
        Result:
            Vector of unsigned char - unscrambled string bytes
        MITRE ATT&CK Techniques:
        CTI:
            https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
        References:
    */
    static std::vector<unsigned char> unscrambleString();
};

#endif /* Transform_hpp */
