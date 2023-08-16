// Copyright (C) 2022 Evan McBroom
// If you are using Visual Studio, you will need to disable the "Edit and Continue" feature.

// Prng based off of Parker Miller's
// "Multiplicative Linear Congruential Generator"
// https://en.wikipedia.org/wiki/Lehmer_random_number_generator

#ifndef no_strings_h
#define no_strings_h

#include <stddef.h>

template<typename T, size_t N>
struct encrypted {
    T data[N];
};

template<size_t N>
constexpr auto crypt(const char(&input)[N]) {
    encrypted<char, N> blob{};
    for (uint32_t index{ 0 }; index < N; index++) {
        blob.data[index] = input[index] ^ 0x1B;
    }
    return blob;
}

#define xor_string(STRING) ([&] {            \
    constexpr auto _{ crypt(STRING) };        \
    return std::string{ crypt(_.data).data }; \
}())


#endif /* no_strings_h */
