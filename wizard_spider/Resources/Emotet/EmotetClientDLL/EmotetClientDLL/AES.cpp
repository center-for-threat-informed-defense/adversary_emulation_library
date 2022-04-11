// Source: https://github.com/SergeyBel/AES
// License: MIT License

#include "pch.h"
#include "AES.h"

AES::AES(int keyLen)
{
    this->Nb = 4;
    switch (keyLen)
    {
    case 128:
        this->Nk = 4;
        this->Nr = 10;
        break;
    case 192:
        this->Nk = 6;
        this->Nr = 12;
        break;
    case 256:
        this->Nk = 8;
        this->Nr = 14;
        break;
    default:
        throw "Incorrect key length";
    }

    blockBytesLen = 4 * this->Nb * sizeof(unsigned char);
}

unsigned char* AES::EncryptECB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned int& outLen)
{
    outLen = GetPaddingLength(inLen);
    unsigned char* alignIn = PaddingNulls(in, inLen, outLen);
    unsigned char* out = new unsigned char[outLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    for (unsigned int i = 0; i < outLen; i += blockBytesLen)
    {
        EncryptBlock(alignIn + i, out + i, roundKeys);
    }

    delete[] alignIn;
    delete[] roundKeys;

    return out;
}

unsigned char* AES::DecryptECB(unsigned char in[], unsigned int inLen, unsigned  char key[])
{
    unsigned char* out = new unsigned char[inLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    for (unsigned int i = 0; i < inLen; i += blockBytesLen)
    {
        DecryptBlock(in + i, out + i, roundKeys);
    }

    delete[] roundKeys;

    return out;
}


unsigned char* AES::EncryptCBC(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char* iv, unsigned int& outLen)
{
    outLen = GetPaddingLength(inLen);
    unsigned char* alignIn = PaddingNulls(in, inLen, outLen);
    unsigned char* out = new unsigned char[outLen];
    unsigned char* block = new unsigned char[blockBytesLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    memcpy(block, iv, blockBytesLen);
    for (unsigned int i = 0; i < outLen; i += blockBytesLen)
    {
        XorBlocks(block, alignIn + i, block, blockBytesLen);
        EncryptBlock(block, out + i, roundKeys);
        memcpy(block, out + i, blockBytesLen);
    }

    delete[] block;
    delete[] alignIn;
    delete[] roundKeys;

    return out;
}

unsigned char* AES::DecryptCBC(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char* iv)
{
    unsigned char* out = new unsigned char[inLen];
    unsigned char* block = new unsigned char[blockBytesLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    memcpy(block, iv, blockBytesLen);
    for (unsigned int i = 0; i < inLen; i += blockBytesLen)
    {
        DecryptBlock(in + i, out + i, roundKeys);
        XorBlocks(block, out + i, out + i, blockBytesLen);
        memcpy(block, in + i, blockBytesLen);
    }

    delete[] block;
    delete[] roundKeys;

    return out;
}

unsigned char* AES::EncryptCFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char* iv, unsigned int& outLen)
{
    outLen = GetPaddingLength(inLen);
    unsigned char* alignIn = PaddingNulls(in, inLen, outLen);
    unsigned char* out = new unsigned char[outLen];
    unsigned char* block = new unsigned char[blockBytesLen];
    unsigned char* encryptedBlock = new unsigned char[blockBytesLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    memcpy(block, iv, blockBytesLen);
    for (unsigned int i = 0; i < outLen; i += blockBytesLen)
    {
        EncryptBlock(block, encryptedBlock, roundKeys);
        XorBlocks(alignIn + i, encryptedBlock, out + i, blockBytesLen);
        memcpy(block, out + i, blockBytesLen);
    }

    delete[] block;
    delete[] encryptedBlock;
    delete[] alignIn;
    delete[] roundKeys;

    return out;
}

unsigned char* AES::DecryptCFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char* iv)
{
    unsigned char* out = new unsigned char[inLen];
    unsigned char* block = new unsigned char[blockBytesLen];
    unsigned char* encryptedBlock = new unsigned char[blockBytesLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    memcpy(block, iv, blockBytesLen);
    for (unsigned int i = 0; i < inLen; i += blockBytesLen)
    {
        EncryptBlock(block, encryptedBlock, roundKeys);
        XorBlocks(in + i, encryptedBlock, out + i, blockBytesLen);
        memcpy(block, in + i, blockBytesLen);
    }

    delete[] block;
    delete[] encryptedBlock;
    delete[] roundKeys;

    return out;
}

unsigned char* AES::PaddingNulls(unsigned char in[], unsigned int inLen, unsigned int alignLen)
{
    unsigned char* alignIn = new unsigned char[alignLen];
    memcpy(alignIn, in, inLen);
    memset(alignIn + inLen, 0x00, alignLen - inLen);
    return alignIn;
}

unsigned int AES::GetPaddingLength(unsigned int len)
{
    unsigned int lengthWithPadding = (len / blockBytesLen);
    if (len % blockBytesLen) {
        lengthWithPadding++;
    }

    lengthWithPadding *= blockBytesLen;

    return lengthWithPadding;
}

void AES::EncryptBlock(unsigned char in[], unsigned char out[], unsigned  char* roundKeys)
{
    unsigned char** state = new unsigned char* [4];
    state[0] = new unsigned  char[4 * Nb];
    int i, j, round;
    for (i = 0; i < 4; i++)
    {
        state[i] = state[0] + Nb * i;
    }


    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            state[i][j] = in[i + 4 * j];
        }
    }

    AddRoundKey(state, roundKeys);

    for (round = 1; round <= Nr - 1; round++)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 4 * Nb);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + Nr * 4 * Nb);

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            out[i + 4 * j] = state[i][j];
        }
    }

    delete[] state[0];
    delete[] state;
}

void AES::DecryptBlock(unsigned char in[], unsigned char out[], unsigned  char* roundKeys)
{
    unsigned char** state = new unsigned char* [4];
    state[0] = new unsigned  char[4 * Nb];
    int i, j, round;
    for (i = 0; i < 4; i++)
    {
        state[i] = state[0] + Nb * i;
    }


    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++) {
            state[i][j] = in[i + 4 * j];
        }
    }

    AddRoundKey(state, roundKeys + Nr * 4 * Nb);

    for (round = Nr - 1; round >= 1; round--)
    {
        InvSubBytes(state);
        InvShiftRows(state);
        AddRoundKey(state, roundKeys + round * 4 * Nb);
        InvMixColumns(state);
    }

    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, roundKeys);

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++) {
            out[i + 4 * j] = state[i][j];
        }
    }

    delete[] state[0];
    delete[] state;
}


void AES::SubBytes(unsigned char** state)
{
    int i, j;
    unsigned char t;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            t = state[i][j];
            state[i][j] = sbox[t / 16][t % 16];
        }
    }

}

void AES::ShiftRow(unsigned char** state, int i, int n)    // shift row i on n positions
{
    unsigned char* tmp = new unsigned char[Nb];
    for (int j = 0; j < Nb; j++) {
        tmp[j] = state[i][(j + n) % Nb];
    }
    memcpy(state[i], tmp, Nb * sizeof(unsigned char));

    delete[] tmp;
}

void AES::ShiftRows(unsigned char** state)
{
    ShiftRow(state, 1, 1);
    ShiftRow(state, 2, 2);
    ShiftRow(state, 3, 3);
}

unsigned char AES::xtime(unsigned char b)    // multiply on x
{
    return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}



/* Implementation taken from https://en.wikipedia.org/wiki/Rijndael_mix_columns#Implementation_example */
void AES::MixSingleColumn(unsigned char* r)
{
    unsigned char a[4];
    unsigned char b[4];
    unsigned char c;
    unsigned char h;
    /* The array 'a' is simply a copy of the input array 'r'
    * The array 'b' is each element of the array 'a' multiplied by 2
    * in Rijndael's Galois field
    * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */
    for (c = 0; c < 4; c++)
    {
        a[c] = r[c];
        /* h is 0xff if the high bit of r[c] is set, 0 otherwise */
        h = (unsigned char)((signed char)r[c] >> 7); /* arithmetic right shift, thus shifting in either zeros or ones */
        b[c] = r[c] << 1; /* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
        b[c] ^= 0x1B & h; /* Rijndael's Galois field */
    }
    r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
    r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
    r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
    r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
}

/* Performs the mix columns step. Theory from: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_MixColumns_step */
void AES::MixColumns(unsigned char** state)
{
    unsigned char* temp = new unsigned char[4];

    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            temp[j] = state[j][i]; //place the current state column in temp
        }
        MixSingleColumn(temp); //mix it using the wiki implementation
        for (int j = 0; j < 4; ++j)
        {
            state[j][i] = temp[j]; //when the column is mixed, place it back into the state
        }
    }
    delete[] temp;
}

void AES::AddRoundKey(unsigned char** state, unsigned char* key)
{
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            state[i][j] = state[i][j] ^ key[i + 4 * j];
        }
    }
}

void AES::SubWord(unsigned char* a)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        a[i] = sbox[a[i] / 16][a[i] % 16];
    }
}

void AES::RotWord(unsigned char* a)
{
    unsigned char c = a[0];
    a[0] = a[1];
    a[1] = a[2];
    a[2] = a[3];
    a[3] = c;
}

void AES::XorWords(unsigned char* a, unsigned char* b, unsigned char* c)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        c[i] = a[i] ^ b[i];
    }
}

void AES::Rcon(unsigned char* a, int n)
{
    int i;
    unsigned char c = 1;
    for (i = 0; i < n - 1; i++)
    {
        c = xtime(c);
    }

    a[0] = c;
    a[1] = a[2] = a[3] = 0;
}

void AES::KeyExpansion(unsigned char key[], unsigned char w[])
{
    unsigned char* temp = new unsigned char[4];
    unsigned char* rcon = new unsigned char[4];

    int i = 0;
    while (i < 4 * Nk)
    {
        w[i] = key[i];
        i++;
    }

    i = 4 * Nk;
    while (i < 4 * Nb * (Nr + 1))
    {
        temp[0] = w[i - 4 + 0];
        temp[1] = w[i - 4 + 1];
        temp[2] = w[i - 4 + 2];
        temp[3] = w[i - 4 + 3];

        if (i / 4 % Nk == 0)
        {
            RotWord(temp);
            SubWord(temp);
            Rcon(rcon, i / (Nk * 4));
            XorWords(temp, rcon, temp);
        }
        else if (Nk > 6 && i / 4 % Nk == 4)
        {
            SubWord(temp);
        }

        w[i + 0] = w[i - 4 * Nk] ^ temp[0];
        w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
        w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
        w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
        i += 4;
    }

    delete[]rcon;
    delete[]temp;

}


void AES::InvSubBytes(unsigned char** state)
{
    int i, j;
    unsigned char t;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            t = state[i][j];
            state[i][j] = inv_sbox[t / 16][t % 16];
        }
    }
}


unsigned char AES::mul_bytes(unsigned char a, unsigned char b) // multiplication a and b in galois field
{
    unsigned char p = 0;
    unsigned char high_bit_mask = 0x80;
    unsigned char high_bit = 0;
    unsigned char modulo = 0x1B; /* x^8 + x^4 + x^3 + x + 1 */


    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }

        high_bit = a & high_bit_mask;
        a <<= 1;
        if (high_bit) {
            a ^= modulo;
        }
        b >>= 1;
    }

    return p;
}


void AES::InvMixColumns(unsigned char** state)
{
    unsigned char s[4], s1[4];
    int i, j;

    for (j = 0; j < Nb; j++)
    {
        for (i = 0; i < 4; i++)
        {
            s[i] = state[i][j];
        }
        s1[0] = mul_bytes(0x0e, s[0]) ^ mul_bytes(0x0b, s[1]) ^ mul_bytes(0x0d, s[2]) ^ mul_bytes(0x09, s[3]);
        s1[1] = mul_bytes(0x09, s[0]) ^ mul_bytes(0x0e, s[1]) ^ mul_bytes(0x0b, s[2]) ^ mul_bytes(0x0d, s[3]);
        s1[2] = mul_bytes(0x0d, s[0]) ^ mul_bytes(0x09, s[1]) ^ mul_bytes(0x0e, s[2]) ^ mul_bytes(0x0b, s[3]);
        s1[3] = mul_bytes(0x0b, s[0]) ^ mul_bytes(0x0d, s[1]) ^ mul_bytes(0x09, s[2]) ^ mul_bytes(0x0e, s[3]);

        for (i = 0; i < 4; i++)
        {
            state[i][j] = s1[i];
        }
    }
}

void AES::InvShiftRows(unsigned char** state)
{
    ShiftRow(state, 1, Nb - 1);
    ShiftRow(state, 2, Nb - 2);
    ShiftRow(state, 3, Nb - 3);
}

void AES::XorBlocks(unsigned char* a, unsigned char* b, unsigned char* c, unsigned int len)
{
    for (unsigned int i = 0; i < len; i++)
    {
        c[i] = a[i] ^ b[i];
    }
}

void AES::printHexArray(unsigned char a[], unsigned int n)
{
    for (unsigned int i = 0; i < n; i++) {
        printf("%02x ", a[i]);
    }
}