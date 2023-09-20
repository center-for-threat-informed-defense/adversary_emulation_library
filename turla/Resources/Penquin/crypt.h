// crypt.h:
//		1. Encrypt functions to obfuscate strings at compile time
//		2. Decrypt fuctions to translate strings at runtime
//	MITRE ATT&CK Techniques:
//		T1027 : Obfuscated Files or Information   
//	Adapted for ATT&CK Evaluations 2023 from the following resource:
//		https://github.com/BroOfBros/C-Cpp-Macro-Encryption/blob/master/Crypt.h   


#ifndef CRYPT
#define CRYPT
#include <stdlib.h>
#include <string.h>

// XOR Key snake == змея == 0xd0b7d0bcd0b5d18f
#define XORKEY "zmey"
#ifndef __SHIFT_KEY

//0x736e616b65 == snake in hex
#define __SHIFT_KEY (0x736e616b65)
#endif

#ifndef __SHIFT64

#define __SHIFT64(__String) \
(((__String)[0] + __SHIFT_KEY) ^XORKEY[0]), (((__String)[1] + __SHIFT_KEY) ^XORKEY[1]), (((__String)[2] + __SHIFT_KEY) ^XORKEY[2]), (((__String)[3] + __SHIFT_KEY) ^XORKEY[3]), \
(((__String)[4] + __SHIFT_KEY) ^XORKEY[0]), (((__String)[5] + __SHIFT_KEY) ^XORKEY[1]), (((__String)[6] + __SHIFT_KEY) ^XORKEY[2]), (((__String)[7] + __SHIFT_KEY) ^XORKEY[3]), \
(((__String)[8] + __SHIFT_KEY) ^XORKEY[0]), (((__String)[9] + __SHIFT_KEY) ^XORKEY[1]), (((__String)[10] + __SHIFT_KEY) ^XORKEY[2]), (((__String)[11] + __SHIFT_KEY) ^XORKEY[3]), \
(((__String)[12] + __SHIFT_KEY) ^XORKEY[0]), (((__String)[13] + __SHIFT_KEY) ^XORKEY[1]), (((__String)[14] + __SHIFT_KEY) ^XORKEY[2]), (((__String)[15] + __SHIFT_KEY) ^XORKEY[3]), \
(((__String)[16] + __SHIFT_KEY) ^XORKEY[0]), (((__String)[17] + __SHIFT_KEY) ^XORKEY[1]), (((__String)[18] + __SHIFT_KEY) ^XORKEY[2]), (((__String)[19] + __SHIFT_KEY) ^XORKEY[3]), \
(((__String)[20] + __SHIFT_KEY) ^XORKEY[0]), (((__String)[21] + __SHIFT_KEY) ^XORKEY[1]), (((__String)[22] + __SHIFT_KEY) ^XORKEY[2]), (((__String)[23] + __SHIFT_KEY) ^XORKEY[3]), \
(((__String)[24] + __SHIFT_KEY) ^XORKEY[0]), (((__String)[25] + __SHIFT_KEY) ^XORKEY[1]), (((__String)[26] + __SHIFT_KEY) ^XORKEY[2]), (((__String)[27] + __SHIFT_KEY) ^XORKEY[3]), \
(((__String)[28] + __SHIFT_KEY) ^XORKEY[0]), (((__String)[29] + __SHIFT_KEY) ^XORKEY[1]), (((__String)[30] + __SHIFT_KEY) ^XORKEY[2]), (((__String)[31] + __SHIFT_KEY) ^XORKEY[3]), \
(((__String)[32] + __SHIFT_KEY) ^XORKEY[0]), (((__String)[33] + __SHIFT_KEY) ^XORKEY[1]), (((__String)[34] + __SHIFT_KEY) ^XORKEY[2]), (((__String)[35] + __SHIFT_KEY) ^XORKEY[3]), \
(((__String)[36] + __SHIFT_KEY) ^XORKEY[0]), (((__String)[37] + __SHIFT_KEY) ^XORKEY[1]), (((__String)[38] + __SHIFT_KEY) ^XORKEY[2]), (((__String)[39] + __SHIFT_KEY) ^XORKEY[3]), \
(((__String)[40] + __SHIFT_KEY) ^XORKEY[0]), (((__String)[41] + __SHIFT_KEY) ^XORKEY[1]), (((__String)[42] + __SHIFT_KEY) ^XORKEY[2]), (((__String)[43] + __SHIFT_KEY) ^XORKEY[3]), \
(((__String)[44] + __SHIFT_KEY) ^XORKEY[0]), (((__String)[45] + __SHIFT_KEY) ^XORKEY[1]), (((__String)[46] + __SHIFT_KEY) ^XORKEY[2]), (((__String)[47] + __SHIFT_KEY) ^XORKEY[3]), \
(((__String)[48] + __SHIFT_KEY) ^XORKEY[0]), (((__String)[49] + __SHIFT_KEY) ^XORKEY[1]), (((__String)[50] + __SHIFT_KEY) ^XORKEY[2]), (((__String)[51] + __SHIFT_KEY) ^XORKEY[3]), \
(((__String)[52] + __SHIFT_KEY) ^XORKEY[0]), (((__String)[53] + __SHIFT_KEY) ^XORKEY[1]), (((__String)[54] + __SHIFT_KEY) ^XORKEY[2]), (((__String)[55] + __SHIFT_KEY) ^XORKEY[3]), \
(((__String)[56] + __SHIFT_KEY) ^XORKEY[0]), (((__String)[57] + __SHIFT_KEY) ^XORKEY[1]), (((__String)[58] + __SHIFT_KEY) ^XORKEY[2]), (((__String)[59] + __SHIFT_KEY) ^XORKEY[3]), \
(((__String)[60] + __SHIFT_KEY) ^XORKEY[0]), (((__String)[61] + __SHIFT_KEY) ^XORKEY[1]), (((__String)[62] + __SHIFT_KEY) ^XORKEY[2]), (((__String)[63] + __SHIFT_KEY) ^XORKEY[3]),	'\0'
#endif

#ifndef __ENCRYPT64

//Less than 64 characters
#define __ENCRYPT64(__String) { __SHIFT64(__String"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0") }
#endif

char * __DECRYPT64(char *EncryptedString)
{
    //assumes no larger than 64 characters
    char *NormalizedString = (char *)calloc(64, sizeof(char));
	int index = 0;
	int keyLength = strlen(XORKEY);
	for (int i = 0; i < 64; i++)
	{
		char NormalizedChar = (EncryptedString[i] ^XORKEY[i % 4]) - __SHIFT_KEY;
		if (NormalizedChar)
			NormalizedString[index++] = NormalizedChar;
	}
	NormalizedString = (char *)realloc(NormalizedString, index * sizeof(char) + 1);
	strcpy(EncryptedString, NormalizedString);
	free(NormalizedString);
	return EncryptedString;
}
#endif
