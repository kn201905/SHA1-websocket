#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <iostream>
#include <sstream>

// 24文字 ＋ 36文字（vmovdqa を利用するため、32バイトアライメントが必要）
// static char __attribute__ ((aligned (32))) sa_WS_Key_24chr[64]
//	= "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	//	b3 7a 4f 2c  c0 62 4f 16  90 f6 46 06  cf 38 59 45  b2 be c4 ea
	// s3pP LMBi TxaQ 9kYG zzhZ RbK+ xOo=

//static char __attribute__ ((aligned (32))) sa_WS_Key_24chr[64]
//	= "E4WSEcseoWr4csPLS2QJHA==258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	// ed e4 02 86  00 ad 40 c9  d5 20 b7 9f  24 03 ba 74  ae 49 c0 f7 
	// 7eQC hgCt QMnV ILef JAO6 dK5J wPc=

static char __attribute__ ((aligned (32))) sa_WS_Key_24chr[64]
	= "zYuFKiL/3y3UA63cCi8V6g==258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	// 7f 8b ce b1  ca 9f ab b2  fa ab 7a f2  79 89 4a 73  db f6 98 e5
	// f4vO scqf q7L6 q3ry eYlK c9v2 mOU=


extern "C" void sha1_update_intel(uint8_t* o_pbase64, const char* i_pbuf_to24chr);
//extern "C" void  sha1_update_intel(uint32_t* o_pHash, const char* i_pBuffer, uint8_t* o_pW_asm);

extern "C" void  sha1_init_once();


/////////////////////////////////////////////////////////////////////////////////////

uint8_t*  G_cout_16bytes(uint8_t* psrc)
{
	auto  tohex = [](uint8_t chr) -> char { return  chr < 10 ? chr + 0x30 : chr + 0x30 + 7 + 0x20; };
	char  hex[4] = { 0, 0, 0x20, 0 };
	std::string  str;

	for (int i = 0; i < 16; ++i)
	{
		uint8_t  a = *psrc++;
		hex[0] = tohex( a >> 4 );
		hex[1] = tohex( a & 0xf );
		str += hex;

		if ((i & 3) == 3) { str += ' '; }
	}
	std::cout << str << std::endl;

	return  psrc;
}

void  G_cout_ui32(uint32_t srcval)
{
	auto  tohex = [](uint8_t chr) -> char { return  chr < 10 ? chr + 0x30 : chr + 0x30 + 7 + 0x20; };
	auto  cout_bytes = [&](uint8_t byte, char* pdst) {
		*pdst++ = tohex( byte >> 4);
		*pdst = tohex( byte & 0xf );
	};
	char  hexes[] = "00 00 00 00  ";

	cout_bytes( srcval >> 24, hexes);

	srcval &= 0xff'ffff;
	cout_bytes( srcval >> 16, hexes + 3);

	srcval &= 0xffff;
	cout_bytes( srcval >> 8, hexes + 6);

	cout_bytes( srcval & 0xff, hexes + 9);

	std::cout << hexes;
}

void  G_out_ui32_8(uint32_t* psrc_ui32)
{
	for (int i = 0; i < 4; ++i)
	{ G_cout_ui32(*psrc_ui32++); }
	std::cout << ' ';

	for (int i = 0; i < 4; ++i)
	{ G_cout_ui32(*psrc_ui32++); }
	std::cout << std::endl;
}

void  G_out_ui8_32(const uint8_t* psrc_ui8)
{
	for (int i = 0; i < 4; ++i)
	{
		uint32_t  val_ui32 = (*psrc_ui8++ << 24) + (*psrc_ui8++ << 16) + (*psrc_ui8++ << 8) + *psrc_ui8++;
		G_cout_ui32(val_ui32);
	}
	std::cout << ' ';

	for (int i = 0; i < 4; ++i)
	{
		uint32_t  val_ui32 = (*psrc_ui8++ << 24) + (*psrc_ui8++ << 16) + (*psrc_ui8++ << 8) + *psrc_ui8++;
		G_cout_ui32(val_ui32);
	}
	std::cout << std::endl;
}

void  G_out_ui8_32chr(const char* psrc)
{
	char  str[32 + 9 + 1];		// スペース 9文字 + \0
	char*  pdst = str;
	for (int i = 0; i < 32; ++i)
	{
		*pdst++ = *psrc++;
		if ((i & 3) == 3)
		{
			*pdst++ = 0x20;
			if (i == 15) { *pdst++ = 0x20; }
		}
	}
	*pdst = 0;

	std::cout << str << std::endl;
}


/////////////////////////////////////////////////////////////////////////////////////

int main()
{
    uint8_t __attribute__ ((aligned (16))) base64[32];
	memset(base64, 0, sizeof(base64));

	// アセンブラ内での W情報
	uint8_t __attribute__ ((aligned (32))) W_asm[320];
	memset(W_asm, 0, sizeof(W_asm));

	// ----------------------------------------
	// アセンブラルーチン呼び出し
	sha1_init_once();
	sha1_update_intel(base64, sa_WS_Key_24chr);


	// ----------------------------------------
	// base64 値のダンプ
	std::cout << std::endl;
	std::cout << "base64 ダンプ" << std::endl;
	G_out_ui8_32(base64);
	G_out_ui8_32chr((char*)base64);

    return  0;
}
