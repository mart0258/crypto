#include <stdio.h>

#define BIT(a,b) ( ((a)>>(b)) &1)

void printoutput(char *text, int id, char *hex, int l);
void printoutput(char *text, int id, unsigned char *hex, int l);
void printoutput(char *text, int id, unsigned int *hex, int l);

class finite_field
{
	int poly; 
	int gf_mult[256][256]; /* a * b = ? */
	int gf_mult_inv[256]; /* a * ? = 1 */
	int gf_grid_sub[256];
	int gf_grid_subinv[256];

	int gmult_init(int a, int b)
	{
		int i;
		int p=0;
		for (i=0; i<8; ++i)
		{
			if (b&1) p^=a;
			a <<=1;
			if (a&0x100) a^=poly; 
			b >>=1;
		}
		return p; 
	}

	unsigned int subchar_init(unsigned int val )
	{
		val=gf_mult_inv[val&0xff];
		unsigned int nval=0;//gf_grid_inv[val];
		nval|=(BIT(val,0) ^ BIT(val,4) ^ BIT(val,5) ^ BIT(val,6) ^ BIT(val,7)^1);
		nval|=(BIT(val,1) ^ BIT(val,5) ^ BIT(val,6) ^ BIT(val,7) ^ BIT(val,0)^1)<<1;
		nval|=(BIT(val,2) ^ BIT(val,6) ^ BIT(val,7) ^ BIT(val,0) ^ BIT(val,1))<<2;
		nval|=(BIT(val,3) ^ BIT(val,7) ^ BIT(val,0) ^ BIT(val,1) ^ BIT(val,2))<<3;
		nval|=(BIT(val,4) ^ BIT(val,0) ^ BIT(val,1) ^ BIT(val,2) ^ BIT(val,3))<<4;
		nval|=(BIT(val,5) ^ BIT(val,1) ^ BIT(val,2) ^ BIT(val,3) ^ BIT(val,4)^1)<<5;
		nval|=(BIT(val,6) ^ BIT(val,2) ^ BIT(val,3) ^ BIT(val,4) ^ BIT(val,5)^1)<<6;
		nval|=(BIT(val,7) ^ BIT(val,3) ^ BIT(val,4) ^ BIT(val,5) ^ BIT(val,6))<<7;
		return nval;
	}


public: 
	int add (int a, int b)
	{
		return a^b;
	}

	int mult(unsigned char a, unsigned char b)
	{
		//return gmult_init(a,b);
		return gf_mult[a][b];
	}

	int subchar(unsigned char a)
	{
		//return subchar_init(a);
		return gf_grid_sub[a];
	}

	int invsubchar(unsigned char a)
	{
		return gf_grid_subinv[a];
	}

	static finite_field *init(int p)
	{
		finite_field *ret = new finite_field();
		ret->poly=p;
		for (int x=0; x<256; ++x)
			for (int y=0; y<256; ++y)
			{
				int z=ret->gmult_init(x,y);
				if (z==1) ret->gf_mult_inv[x]=y;
				ret->gf_mult[x][y]=z;
			}
		ret->gf_mult_inv[0]=0;

		for (int x=0; x<256; ++x)
		{
			int y=ret->subchar_init(x);
			ret->gf_grid_sub[x]=y;
			ret->gf_grid_subinv[y]=x;
		}
		return ret; 
	}
};

class rijndael
{
protected:
	int nk; /* Key length. AES standard uses 4, 6, or 8.  */
	int nb; /* Block size/number of columns. AES standard uses 4. */
	int nr; /* Number of rounds. AES standard uses 10, 12, 14 */
	int poly; 
	finite_field *field;
	char *state;
	char *statep;

	inline unsigned int RotWord( unsigned int i)
	{
		return (i<<8) + ((i>>24)&0xff);
	}
	unsigned int SubInt(unsigned int val)
	{
		return (field->subchar((val>>24)&0xff)<<24)+(field->subchar((val>>16)&0xff)<<16)+
			(field->subchar((val>>8)&0xff)<<8)+(field->subchar(val&0xff));
	}


	unsigned int *expandkey(unsigned char *key)
	{
		unsigned int *w = new unsigned int[nb*(nr+1)];
		unsigned int temp;
		unsigned int i=0;

		for (i=0; i<nk; ++i)
		{
			w[i]=(key[4*i]<<24) +(key[4*i+1]<<16) +(key[4*i+2]<<8) +(key[4*i+3]);
		}
		unsigned int rcon=1;
		for (i=nk; i<nb*(nr+1); ++i)
		{
			int imnk=i%nk;
			temp=w[i-1];
			if (imnk==0)
			{
				temp=RotWord(temp);
				temp=SubInt(temp);

				temp=temp^(rcon << 24);
				rcon=field->mult(rcon, 2);
			} else if (nk>6 && (imnk&0x3)==0) // Original spec was imnk = 4, this handles nk>8)
			{
				temp=SubInt(temp);
			}

			w[i]=w[i-nk]^temp;
		}
		return w;
	}

	void SubBytes()
	{
		for (int i=0; i<4*nb; ++i)
		{
			state[i]=field->subchar(state[i]);
		}
	}

/*
	for (y=0; y<4; ++y)
	{
		for (x=0; x<4; ++x)
		{
			statep[y*4+x]=state[(y+x)%4*4+x];
		}
	}*/
	void ShiftRows()
	{
		unsigned int r,c;

		for (c=0; c<nb; ++c)
		{
			for (r=0; r<4; ++r)
			{
				statep[c*4+r]=state[((c+r)%nb)*4 +r];
			}
		}
		for (c=0; c<4*nb; ++c)
		{
			state[c]=statep[c];
		}
	}

	void MixColumns()
	{
		unsigned int x,y;

/*printf ("%02x %02x %02x %02x\n", field->mult(2,state[+0]),
		field->mult(3,state[+1]),
		field->mult(1,state[+2]),
		field->mult(1,state[+3])) ;

printf ("%02x %02x %02x %02x\n", field->mult(1,state[+0]),
		field->mult(1,state[+1]),
		field->mult(1,state[+2]),
		field->mult(1,state[+3])) ;*/

		for (x=0; x<nb; ++x)
		{
			statep[x*4+0]=field->mult(2,state[x*4+0]) ^ field->mult(3,state[x*4+1]) ^field->mult(1,state[x*4+2]) ^field->mult(1,state[x*4+3]) ;
			statep[x*4+1]=field->mult(1,state[x*4+0]) ^ field->mult(2,state[x*4+1]) ^field->mult(3,state[x*4+2]) ^field->mult(1,state[x*4+3]) ;
			statep[x*4+2]=field->mult(1,state[x*4+0]) ^ field->mult(1,state[x*4+1]) ^field->mult(2,state[x*4+2]) ^field->mult(3,state[x*4+3]) ;
			statep[x*4+3]=field->mult(3,state[x*4+0]) ^ field->mult(1,state[x*4+1]) ^field->mult(1,state[x*4+2]) ^field->mult(2,state[x*4+3]) ;
		}
		for (y=0; y<4*nb; ++y)
			state[y]=statep[y];

	}

	void AddRoundKey(unsigned int *w)
	{
		unsigned int y;
		for (y=0; y<nb; y++)
		{
			state[y*4+0]^=w[y]>>24;
			state[y*4+1]^=w[y]>>16;
			state[y*4+2]^=w[y]>>8;
			state[y*4+3]^=w[y]>>0;
		}
	}

	void InvShiftRows()
	{
		unsigned int x,y;

		for (y=0; y<nb; ++y)
		{
			for (x=0; x<4; ++x)
			{
				statep[(y+x)%nb*4 +x]=state[y*4+x];
			}
		}
		for (y=0; y<4*nb; ++y)
		{
			state[y]=statep[y];
		}
	}

	void InvSubBytes()
	{
		for (int i=0; i<4*nb; ++i)
		{
			state[i]=field->invsubchar(state[i]);
		}
	}

	void InvMixColumns()
	{
		unsigned int x,y;

		for (x=0; x<4; ++x)
		{
			statep[x*4+0]=field->mult(14,state[x*4+0]) ^ field->mult(11,state[x*4+1]) ^field->mult(13,state[x*4+2]) ^field->mult( 9,state[x*4+3]) ;
			statep[x*4+1]=field->mult( 9,state[x*4+0]) ^ field->mult(14,state[x*4+1]) ^field->mult(11,state[x*4+2]) ^field->mult(13,state[x*4+3]) ;
			statep[x*4+2]=field->mult(13,state[x*4+0]) ^ field->mult( 9,state[x*4+1]) ^field->mult(14,state[x*4+2]) ^field->mult(11,state[x*4+3]) ;
			statep[x*4+3]=field->mult(11,state[x*4+0]) ^ field->mult(13,state[x*4+1]) ^field->mult( 9,state[x*4+2]) ^field->mult(14,state[x*4+3]) ;
		}
		for (y=0; y<4*nb; ++y)
			state[y]=statep[y];

	}

public:
	rijndael(): nk(8), nb(4), nr(14), poly(0x11b)
	{
		field = finite_field::init(poly);
	}
	
	void init (int _nk, int _nb, int _nr, int _poly = 0x11b)
	{
		nk=_nk; nb=_nb; nr=_nr;
		if (poly!=_poly)
		{
			poly=_poly;
			field = finite_field::init(poly);
		}
	}

	void encode (unsigned char *in, unsigned char *out, unsigned int *w)
	{
		state = new char[4*nb];
		statep = new char[4*nb];
		int i;

		for (i=0; i<4*nb; ++i)
			state[i]=in[i];
		AddRoundKey(w);
		//printoutput("Rkv %d", 0, w, nb);

		for (int round=1; round < nr; ++round)
		{
			//printoutput("round %2d", round, state, 4*nb);
			SubBytes();
			//printoutput("after sb" , round, state, 4*nb);
			ShiftRows();
			//printoutput("after sr", round, state, 4*nb);
			MixColumns();
			//printoutput("after mc", round, state, 4*nb);
			AddRoundKey(w+round*nb);
			//printoutput("Rkv %d =", round, w+round*nb, nb);
		}

		//printoutput("round %2d", nr, state, 4*nb);
		SubBytes();
		//printoutput("after sb" , nr, state, 4*nb);
		ShiftRows();
		//printoutput("after sr", nr, state, 4*nb);
		AddRoundKey(w+nr*nb);
		//printoutput("Rkv %d =", nr, w+nr*nb, nb);

		for (i=0; i<4*nb; ++i)
			out[i]=state[i];
		for (i=0; i<4*nb; ++i)
			statep[i]=0;
		delete [] state;
		delete [] statep;
	}
	void encode(unsigned char *in, unsigned char *out, unsigned char *key)
	{
		int i;
		unsigned int *w = expandkey(key);
		encode(in, out, w);
		delete [] w;
	}
	void encode(char *in, char *out, char *key)
	{
		int i;
		unsigned int *w = expandkey((unsigned char*)key);
		encode((unsigned char *)in, (unsigned char *)out, w);
		delete [] w;
	}


	void decode (unsigned char *in, unsigned char *out, unsigned int *w)
	{
		state = new char[4*nb];
		statep = new char[4*nb];
		int i;

		for (i=0; i<4*nb; ++i)
			state[i]=in[i];

		AddRoundKey(w+nr*nb);

		for (int round=nr-1; round >0; --round)
		{
			InvShiftRows();
			InvSubBytes();
			AddRoundKey(w+round*nb);
			InvMixColumns();
		}
		InvShiftRows();
		InvSubBytes();
		AddRoundKey(w);

		for (i=0; i<4*nb; ++i)
			out[i]=state[i];
		for (i=0; i<4*nb; ++i)
			statep[i]=0;
		delete [] state;
		delete [] statep;
	}
	void decode(unsigned char *in, unsigned char *out, unsigned char *key)
	{
		int i;
		unsigned int *w = expandkey(key);
		decode(in, out, w);
		delete [] w;
	}
	void decode(char *in, char *out, char *key)
	{
		int i;
		unsigned int *w = expandkey((unsigned char*) key);
		decode((unsigned char *)in, (unsigned char *)out, w);
		delete [] w;
	}

};

void printoutput(char *text, int id, char *hex, int l)
{
	printf (text, id);
	for (int i=0; i<l; ++i)
	{
		printf (" %02x", (unsigned char)hex[i]);
	}
	printf ("\n");
}
void printoutput(char *text, int id, unsigned char *hex, int l)
{
	printf (text, id);
	for (int i=0; i<l; ++i)
	{
		printf (" %02x", (unsigned char)hex[i]);
	}
	printf ("\n");
}
void printoutput(char *text, int id, unsigned int *hex, int l)
{
	printf (text, id);
	for (int i=0; i<l; ++i)
	{
		printf (" %08x", hex[i]);
	}
	printf ("\n");
}


int main (void)
{
	rijndael aes_128;
	rijndael aes_192;
	rijndael aes_256;
	aes_128.init(4,4,10);
	aes_192.init(6,4,12);
	aes_256.init(8,4,14);

	char output[100];
	char output2[100];
	char app_b_example[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	char app_b_keycode[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	aes_128.encode(app_b_example, output, app_b_keycode);
	printoutput("App B Example:", 0, output, 16);

	char c1_pt[]={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
	char c1_ke[]={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	aes_128.encode(c1_pt, output, c1_ke);
	aes_128.decode(output, output2, c1_ke);
	printoutput ("C.1 AES-128 encode:", 0, output, 16);
	printoutput ("C.1 AES-128 decode:", 0, output2, 16);

	char c2_pt[]={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
	char c2_ke[]={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17};
	aes_192.encode(c2_pt, output, c2_ke);
	aes_192.decode(output, output2, c2_ke);
	printoutput ("C.2 AES-192 encode:", 0, output, 16);
	printoutput ("C.2 AES-192 decode:", 0, output2, 16);


	char c3_pt[]={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
	char c3_ke[]={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
	aes_256.encode(c3_pt, output, c3_ke);
	aes_256.decode(output, output2, c3_ke);
	printoutput ("C.3 AES-256 encode:", 0, output, 16);
	printoutput ("C.3 AES-256 decode:", 0, output2, 16);

}