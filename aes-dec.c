#include <stdio.h>

/* gmult(a,b) returns the finite field multiplication of two numbers. 
 * Based on http://en.wikipedia.org/w/index.php?title=Finite_field_arithmetic&oldid=313340001#Program_examples 
*/
int gf_grid[256][256];
int gf_grid_inv[256];
int gf_grid_shi[256];
int gf_grid_shi_inv[256];
int grid_shi[256];
/* Multiply two numbers in the GF(2^8) finite field defined 
 * by the polynomial x^8 + x^4 + x^3 + x + 1 */
typedef unsigned char uint8_t;
uint8_t gmult(uint8_t a, uint8_t b) {
	uint8_t x=a, y=b;
	uint8_t p = 0;
	uint8_t counter;
	uint8_t hi_bit_set;
		if (gf_grid[x][y]>=0) return gf_grid[x][y];

	for(counter = 0; counter < 8; counter++) {
		if(b & 1) 
			p ^= a;
		hi_bit_set = (a & 0x80);
		a <<= 1;
		if(hi_bit_set) 
			a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
		b >>= 1;
	}
	if (p==1)
	{
		gf_grid_inv[x]=y;
		//gf_grid_inv[y]=x;
	}
	return gf_grid[x][y]=p;

	//return p;
}

/*unsigned int gmult(unsigned int a, unsigned int b)
{
	unsigned int r=0;
	unsigned int it=0;
	unsigned int x=a&0xff, y=b&0xff;
	if (gf_grid[x][y]>=0) return gf_grid[x][y];

	for (it=0; it<8; ++it)
	{
		if (a&1)
		{
			r^=b&0xff;
		}
		b<<=1;
		if (b&0x100)
			b^=0x11b;
		a>>=1;
	}

	if (r==1)
	{
		gf_grid_inv[x]=y;
		gf_grid_inv[y]=x;
	}
	return gf_grid[x][y]=r;
}*/

/* Algorithm based on http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf */
/* nk (key length) = 4, Nb (Block Size)=4, Nr (Rounds) = 10 */
/* For AES-192, nk (key length) = 6, Nb (Block Size)=4, Nr (Rounds) = 12 */
/* For AES-256, nk (key length) = 8, Nb (Block Size)=4, Nr (Rounds) = 14 */
//int nk=4, nb=4, nr=10;
#define NK 4
#define NB 4
#define NR 10
void SubBytes(unsigned char state[4*NB]);
void ShiftRows(unsigned char state[4*NB]);
void MixColumns(unsigned char state[4*NB]);
void AddRoundKey(unsigned char state[4*NB], unsigned int *w);
int Rcon[] =
{
	0, 0x01000000,0x02000000,0x04000000,0x08000000,
	0x10000000,0x20000000,0x40000000,0x80000000,
	0x1b000000,0x36000000
};
void Cipher (unsigned char *in, unsigned char *out, unsigned int *w)
{
	unsigned int i;
	unsigned int x,y;
	unsigned int round;
	unsigned char state[4*NB];
	for (y=0; y<4; ++y)
		for (x=0; x<NB; ++x)
		{
			state[y*4+x]=in[y*4+x];
		}

	printf ("%dA: ",0);
	for (i=0; i<16; ++i)
	{
		printf ("%02x", state[i]); 
	}
	printf ("\n");
		AddRoundKey(state, w);
	printf ("%dB: ",0);
	for (i=0; i<16; ++i)
	{
		printf ("%02x", state[i]); 
	}
	printf ("\n");

	for (round=1; round<NR; ++round)
	{
		/*printf ("round[%d].input =",round);
		for (i=0; i<16; ++i)
		{
			printf ("%02x", state[i]); 
		}
		printf ("\n");*/
	printf ("%dA: ", round);
	for (i=0; i<16; ++i)
	{
		if (i%4==0) printf (" ");
		printf ("%02x", state[i]); 
	}
	printf ("\n");
		SubBytes(state);
	printf ("%dB: ", round);
	for (i=0; i<16; ++i)
	{
		if (i%4==0) printf (" ");
		printf ("%02x", state[i]); 
	}
	printf ("\n");
		ShiftRows(state);
	printf ("%dC: ", round);
	for (i=0; i<16; ++i)
	{
		if (i%4==0) printf (" ");
		printf ("%02x", state[i]); 
	}
	printf ("\n");
		MixColumns(state);
	printf ("%dD: ", round);
	for (i=0; i<16; ++i)
	{
		if (i%4==0) printf (" ");
		printf ("%02x", state[i]); 
	}
	printf ("\n");
	printf ("%dR: ", round);
	for (i=0; i<4; ++i)
	{
		//if (i%4==0) printf (" ");
		printf (" %08x", (w+(round*NB))[i]); 
	}
	printf ("\n");
		AddRoundKey(state, w+(round*NB));
	printf ("%dE: ", round);
	for (i=0; i<16; ++i)
	{
		if (i%4==0) printf (" ");
		printf ("%02x", state[i]); 
	}
	printf ("\n");
	}
	printf ("%dA: ", round);
	for (i=0; i<16; ++i)
	{
		if (i%4==0) printf (" ");
		printf ("%02x", state[i]); 
	}
	printf ("\n");
	SubBytes(state);
	printf ("%dB: ", round);
	for (i=0; i<16; ++i)
	{
		if (i%4==0) printf (" ");
		printf ("%02x", state[i]); 
	}
	printf ("\n");
	ShiftRows(state);
	printf ("%dC: ", round);
	for (i=0; i<16; ++i)
	{
		if (i%4==0) printf (" ");
		printf ("%02x", state[i]); 
	}
	printf ("\n");
	printf ("%dR: ", round);
	for (i=0; i<4; ++i)
	{
		//if (i%4==0) printf (" ");
		printf (" %08x", (w+(round*NB))[i]); 
	}
	printf ("\n");
	AddRoundKey(state, w+(NR*NB));
	printf ("Out: ", round);
	for (i=0; i<16; ++i)
	{
		if (i%4==0) printf (" ");
		printf ("%02x", state[i]); 
	}
	printf ("\n");

	for (y=0; y<4; ++y)
		for (x=0; x<NB; ++x)
		{
			out[y*4+x]=state[y*4+x];
		}
}

#define BIT(a,b) ( ((a)>>(b)) &1)
unsigned int SubChar(unsigned int val )
{
	unsigned int oval=(val&=0xff);
	val&=0xff;
	if (gf_grid_shi[val]>=0)
	{
		return gf_grid_shi[val];
	} 
	val=gf_grid_inv[val];
	unsigned int nval=0;//gf_grid_inv[val];
	nval|=(BIT(val,0) ^ BIT(val,4) ^ BIT(val,5) ^ BIT(val,6) ^ BIT(val,7)^1);
	nval|=(BIT(val,1) ^ BIT(val,5) ^ BIT(val,6) ^ BIT(val,7) ^ BIT(val,0)^1)<<1;
	nval|=(BIT(val,2) ^ BIT(val,6) ^ BIT(val,7) ^ BIT(val,0) ^ BIT(val,1))<<2;
	nval|=(BIT(val,3) ^ BIT(val,7) ^ BIT(val,0) ^ BIT(val,1) ^ BIT(val,2))<<3;
	nval|=(BIT(val,4) ^ BIT(val,0) ^ BIT(val,1) ^ BIT(val,2) ^ BIT(val,3))<<4;
	nval|=(BIT(val,5) ^ BIT(val,1) ^ BIT(val,2) ^ BIT(val,3) ^ BIT(val,4)^1)<<5;
	nval|=(BIT(val,6) ^ BIT(val,2) ^ BIT(val,3) ^ BIT(val,4) ^ BIT(val,5)^1)<<6;
	nval|=(BIT(val,7) ^ BIT(val,3) ^ BIT(val,4) ^ BIT(val,5) ^ BIT(val,6))<<7;
	//nval=gf_grid_inv[val];
	gf_grid_shi_inv[nval]=oval;
	return gf_grid_shi[oval]=nval;
}
unsigned int SubInt(unsigned int val)
{
	return (SubChar(val>>24)<<24)+(SubChar(val>>16)<<16)+(SubChar(val>>8)<<8)+(SubChar(val));
}
void SubBytes(unsigned char state[4*NB])
{
	unsigned int i;
	unsigned int val; 
	unsigned int nval;

	for (i=0; i<4*NB; ++i)
	{
		state[i]=SubChar(state[i]);
	}
}


void ShiftRows(unsigned char state[4*NB])
{
	unsigned char statep[4*NB];
	unsigned int x,y;

	for (y=0; y<4; ++y)
	{
		for (x=0; x<4; ++x)
		{
			statep[y*4+x]=state[(y+x)%4*4+x];
		}
	}
	for (y=0; y<4; ++y)
	{
		for (x=0; x<4; ++x)
		{
			state[y*4+x]=statep[y*4+x];
		}
	}

}

void MixColumns(unsigned char state[4*NB])
{
	unsigned char statep[4*NB];
	unsigned int x,y;

	for (x=0; x<4; ++x)
	{
		statep[x*4+0]=gmult(2,state[x*4+0]) ^ gmult(3,state[x*4+1]) ^gmult(1,state[x*4+2]) ^gmult(1,state[x*4+3]) ;
		statep[x*4+1]=gmult(1,state[x*4+0]) ^ gmult(2,state[x*4+1]) ^gmult(3,state[x*4+2]) ^gmult(1,state[x*4+3]) ;
		statep[x*4+2]=gmult(1,state[x*4+0]) ^ gmult(1,state[x*4+1]) ^gmult(2,state[x*4+2]) ^gmult(3,state[x*4+3]) ;
		statep[x*4+3]=gmult(3,state[x*4+0]) ^ gmult(1,state[x*4+1]) ^gmult(1,state[x*4+2]) ^gmult(2,state[x*4+3]) ;
	}
	for (y=0; y<4; ++y)
	{
		for (x=0; x<4; ++x)
		{
			state[y*4+x]=statep[y*4+x];
		}
	}

}

void AddRoundKey(unsigned char state[4*NB], unsigned int *w)
{
	unsigned int x,y;
//	for (x=0; x<4; x++)
//	{
		for (y=0; y<4; y++)
		{
			state[y*4+0]^=w[y]>>24;
			state[y*4+1]^=w[y]>>16;
			state[y*4+2]^=w[y]>>8;
			state[y*4+3]^=w[y]>>0;
		}
//	}
}

unsigned int RotWord( unsigned int i)
{
	return (i<<8) + ((i>>24)&0xff);
}
unsigned int *KeyExpansion(unsigned char key[4*NK])
{
	static unsigned int w[NB*(NR+1)];
	unsigned int temp;
	unsigned int i=0;

	for (i=0; i<NK; ++i)
	{
		w[i]=(key[4*i]<<24) +(key[4*i+1]<<16) +(key[4*i+2]<<8) +(key[4*i+3]);
	}
	for (i=NK; i<NB*(NR+1); ++i)
	{
		temp=w[i-1];
		if (i%NK==0)
		{
			temp=RotWord(temp);
			temp=SubInt(temp);

			temp=temp^Rcon[i/NK];
		} else if (NK>6 && i%NK==4)
		{
			temp=SubInt(temp);
		}

		w[i]=w[i-NK]^temp;
	}
	return w;
}


int init()
{
	int x,y;
	for (y=0; y<256; ++y)
	{
		for (x=0; x<256; ++x)
		{
			gf_grid[x][y]=-1;
			gmult(x,y);
			//printf ("%d\t", gf_grid[x][y]);
		}
		gf_grid_shi[y]=-1;
		grid_shi[y]=-1;
		//printf ("\n", gf_grid[x][y]);
	}
	for (y=0; y<256; ++y)
	{
		SubChar(y);
	}
}

void InvShiftRows(unsigned char state[4*NB])
{
	unsigned char statep[4*NB];
	unsigned int x,y;

	for (y=0; y<4; ++y)
	{
		for (x=0; x<4; ++x)
		{
			statep[(y+x)%4*4+x]=state[y*4+x];
		}
	}
	for (y=0; y<4; ++y)
	{
		for (x=0; x<4; ++x)
		{
			state[y*4+x]=statep[y*4+x];
		}
	}

}

void InvSubBytes(unsigned char state[4*NB])
{
	unsigned int i;
	unsigned int val; 
	unsigned int nval;

	for (i=0; i<4*NB; ++i)
	{
		state[i]=gf_grid_shi_inv[state[i]];
	}
}

void InvMixColumns(unsigned char state[4*NB])
{
	unsigned char statep[4*NB];
	unsigned int x,y;

	for (x=0; x<4; ++x)
	{
		statep[x*4+0]=gmult(0x0e,state[x*4+0]) ^ gmult(0x0b,state[x*4+1]) ^gmult(0x0d,state[x*4+2]) ^gmult(0x09,state[x*4+3]) ;
		statep[x*4+1]=gmult(0x09,state[x*4+0]) ^ gmult(0x0e,state[x*4+1]) ^gmult(0x0b,state[x*4+2]) ^gmult(0x0d,state[x*4+3]) ;
		statep[x*4+2]=gmult(0x0d,state[x*4+0]) ^ gmult(0x09,state[x*4+1]) ^gmult(0x0e,state[x*4+2]) ^gmult(0x0b,state[x*4+3]) ;
		statep[x*4+3]=gmult(0x0b,state[x*4+0]) ^ gmult(0x0d,state[x*4+1]) ^gmult(0x09,state[x*4+2]) ^gmult(0x0e,state[x*4+3]) ;
	}
	for (y=0; y<4; ++y)
	{
		for (x=0; x<4; ++x)
		{
			state[y*4+x]=statep[y*4+x];
		}
	}

}


void InvCipher (unsigned char *in, unsigned char *out, unsigned int *w)
{
	unsigned int i;
	unsigned int x,y;
	unsigned int round;
	unsigned char state[4*NB];
	for (y=0; y<4; ++y)
		for (x=0; x<NB; ++x)
		{
			state[y*4+x]=in[y*4+x];
		}

	printf ("%dA: ",0);
	for (i=0; i<16; ++i)
	{
		printf ("%02x", state[i]); 
	}
	printf ("\n");
	AddRoundKey(state, w+(NR*NB));
	printf ("%dB: ",0);
	for (i=0; i<16; ++i)
	{
		printf ("%02x", state[i]); 
	}
	printf ("\n");

	for (round=NR-1; round>0; --round)
	{
		/*printf ("round[%d].input =",round);
		for (i=0; i<16; ++i)
		{
			printf ("%02x", state[i]); 
		}
		printf ("\n");*/
	printf ("%dA: ", round);
	for (i=0; i<16; ++i)
	{
		if (i%4==0) printf (" ");
		printf ("%02x", state[i]); 
	}
	printf ("\n");
		InvShiftRows(state);
	printf ("%dB: ", round);
	for (i=0; i<16; ++i)
	{
		if (i%4==0) printf (" ");
		printf ("%02x", state[i]); 
	}
	printf ("\n");
		InvSubBytes(state);
	printf ("%dC: ", round);
	for (i=0; i<16; ++i)
	{
		if (i%4==0) printf (" ");
		printf ("%02x", state[i]); 
	}
	printf ("\n");
	printf ("%dR: ", round);
	for (i=0; i<4; ++i)
	{
		//if (i%4==0) printf (" ");
		printf (" %08x", (w+(round*NB))[i]); 
	}
	printf ("\n");
		AddRoundKey(state, w+(round*NB));
	printf ("%dE: ", round);
	for (i=0; i<16; ++i)
	{
		if (i%4==0) printf (" ");
		printf ("%02x", state[i]); 
	}
	printf ("\n");
		InvMixColumns(state);
	}

	printf ("%dA: ", round);
	for (i=0; i<16; ++i)
	{
		if (i%4==0) printf (" ");
		printf ("%02x", state[i]); 
	}
	printf ("\n");
	InvShiftRows(state);
	printf ("%dB: ", round);
	for (i=0; i<16; ++i)
	{
		if (i%4==0) printf (" ");
		printf ("%02x", state[i]); 
	}
	printf ("\n");
	InvSubBytes(state);
	printf ("%dR: ", round);
	for (i=0; i<4; ++i)
	{
		//if (i%4==0) printf (" ");
		printf (" %08x", (w+(round*NB))[i]); 
	}
	printf ("\n");
	AddRoundKey(state, w);
	printf ("Out: ", round);
	for (i=0; i<16; ++i)
	{
		if (i%4==0) printf (" ");
		printf ("%02x", state[i]); 
	}
	printf ("\n");

	for (y=0; y<4; ++y)
		for (x=0; x<NB; ++x)
		{
			out[y*4+x]=state[y*4+x];
		}
}

void test(void);

int main (void)
{
	int x,y;
	init();
	/*for (y=0; y<16; ++y)
	{
		for (x=0; x<16; ++x)
		{
			printf ("%x ", SubChar(y*16+x));
		}
		printf ("\n");

	}
	exit(0);*/
	if (gmult(0x57, 0x83)!=0xc1)
	{
		printf ("gmult(0x57, 0x83)!=0xc1: %x\n", gmult(0x57, 0x83));
	}
	if (gmult(0x57, 0x02)!=0xae)
	{
		printf ("gmult(0x57, 0x02)!=0xfe: %x\n", gmult(0x57, 0x02));
	}
	if (gmult(0x57, 0x04)!=0x47)
	{
		printf ("gmult(0x57, 0x04)!=0xfe: %x\n", gmult(0x57, 0x04));
	}
	if (gmult(0x57, 0x08)!=0x8e)
	{
		printf ("gmult(0x57, 0x08)!=0xfe: %x\n", gmult(0x57, 0x08));
	}
	if (gmult(0x57, 0x10)!=0x07)
	{
		printf ("gmult(0x57, 0x13)!=0xfe: %x\n", gmult(0x57, 0x10));
	}
	if (gmult(0x57, 0x13)!=0xfe)
	{
		printf ("gmult(0x57, 0x13)!=0xfe: %x\n", gmult(0x57, 0x13));
	}

	test();

	printf ("\n");
}	

void test(void)
{
	unsigned char k1[16]= {
		//0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
		0x13,0x11,0x1d,0x7f ,0xe3,0x94,0x4a,0x17 ,0xf3,0x07,0xa7,0x8b ,0x4d,0x2b,0x30,0xc5
	};
	unsigned char pt[16] = 
	{
		//0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
		0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04, 0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
	};
	unsigned char ct[16];
	int i;
	int *w;

	for (i=0; i<16; ++i)
	{
		k1[i]=i;
		//pt[i]=i+(i<<4);
	}
	w=KeyExpansion(k1);

	InvCipher(pt, ct, w);

	for (i=0; i<16; ++i)
	{
		printf ("%02x", ct[i]); 
	}
}

