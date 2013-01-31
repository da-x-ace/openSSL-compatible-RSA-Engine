#include <iostream>
#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include <vector>
#include <fstream>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include <sys/syscall.h>
#include <openssl/sha.h>


#define MODULUSSIZE 1024			//No. of bits in n
#define SIZE (MODULUSSIZE/8) 			//No of bytes in n
#define PRIMEBITS (MODULUSSIZE/2) 		
#define BUFSIZE (MODULUSSIZE/8)/2 
#define MSGSIZE SIZE-11				//MSG Length to be eligible for encrypting
#define BLOCKSIZE (MODULUSSIZE/8)/2 
#define OCTET 8
#define MD5SUM_BYTES 16
#define SIGNSIZE SIZE

#define ENCRYPT 0
#define DEBUG 0



using namespace std;

unsigned char* gen_md5_digest(char *);

typedef unsigned char uint8_t ;



struct publicKey{
	mpz_t n;
	mpz_t e;
};

struct privateKey{
       //char* header;
       //char* algorithm;
       mpz_t n;
       mpz_t e;
       mpz_t d;
       mpz_t p;
       mpz_t q;
       mpz_t exp1;
       mpz_t exp2;
       mpz_t u;
};





static const string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";



static inline bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}


int hexToInt(string strHex)
{
    int decimalValue = 0;
    sscanf(strHex.c_str(), "%x", &decimalValue); 
      // cout<<decimalValue<<endl;  
       return decimalValue;
}

struct privateKey* getPrivateStructure(mpz_t n, mpz_t e, mpz_t d,mpz_t p,mpz_t q,mpz_t exp1,mpz_t exp2, mpz_t u)
{

	struct privateKey* priKey = (struct privateKey*)malloc(sizeof(struct privateKey));
	mpz_init(priKey->n);
 	mpz_set(priKey->n, n);
 	mpz_init(priKey->e);
 	mpz_set(priKey->e, e);
 	mpz_init(priKey->d);
 	mpz_set(priKey->d, d);
 	mpz_init(priKey->p);
 	mpz_set(priKey->p, p);
 	mpz_init(priKey->q);
 	mpz_set(priKey->q, q);
 	mpz_init(priKey->exp1);
 	mpz_set(priKey->exp1, exp1);
 	mpz_init(priKey->exp2);
 	mpz_set(priKey->exp2, exp2);
 	mpz_init(priKey->u);
 	mpz_set(priKey->u, u);

}


void freePrivateStructure(struct privateKey* priKey)
{
	mpz_clear(priKey->p);
  	mpz_clear(priKey->q);
  	mpz_clear(priKey->n);
  	mpz_clear(priKey->e);
  	mpz_clear(priKey->d);
  	mpz_clear(priKey->exp1);
  	mpz_clear(priKey->exp2);
  	mpz_clear(priKey->u);
	free(priKey);
}




vector<string> myTokenizer(char* input)
{
    vector<string> myList;
    	int count = 2;
    	int index = 0;
    	int indexTemp = 0;
    	char temp[2];
    	
    	for(int i=0; i<strlen(input); i++)
    	{
    		if(index < 2)
    		{
    			temp[indexTemp++] = input[i];
    			index++;
    		}
    		if(index==2)
    		{
    			myList.push_back(temp);
    			index=0;
    			indexTemp=0;
    		}
    	}
     return myList;
}



/* Computes the multiplicative inverse of a number using Euclids algorithm.
   Computes x such that a * x mod n = 1, where 0 < a < n. */

static void mpz_mod_inverse(MP_INT *x, MP_INT *a, MP_INT *n)
{
  MP_INT g0, g1, v0, v1, div, mod, aux;
  mpz_init_set(&g0, n);
  mpz_init_set(&g1, a);
  mpz_init_set_ui(&v0, 0);
  mpz_init_set_ui(&v1, 1);
  mpz_init(&div);
  mpz_init(&mod);
  mpz_init(&aux);
  while (mpz_cmp_ui(&g1, 0) != 0)
    {
      mpz_divmod(&div, &mod, &g0, &g1);
      mpz_mul(&aux, &div, &v1);
      mpz_sub(&aux, &v0, &aux);
      mpz_set(&v0, &v1);
      mpz_set(&v1, &aux);
      mpz_set(&g0, &g1);
      mpz_set(&g1, &mod);
    }
  if (mpz_cmp_ui(&v0, 0) < 0)
    mpz_add(x, &v0, n);
  else
    mpz_set(x, &v0);

  mpz_clear(&g0);
  mpz_clear(&g1);
  mpz_clear(&v0);
  mpz_clear(&v1);
  mpz_clear(&div);
  mpz_clear(&mod);
  mpz_clear(&aux);
}


//Base64 Encoder
string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
  string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    	for(j = i; j < 3; j++)
      		char_array_3[j] = '\0';

    	char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    	char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    	char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    	char_array_4[3] = char_array_3[2] & 0x3f;

   	for (j = 0; (j < i + 1); j++)
      		ret += base64_chars[char_array_4[j]];

    	while((i++ < 3))
      		ret += '=';
  }
  return ret;

}



char* base64Decoder(char *input)
{
	int length = strlen(input);
	int outputLength;
	int countPad =0;
	unsigned char char_array_4[4], char_array_3[3];
	for(int k=length-1; k> 0 ; k--)
	     if(input[k]=='=')
		 countPad++;
	     else
		 break;
//	printf("Pad length = %d\n", countPad);
	if(countPad == 0)
		 outputLength = (length*3)/4;
	else if(countPad == 1)
	 	outputLength = ((length-4)*3)/4+ 2;
	 else if(countPad == 2)
	      	outputLength = ((length-4)*3)/4+ 1;
	      
	int finalLength = 4*outputLength;
	char* output = new char[finalLength];
	memset(output, 0, finalLength);
	char temp[2];

	int index=0, k=0, start=0;


	while (k<length && ( input[k] != '=') && is_base64(input[k])) 
	{
	     char_array_4[index++] = input[k++];
	     
	     if(index == 4)
	     {
		      //printf("The segment is : %s \n", char_array_4);
	     
		      index=0;
		      //printf("The segment is : %c \n", char_array_4[3]);
		      
		      for (int j = 0; j <4; j++)
		      	char_array_4[j] = base64_chars.find(char_array_4[j]);
		      //printf("The segment is : %d \n", char_array_4[3]);
		      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
		      
		      sprintf(temp,"%02x", char_array_3[0]);
		      strcat(output,temp);
		      strcat(output," ");
		      sprintf(temp,"%02x", char_array_3[1]);
		      strcat(output,temp);
		      strcat(output," ");
		      sprintf(temp,"%02x", char_array_3[2]);
		      strcat(output,temp);
		      strcat(output," ");
		      //printf("The value is : %02x \n", char_array_3[0]);
		      //printf("The value is : %02x \n", char_array_3[1]);
		      //printf("The value is : %02x \n", char_array_3[2]);
		      //printf("Output : %s\n", output);
	     }
	}
	if(index)
	{
	      //printf("The segment is : %s \n", char_array_4);
	      for (start = index; start <4; start++)
		       char_array_4[start] = 0;
	      //printf("The segment is : %c \n", char_array_4[2]);
	      //printf("The segment is : %c \n", char_array_4[3]);
	      //printf("The segment is : %s \n", char_array_4);
	      for (start = 0; start <4; start++)
		  char_array_4[start] = base64_chars.find(char_array_4[start]);

		//  printf("The segment is : %d \n", char_array_4[3]);

	    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
	    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
	    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

	      sprintf(temp,"%02x", char_array_3[0]);
	      strcat(output,temp);
	      strcat(output," ");
	      sprintf(temp,"%02x", char_array_3[1]);
	      strcat(output,temp);
	      //strcat(output,"\n");
	      //sprintf(temp,"%x", char_array_3[2]);
	      //strcat(output,temp);
	      //printf("The value is : %c \n", char_array_3[0]);
	      //printf("The value is : %c \n", char_array_3[1]);
	      //printf("The value is : %c \n", char_array_3[2]);
	     // printf("Output : \n%s\n", output);
	}
#if DEBUG
	printf("Output : \n%s\n", output);
#endif
	return output;
}


int TLVHeaderDecoder(vector<string> myList, int start,int size, string& TLVLength)
{
    int type = hexToInt(myList[start]);
    int length= hexToInt(myList[start+1]);

#if DEBUG
	printf("Hiii = %d\n",hexToInt(myList[start+1]));
#endif    
	int blocksLength = 0;
    int index;
    if(length > 128)
    {
              blocksLength = length - 128;
              index = start+2;
              for(int i=0; i< blocksLength; i++)
                      TLVLength = TLVLength + myList[index++];
#if DEBUG
              printf("Length = %s\n", TLVLength.c_str());
              printf("Index = %d\n", index);
#endif
              return index;
    }
    else
    {
        TLVLength = myList[start+1];
        index = start+2;
        //printf("Index = %d\n", index);      
        return index;
    }
}

int TLVDecoder(vector<string> myList, int start, int size, string& TLVLength, string& TLVValue)
{
    int type = hexToInt(myList[start]);
    int length= hexToInt(myList[start+1]);
    int blocksLength = 0;
    int index;
    if(length > 128)
    {
              blocksLength = length - 128;
              index = start+2;
              for(int i=0; i< blocksLength; i++)
                      TLVLength = TLVLength + myList[index++];
          //    printf("Length = %d\n", hexToInt(TLVLength));
              
            //  printf("Index = %d\n", index);
              for(int i=0; i<hexToInt(TLVLength); i++)
              {
                      TLVValue = TLVValue+myList[index++];
                      }
              
              //cout<<TLVValue<<endl;
              return index;
    }
    else
    {
        TLVLength = myList[start+1];
        index = start+2;
#if DEBUG
        printf("Index TLV LEngth = %s\n", TLVLength.c_str());
#endif
        for(int i=0; i<hexToInt(TLVLength); i++)
              {
                      TLVValue = TLVValue+myList[index++];
                      }
              
          //    cout<<TLVValue<<endl;
              return index;
    }
    
}

struct publicKey* decodePublicKey(char* input)
{
	vector<string> myList;
    	char* parts;
    	parts = strtok(input," ");
	
	while(parts)
	{
        	//printf("%s\n",parts);
        	myList.push_back(parts);
        	parts = strtok(NULL," ");
     	}

#if DEBUG
	printf("Size of the vector: %d\n", myList.size());

#endif
	
	int value=0;
	string myTypeValue[2], mytempTypeValue;
	string myTypeLength[2], mytempTypeLength;
	
    	string headerLength;
	string tempheaderLength;
    	
	value = TLVHeaderDecoder(myList, value, 2, tempheaderLength);

#if DEBUG
	printf("Index = %d\n", value);

#endif
	value = TLVDecoder(myList, value, 2, mytempTypeLength, mytempTypeValue);
//	printf("Check best Index = %d\n", value);

	value = TLVHeaderDecoder(myList, value, 2, tempheaderLength);
#if DEBUG
	printf("Index = %d\n", value);
#endif
	value++;
#if DEBUG
	printf("This Index = %d\n", value);
#endif
	
	value = TLVHeaderDecoder(myList, value, 2, tempheaderLength);

#if DEBUG
	printf("Index = %d\n", value);
#endif	
	for(int i=0; i<2; i++)
	{
            value = TLVDecoder(myList, value, 2, myTypeLength[i], myTypeValue[i]);
#if DEBUG
	        printf("you Index = %d\n", value);
#endif
 	}
 	
 	struct publicKey* pubKey = (struct publicKey*)malloc(sizeof(struct publicKey));
	mpz_init(pubKey->n);
 	mpz_init_set_str(pubKey->n, myTypeValue[0].c_str(), 16);
 	mpz_init(pubKey->e);
 	mpz_init_set_str(pubKey->e, myTypeValue[1].c_str(), 16);
#if DEBUG	
	gmp_printf("\n%Zd\n", pubKey->n);
	gmp_printf("\n%Zd\n", pubKey->e);
#endif
	//if(mpz_cmp)

	//*n = pubKey->n;
	//*e = pubKey->e;
	//mpz_clear(pubKey->n);
	//mpz_clear(pubKey->e);
	return pubKey;
}


struct privateKey* decodePrivateKey(char* input)
{
	char* parts;
	
	//Aim to fill the vector with 1 byte of hexdata
    	vector<string> myList;
    
    	parts = strtok(input," ");
	
	while(parts)
	{
        	//printf("%s\n",parts);
        	myList.push_back(parts);
        	parts = strtok(NULL," ");
     	}
	
#if DEBUG
	printf("Size of the vector: %d\n", myList.size());
#endif	
	int value;
	string myTypeValue[9];
	string myTypeLength[9];
	
    	string headerLength;
    	
	value = TLVHeaderDecoder(myList, 0, 2, headerLength);
#if DEBUG
	printf("Index = %d\n", value);
#endif	
	for(int i=0; i<9; i++)
	{
            	value = TLVDecoder(myList, value, 2, myTypeLength[i], myTypeValue[i]);
#if DEBUG	        
		printf("Index = %d\n", value);
#endif
 	}
 
 	struct privateKey* priKey = (struct privateKey*)malloc(sizeof(struct privateKey));
 
 	mpz_init(priKey->n);
 	mpz_init_set_str(priKey->n, myTypeValue[1].c_str(), 16);
 	mpz_init(priKey->e);
 	mpz_init_set_str(priKey->e, myTypeValue[2].c_str(), 16);
 	mpz_init(priKey->d);
 	mpz_init_set_str(priKey->d, myTypeValue[3].c_str(), 16);
 	mpz_init(priKey->p);
 	mpz_init_set_str(priKey->p, myTypeValue[4].c_str(), 16);
 	mpz_init(priKey->q);
 	mpz_init_set_str(priKey->q, myTypeValue[5].c_str(), 16);
 	mpz_init(priKey->exp1);
 	mpz_init_set_str(priKey->exp1, myTypeValue[6].c_str(), 16);
 	mpz_init(priKey->exp2);
 	mpz_init_set_str(priKey->exp2, myTypeValue[7].c_str(), 16);
 	mpz_init(priKey->u);
 	mpz_init_set_str(priKey->u, myTypeValue[8].c_str(), 16);
 
 
  	//mpz_t n;  mpz_init(n); mpz_init_set_str(n, myTypeValue[1].c_str(), 16);
   	mpz_t p;  mpz_init(p); mpz_init_set_str(p, myTypeValue[4].c_str(), 16);
    	mpz_t q;  mpz_init(q); mpz_init_set_str(q, myTypeValue[5].c_str(), 16);
    	mpz_t temp; mpz_init(temp);
    	mpz_mul(temp, p, q);
	//gmp_printf("\n%Zd\n", priKey->n);
	//gmp_printf("\n%Zd\n", temp);

	
	mpz_clear(p);
     	mpz_clear(q);
	return priKey;  	

/*
  	mpz_clear(priKey->p);
  	mpz_clear(priKey->q);
  	mpz_clear(priKey->n);
  	mpz_clear(priKey->e);
  	mpz_clear(priKey->d);
  	mpz_clear(priKey->exp1);
  	mpz_clear(priKey->exp2);
  	mpz_clear(priKey->u);
  
  	mpz_clear(temp);
*/
}

//Certificate related stuff

struct tlv{
	string t;
	string l;
	string v;
};

struct seq2{
	string t;
	string l;
	struct tlv first;
	struct tlv second;
};

struct set{
	string t;
	string l;
	struct seq2 sequence;
};

struct sequence_7{
	string t;
	string l;
	struct set setArray[7];
};

struct keyInfoSeq{
	string t;
	string l;
	struct seq2 sequence;
	struct set keyInfo;
};

struct sequence1{
	string t;
	string l;
	struct tlv myInt;
	struct seq2 s_1;
	struct sequence_7 s_2;
	struct seq2 s_3;
	struct sequence_7 s_4;
	struct keyInfoSeq s_5;
};

struct certificate{
	string t;
	string l;
	struct sequence1 s1;
	struct seq2 s2;
	struct tlv s3;
};



int TLVHeaderDecoderNew(vector<string> myList, int start,int size, string& TLVTag, string& TLVLength)
{
    int type = hexToInt(myList[start]);
	TLVTag = myList[start];
    int length= hexToInt(myList[start+1]);
    int blocksLength = 0;
    int index;
    if(length > 128)
    {
              blocksLength = length - 128;
              index = start+2;
              for(int i=0; i< blocksLength; i++)
                      TLVLength = TLVLength + myList[index++];
              //printf("Length = %d\n", hexToInt(TLVLength));
              //printf("Index = %d\n", index);
              return index;
    }
    else
    {
        TLVLength = myList[start+1];
        index = start+2;
        //printf("Index = %d\n", index);      
        return index;
    }
}




int TLVDecoderNew(vector<string> myList, int start, int size,string& TLVTag, string& TLVLength, string& TLVValue)
{
    int type = hexToInt(myList[start]);
	TLVTag = myList[start];
    int length= hexToInt(myList[start+1]);
    int blocksLength = 0;
    int index;
    if(length > 128)
    {
              blocksLength = length - 128;
              index = start+2;
              for(int i=0; i< blocksLength; i++)
                      TLVLength = TLVLength + myList[index++];
          //    printf("Length = %d\n", hexToInt(TLVLength));
              
            //  printf("Index = %d\n", index);
              for(int i=0; i<hexToInt(TLVLength); i++)
              {
                      TLVValue = TLVValue+myList[index++];
                      }
              
              //cout<<TLVValue<<endl;
              return index;
    }
    else
    {
        TLVLength = myList[start+1];
        index = start+2;
        //printf("Index = %d\n", index);
        for(int i=0; i<hexToInt(TLVLength); i++)
              {
                      TLVValue = TLVValue+myList[index++];
                      }
              
          //    cout<<TLVValue<<endl;
              return index;
    }
    
}

struct seq2 sequenceWith2(vector<string> myList, int start, int& index)
{
	int type;
	int length;
	//int index;
	string myTypeTag[2];
	string myTypeValue[2];
	string myTypeLength[2];
	
	string headerLength;
	string headerType;
    	
	struct seq2 mySeq;
	
	struct tlv myTLV[2];

	index = TLVHeaderDecoderNew(myList, start, 2, headerType, headerLength);
	//printf("Index = %d\n", index);
	
	mySeq.t = headerType;
	mySeq.l = headerLength;

	//printf("Type:%s ", mySeq.t.c_str());
	//printf("Length:%s\n", mySeq.l.c_str());

	for(int i=0; i<2; i++)
	{
		//myTLV[i] = (struct tlv*) malloc(sizeof(struct tlv));
            	index = TLVDecoderNew(myList, index, 2, myTypeTag[i], myTypeLength[i], myTypeValue[i]);
		myTLV[i].t = myTypeTag[i];
		myTLV[i].l = myTypeLength[i];
		myTLV[i].v = myTypeValue[i];

		if(i==0)
			mySeq.first = myTLV[i];
		else
			mySeq.second = myTLV[i];
		//free(myTLV);
	  //      printf("Index = %d\n", index);
 	}
	//printf("Value 1:\n%s\n", (mySeq.first.v).c_str());
	//printf("Value 2:\n%s\n", (mySeq.second.v).c_str());

	//inputSeq = mySeq;	

	//free(mySeq);
	return mySeq;
	
}

struct set makeSet(vector<string> myList, int start, int& value)
{
	struct set mySet;

	struct seq2 mySeq;	
	
	
	string headerLength;
	string headerType;

	start = TLVHeaderDecoderNew(myList, start, 2, headerType, headerLength);
#if DEBUG
	printf("Index = %d\n", start);
#endif	
	mySet.t = headerType;
	mySet.l = headerLength;
	
	if(hexToInt(headerType) == 3)
		start++;

	mySeq = sequenceWith2(myList, start, value);
	mySet.sequence = mySeq;

	//printf("Value 1:\n%s\n", (mySet.sequence.first.v).c_str());
	//printf("Value 2:\n%s\n", (mySet.sequence.second.v).c_str());

	//printf("Index = %d\n", value);
	//return value;
	return mySet;
}

int decodeLargeSequence(vector<string> myList, int start, struct sequence_7& bigSeq)
{
	//struct sequence_7 bigSeq;
	string headerLength;
	string headerType;

	struct set mySet[8];

	start = TLVHeaderDecoderNew(myList, start, 2, headerType, headerLength);

	bigSeq.t = headerType;
	bigSeq.l = headerLength;
	
	//printf("Value 1:\n%s\n", bigSeq.t.c_str());
	//printf("Value 2:\n%s\n", bigSeq.l.c_str());
	int lengthSub = hexToInt(headerLength);
	//printf("Length of subsequence: %d\n", lengthSub);
	int offset = lengthSub+start;
	//printf("Index before offset= %d\n", start);
	int value = start;
	
	for(int i=0; i<8, value<offset; i++)
	{
		mySet[i] = makeSet(myList, value, start);
		bigSeq.setArray[i] = mySet[i];
		value = start;
		//printf("Length at bigSeq for i= %d is %d\n", i, value);
	}
	
	//printf("Some random check : %s \n", bigSeq.setArray[3].sequence.first.v.c_str());
#if DEBUG	
	printf("Index = %d\n", start);
#endif
	return start;
}

int decodeAlgo(vector<string> myList, int start, struct seq2& seqAlgo)
{
	int index=0;
	seqAlgo= sequenceWith2(myList,start,index);
#if DEBUG
	printf("Algo type = %s\n", seqAlgo.first.v.c_str());
#endif
	return index;
}

int decodeTimeValidity(vector<string> myList, int start, struct seq2& timeValidity)
{
	int index=0;
	timeValidity= sequenceWith2(myList,start,index);
	//printf("Time type = %s\n", timeValidity.first.t.c_str());

	return index;
}

int decodeKeySequence(vector<string> myList, int start, struct keyInfoSeq& keyInformation)
{
	string headerLength;
	string headerType;

	struct seq2 myObj;
	struct set keyInfoString;

	

	start = TLVHeaderDecoderNew(myList, start, 2, headerType, headerLength);
	
	keyInformation.t = headerType;
	keyInformation.l = headerLength;
	
#if DEBUG
	printf("Index in decode key sequence = %d\n", start);
#endif

	int index = start;
	myObj = sequenceWith2(myList,start,index);
	start = index;

#if DEBUG
	printf("Index in decode key sequence = %d\n", start);
#endif

	keyInfoString = makeSet(myList,start,index);
	keyInformation.sequence=myObj;
	keyInformation.keyInfo = keyInfoString;

#if DEBUG	
	printf("Check for key : %s\n", keyInformation.keyInfo.sequence.second.v.c_str());
	

	printf("Index in decode key sequence = %d\n", index);
#endif
	return index;
	


}

int sequence1Decoder(vector<string> myList, int  value, struct sequence1& s1)
{


	string myTypeTag[2];
	string myTypeLength[2];
	string myTypeValue[2];

	value = TLVHeaderDecoderNew(myList, value, 2, myTypeTag[0], myTypeLength[0]);
#if DEBUG
	printf("Index = %d\n", value);
#endif
	s1.t = myTypeTag[0];
	s1.l = myTypeLength[0];

	value = TLVDecoderNew(myList, value, 2, myTypeTag[1], myTypeLength[1], myTypeValue[1]);

#if DEBUG
	printf("Index = %d\n", value);
#endif
	
	struct tlv myInteger;
	myInteger.t= myTypeTag[1];
	myInteger.l = myTypeLength[1];
	myInteger.v = myTypeValue[1];
	
	s1.myInt = myInteger;
	
#if DEBUG
	printf("Check Integer value= %s\n", s1.myInt.v.c_str());

	printf("length  = %s\n", myTypeValue[1].c_str());
#endif	
	//Validity Set sequence
	struct seq2 seqAlgo;
	value = decodeAlgo(myList, value, seqAlgo);
#if DEBUG
	printf("Index = %d\n", value);
#endif	
	s1.s_1 = seqAlgo;

#if DEBUG
	printf("Check Algo Value= %s\n", s1.s_1.first.v.c_str());

#endif
	//After NULL
	//First 7 element set
	
	struct sequence_7 bigSeq1;

	value = decodeLargeSequence(myList, value, bigSeq1);
#if DEBUG
	printf("Index = %d\n", value);
#endif
	s1.s_2 = bigSeq1;

#if DEBUG
	printf("Check sequence 7 first value= %s\n", s1.s_2.setArray[0].sequence.first.v.c_str());
#endif	
	//printf("IMP check sequence 7 first value= %s\n", s1.s_2.setArray[7].sequence.first.v.c_str());
	

	//printf("Some random check : %s \n", bigSeq1.setArray[3].sequence.first.v.c_str());
	
	//Validity Set sequence
	struct seq2 seqValidity;
	value = decodeTimeValidity(myList, value, seqValidity);
	//printf("Index = %d\n", value);
	
	s1.s_3 = seqValidity;
	//printf("Check time validity= %s\n", s1.s_3.first.v.c_str());

	//Second 7 element set
	struct sequence_7 bigSeq2;

	value = decodeLargeSequence(myList, value, bigSeq2);
	//printf("Index = %d\n", value);
	
	s1.s_4 = bigSeq2;
#if DEBUG
	printf("Check sequence 7 second= %s\n", s1.s_4.setArray[0].sequence.first.v.c_str());
#endif	

	//Decode double sequence
	struct keyInfoSeq keyInformation;
	
	value = decodeKeySequence(myList, value, keyInformation);

#if DEBUG
	printf("Index = %d\n", value);
#endif
	s1.s_5 = keyInformation;
#if DEBUG	
	printf("Check public key= %s\n", s1.s_5.keyInfo.sequence.first.v.c_str());
#endif	

	return value;
}

int sequence2Decoder(vector<string> myList, int start, struct seq2& s2)
{
	int index=0;
	s2= sequenceWith2(myList,start,index);
#if DEBUG	
	printf("Sequence 2 = %s\n", s2.first.v.c_str());
#endif
	return index;
}

struct certificate decodeX509(char* input)
{
	vector<string> myList;
    	char* parts;
    	parts = strtok(input," ");
	
	while(parts)
	{
        	//printf("%s\n",parts);
        	myList.push_back(parts);
        	parts = strtok(NULL," ");
     	}
	//printf("Size of the vector: %d\n", myList.size());
	
	struct certificate X509Structure;

	int value;
	string myTypeTag;
	string myTypeValue;
	string myTypeLength;
	
    	string headerLength;
    	
	value = TLVHeaderDecoder(myList, 0, 2, headerLength);
#if DEBUG
	printf("Index = %d\n", value);
#endif
	X509Structure.t = "30";
	X509Structure.l = headerLength;

	struct sequence1 s1;


	value = sequence1Decoder(myList, value, s1);
#if DEBUG
	printf("Index = %d\n", value);
	//printf("length  = %s\n", headerLength.c_str());
	//printf("length  = %d\n", hexToInt(headerLength));
#endif	
	struct seq2 s2;

	value = sequence2Decoder(myList, value, s2);
#if DEBUG
	printf("Index = %d\n", value);
#endif
	struct tlv s3;

	value = TLVDecoderNew(myList, value, 2, myTypeTag, myTypeLength, myTypeValue);
#if DEBUG
	printf("Index = %d\n", value);
#endif	
	s3.t= myTypeTag;
	s3.l = myTypeLength;
	s3.v = myTypeValue;

	
	X509Structure.s1 = s1;
	X509Structure.s2 = s2;
	X509Structure.s3 = s3;

	

	return X509Structure;

}

struct publicKey* extractKeysFromCertificate(struct certificate cert)
{
	int fp;

#if DEBUG	
	printf("Check modulus key= %s\n", cert.s1.s_5.keyInfo.sequence.first.v.c_str());
	printf("Check e key= %s\n", cert.s1.s_5.keyInfo.sequence.second.v.c_str());
#endif
	struct publicKey* pubKey = (struct publicKey*)malloc(sizeof(struct publicKey));
	mpz_init(pubKey->n);
 	mpz_init_set_str(pubKey->n, cert.s1.s_5.keyInfo.sequence.first.v.c_str(), 16);
 	mpz_init(pubKey->e);
 	mpz_init_set_str(pubKey->e, cert.s1.s_5.keyInfo.sequence.second.v.c_str(), 16);	
#if DEBUG	
	gmp_printf("\n%Zd\n", pubKey->n);
	gmp_printf("\n%Zd\n", pubKey->e);
	printf("Length of the certificate = %d\n", hexToInt(cert.l));
	//printf("Length of the certificate = %s\n", cert.l.c_str());
#endif	
	/*int index=0;

	fp =open("parseCert",O_WRONLY|O_CREAT);
	if ( fp < 0 ) {
		printf("unable to open file\n");
	}
	
	write(fp, "Certificate:\n",13);
	write(fp, );
	
	close(fp);*/
	return pubKey;

}



//End the certificate related stuff



uint8_t generateNonZeroOctet()
{
	srand(time(NULL));
	uint8_t temp = rand()% 0xFF;
	while(temp == 0x00)
		temp = rand()% 0xFF;
	temp |= 0x11;
	return temp;
	
}

uint8_t* rsaEncryption(mpz_t n,mpz_t e,char* m,int mLen)
{
	uint8_t* EM = new uint8_t[SIZE];
	memset(EM, 0, SIZE);
	uint8_t zeroByte=0x00;
	uint8_t  padStart=0x02;
	uint8_t temp;
	uint8_t* msg = (uint8_t*)m;
	int start =0;
	int index=0;
	EM[index++]=zeroByte;
	EM[index++]=padStart;
	int padLen = SIZE - mLen -3;
	for(int i=0; i<padLen; i++)
	{
		temp =generateNonZeroOctet();
		EM[index++]=temp;
	}
	EM[index++]=zeroByte;
	while(index<SIZE)
		EM[index++]=msg[start++];

#if DEBUG
	cout<<endl<<"Encryption thing"<<endl;
#endif	
	//for(int i=0; i<SIZE; i++)
        //     printf("%02x", EM[i]);
	//cout<<endl;	
	
	mpz_t msgNum;		mpz_init(msgNum);
	mpz_t cipherNum;	mpz_init(cipherNum);

	mpz_import(msgNum, SIZE, 1, sizeof(EM[0]),0,0, EM);

#if DEBUG	
	gmp_printf("\n%Zd\n", msgNum);
	printf("Size of the number : %d\n", mpz_sizeinbase(msgNum, 2));	
#endif	
	mpz_powm(cipherNum,msgNum,e,n);
	size_t cipherLen;
	uint8_t* cipher= (uint8_t *)mpz_export(NULL,&cipherLen,1,1,0,0,cipherNum);
	
#if DEBUG
	printf("The length of the ciphertext = %d\n", cipherLen);
#endif
	if(cipherLen != SIZE)
	{
		printf("Encryption Failed: Cipher Length != BitRsa/8");
	}
	mpz_clear(msgNum);
	mpz_clear(cipherNum);
	return cipher;
}

uint8_t* leftPad(uint8_t* temp, int length, int size)
{
	uint8_t* array = new uint8_t[size];
	int diff = size-length;
	memset(array,0, size);
	memcpy(array+diff,temp, length);
	return array;
}


uint8_t* rsaDecryption(mpz_t n, mpz_t d, uint8_t* cipher, int* finalLength)
{
	mpz_t cipherNum;	mpz_init(cipherNum);
	mpz_t msgNum;		mpz_init(msgNum);
	mpz_import(cipherNum, SIZE, 1, sizeof(cipher[0]),0,0, cipher);
	mpz_powm(msgNum, cipherNum, d, n);

	//gmp_printf("\n%Zd\n", msgNum);
	
	size_t msgLen;
	uint8_t* tempMsg= (uint8_t *)mpz_export(NULL,&msgLen,1,1,0,0,msgNum);

	//printf("The length of the message = %d\n", msgLen);

	uint8_t* msg;
	
	if(msgLen < SIZE)
	{
		msg = leftPad(tempMsg, msgLen, SIZE);
		
		msgLen = SIZE;
	}
	else if (msgLen == SIZE)
		{
			msg = tempMsg;
		}
		else
		{
			printf("Decryption Failed:The size of the ecrypted message > BitRsa/8");
		}

	//for(int i=0; i<msgLen; i++)
        //     printf("%02x", msg[i]);
	//cout<<endl;

	//Checks for the added padding while encrypting
	int index=0;
	if(msg[index++] != 0x00)
	{
		printf("Decryption Failed: First Byte != 0x00");
		return NULL;
	}
	if(msg[index++] != 0x02)
	{
		printf("Decryption Failed: Second Byte != 0x02");
		return NULL;
	}
	int countNonZero =0;
	while(msg[index++] != 0x00)
	{
		countNonZero++;
	}
	if(countNonZero <= 8)
	{
		printf("Decryption Failed: The psuedo random padding < 8");
		return NULL;
	}

#if DEBUG	
	for(int i=0; i<SIZE; i++)
		printf("%02x",msg[i]);
	cout<<endl;	
#endif
	uint8_t* m = new uint8_t[SIZE];
	memset(m, 0, SIZE);
	int j=0;
	int k=index;
	for(int i=index; i<SIZE; i++)
		m[j++]=msg[index++];
	//m[j]='\0';
	//memcpy

	*finalLength = SIZE-k;
	
	return m;

}



string TLVEncoderHeader(int length)
{
     string format;
     char buf[2];
     
     char typeHeader[2];
     sprintf(typeHeader, "%02x", 48);
     format += typeHeader;
     
     if((length/2) <= 127)
    {
        
		sprintf(buf, "%02x", length/2);
		format += buf;
		
    }
    else if((length/2) < 65536)
        {
            if((length/2) < 256)
            {
               sprintf(buf, "%02x", 129);
		       format += buf;
		       sprintf(buf, "%02x", length/2);
		       format += buf;
            }
            else
            {
               sprintf(buf, "%02x", 130);
		       format += buf;
		       char newBuf[4];
		       sprintf(newBuf, "%04x", length/2);
		       format += newBuf;
            }
        }
        else
        {
            printf("Write code for this also x-( \n");
        }
    
    return format;
     
}


string TLVEncoder(char *input)
{
    int length = strlen(input);
    
#if DEBUG
	printf("Length is = %d of \n%s\n", length, input);
#endif    
    string format;
    
    char *value;
    char firstChar;
    int temp=0;
    
    if(length%2)
    {
                value = (char *)malloc(length+2);
                memset(value, 0, length+2);
                value[0] = '0';
                memcpy((value+1),input, length);
    }
    else
    {
        //value = input;
        //strcat(value, input);
        firstChar = input[0];

#if DEBUG
        printf("%c\n", firstChar);
#endif
        if(isdigit(firstChar) && (temp=firstChar - '0')< 8)
        {
#if DEBUG
           printf("No 00 \n");
#endif
           value = (char *)malloc(length+1);
           memset(value, 0, length+1);
           memcpy((value),input, length);
           
        }
        else
        {
#if DEBUG
            printf("yes 00 \n");
#endif
            value = (char *)malloc(length+3);
            memset(value, 0, length+3);
            value[0] = '0';
            value[1] = '0';
            memcpy((value+2),input, length);
        }
    }
    
    length = strlen(value);
    //printf("%s\n", value);
    //printf("%d\n", length);
    char buf[2];
    
    sprintf(buf, "%02x", 2);
    format += buf;
    
    if((length/2) <= 127)
    {
        
		sprintf(buf, "%02x", length/2);
		format += buf;
		
    }
    else if((length/2) < 65536)
        {
            if((length/2) < 256)
            {
               sprintf(buf, "%02x", 129);
		       format += buf;
		       sprintf(buf, "%02x", length/2);
		       format += buf;
            }
            else
            {
               sprintf(buf, "%02x", 130);
		       format += buf;
		       char newBuf[4];
		       sprintf(newBuf, "%04x", length/2);
		       format += newBuf;
            }
        }
        else
        {
            printf("Write code for this also x-( \n");
        }
    
    format +=value;
  
#if DEBUG  
    cout<<"Format :"<<endl<<format<<endl<<endl;
    
    cout<<"Length : "<<format.size()<<endl<<endl;
#endif
   
    return format;
}

uint8_t* NewEncoder(uint8_t *input, size_t length, size_t* outputSize)
{
      
      uint8_t *output;
      int flag=0;
      size_t outputLength = length;
      size_t tempLength = length;
      //printf("%02x\n", input[0]);
      uint8_t first = input[0] & 0x80;
      //printf("%02x\n", first);
      //printf("Length is :%d\n", length);
      if(first == 0x80)
      {
               outputLength++;
               
               flag=1;
      }
      
      tempLength = outputLength;
      
      if(outputLength <=127)
      {
          outputLength++;
      }
      else if(outputLength > 127 && outputLength <= 255)
      {
           outputLength= outputLength+2;                
      }
      else if(outputLength < 65536)
           {
                outputLength = outputLength+3;
           }
      
      
      outputLength = outputLength+1; //For byte of header
      
      output = new uint8_t[outputLength];
      int index=0;
      output[index++]=0x02;
      if(tempLength <=127)
      {
          output[index++]=(uint8_t)tempLength;
      }
      else if(tempLength > 127 && tempLength <= 255)
      {
           output[index++]=0x81;
           output[index++]=(uint8_t)(tempLength);             
      }
      else if(tempLength < 65536)
           {
                output[index++]=0x82;
                output[index++]=(uint8_t)((tempLength & 0x0000ff00) >> 8);
                output[index++]=(uint8_t)(tempLength);    
           }
      if(flag==1)
                 output[index++]=0x00;
      
      for(int i=0; i< length; i++)
              output[index++]=input[i];
 #if DEBUG     
      for(int i=0; i<outputLength; i++)
              printf("%02x", output[i]);
      cout<<endl;
 #endif     
      *outputSize = outputLength;
      
      return output;
               
}

uint8_t* NewHeaderEncoder(size_t length, size_t* outputSize)
{
      
      uint8_t *output;
      int flag=0;
      size_t outputLength = 0;
      size_t tempLength = length;
      //printf("%02x\n", input[0]);
      //printf("Length is :%d\n", length);

      if(tempLength <=127)
      {
          outputLength++;
      }
      else if(tempLength > 127 && tempLength <= 255)
      {
           outputLength= outputLength+2;                
      }
      else if(tempLength < 65536)
           {
                outputLength = outputLength+3;
           }
      
      
      outputLength = outputLength+1; //For byte of header
      
      output = new uint8_t[outputLength];
      int index=0;
      output[index++]=0x30;
      if(tempLength <=127)
      {
          output[index++]=(uint8_t)tempLength;
      }
      else if(tempLength > 127 && tempLength <= 255)
      {
           output[index++]=0x81;
           output[index++]=(uint8_t)(tempLength);             
      }
      else if(tempLength < 65536)
           {
                output[index++]=0x82;
                output[index++]=(uint8_t)((tempLength & 0x0000ff00) >> 8);
                output[index++]=(uint8_t)(tempLength);    
           }
 #if DEBUG     
      for(int i=0; i<outputLength; i++)
              printf("%02x", output[i]);
      cout<<endl;
 #endif     
      *outputSize = outputLength;
      
      return output;
               
}

uint8_t* BitStringHeaderEncoder(size_t length, size_t* outputSize)
{
      
      uint8_t *output;
      int flag=0;
      size_t outputLength = 0;
      size_t tempLength = length;
      //printf("%02x\n", input[0]);
      //printf("Length is :%d\n", length);

      if(tempLength <=127)
      {
          outputLength++;
      }
      else if(tempLength > 127 && tempLength <= 255)
      {
           outputLength= outputLength+2;                
      }
      else if(tempLength < 65536)
           {
                outputLength = outputLength+3;
           }
      
      
      outputLength = outputLength+1; //For byte of header
      
      output = new uint8_t[outputLength];
      int index=0;
      output[index++]=0x03;
      if(tempLength <=127)
      {
          output[index++]=(uint8_t)tempLength;
      }
      else if(tempLength > 127 && tempLength <= 255)
      {
           output[index++]=0x81;
           output[index++]=(uint8_t)(tempLength);             
      }
      else if(tempLength < 65536)
           {
                output[index++]=0x82;
                output[index++]=(uint8_t)((tempLength & 0x0000ff00) >> 8);
                output[index++]=(uint8_t)(tempLength);    
           }
#if DEBUG     
      for(int i=0; i<outputLength; i++)
              printf("%02x", output[i]);
      cout<<endl;
#endif   
      *outputSize = outputLength;
      
      return output;
               
}
void encodePublicKey(mpz_t n, mpz_t e, char* publicKeyFileName)
{
	//Modulus
	size_t mod_size;
	uint8_t *modulus_bytes = (uint8_t *)mpz_export(NULL,&mod_size,1,1,0,0,n);
	  
	size_t nSize=0;
	uint8_t* nBytes = NewEncoder(modulus_bytes, mod_size, &nSize);
//	printf("Output Length is :%d\n\n", nSize);

	uint8_t *e_bytes = (uint8_t *)mpz_export(NULL,&mod_size,1,1,0,0,e);
  	size_t eSize=0;
  	uint8_t* eBytes = NewEncoder(e_bytes, mod_size, &eSize);
//  	printf("Output Length is :%d\n\n", eSize);
	
	//Without Header
  	size_t hSize = nSize+eSize;
//  	cout<<"Length of the document w/o header length "<<hSize<<endl;
	
	//Header
  	size_t hLength=0;
  	uint8_t *hBytes = NewHeaderEncoder(hSize, &hLength);
//  	printf("Output Length is :%d\n\n", hLength);
  
  	//Total
  	size_t docSize = hLength+hSize;
//  	printf("Document size is :%d\n\n", docSize);
	

	uint8_t *docBytes = new uint8_t[docSize+22];
  	memset(docBytes,0, sizeof(uint8_t)*(docSize+22));
  	//int count=0;
 	// while(count<docSize)

	int index=0;

	docBytes[index++]=0x30;
	

	docBytes[index++]=0x81; 
	docBytes[index++]=0x9f;
	docBytes[index++]=0x30; 
	docBytes[index++]=0x0d; 
	docBytes[index++]=0x06; 
	docBytes[index++]=0x09; 
	docBytes[index++]=0x2a; 
	docBytes[index++]=0x86; 
	docBytes[index++]=0x48; 
	docBytes[index++]=0x86; 
	docBytes[index++]=0xf7;
	docBytes[index++]=0x0d; 
	docBytes[index++]=0x01; 
	docBytes[index++]=0x01;
	docBytes[index++]=0x01; 
	docBytes[index++]=0x05; 
	docBytes[index++]=0x00;

	docBytes[index++]=0x03; 
	docBytes[index++]=0x81; 
	docBytes[index++]=0x8d;
	docBytes[index++]=0x00;
  {
        memcpy(docBytes+index, hBytes, hLength);
        memcpy(docBytes+index+hLength, nBytes, nSize);
        memcpy(docBytes+index+hLength+nSize, eBytes, eSize);          
  }
  
  /*for(int i=0; i<(docSize+index++); i++)
          printf("%02x", docBytes[i]);
  cout<<endl<<endl;

*/	docSize = docSize+index++;

	int DERFile;
  //	for(int i=0; i<docSize; i++)
    //      	printf("%02x", docBytes[i]);
          
    	DERFile =open("public_1k.der",O_WRONLY|O_CREAT);
    	if ( DERFile < 0 ) {
        	printf("unable to open file\n");
    	}
    	for(int i=0; i<docSize; i++)
          	write(DERFile, (const void*)&docBytes[i], 1);
          
    	close(DERFile);
  
	
	 string encoded = base64_encode(reinterpret_cast<const unsigned char*>(docBytes),docSize);

//	cout<<endl<<"Base64Coded string is:"<<endl<<encoded<<endl;
	
	int PEMFile;
	int counter = 0;
	index=0;
	const char* startPEM ="-----BEGIN PUBLIC KEY-----";
	const char* endPEM="-----END PUBLIC KEY-----";
	int encodedLength = encoded.size();
//	printf("The size of encoded string is : %d\n", encodedLength);
	char* base64encoded = (char*)(encoded.c_str());
	PEMFile =open(publicKeyFileName,O_RDWR|O_CREAT);
	if ( PEMFile < 0 )
	{
		printf("unable to open file\n");
	}
	write(PEMFile, startPEM, strlen(startPEM));
	write(PEMFile,"\n", 1);
	for(int i=0; i<encodedLength ; i++)
	{
		write(PEMFile,(const char*)&base64encoded[i], 1);
		counter++;
		if(counter == 64)		
		{
			counter=0;
			write(PEMFile,"\n", 1);
		}
	}
	write(PEMFile,"\n", 1);
	write(PEMFile, endPEM, strlen(endPEM));
	write(PEMFile,"\n", 1);
	close(PEMFile);
	

}


void encodePrivateKey(mpz_t n, mpz_t pub_key, mpz_t pri_key, mpz_t p, mpz_t q, mpz_t exp1, mpz_t exp2, mpz_t coef, char* privateKeyFileName)
{

	//Algorithm
	uint8_t aBytes[3];
	aBytes[0]=0x02;
	aBytes[1]=0x01;
	aBytes[2]=0x00;

	size_t aSize=3;

	string algoString;
	algoString="020100";

	size_t mod_size;

	//Modulus

	uint8_t *modulus_bytes = (uint8_t *)mpz_export(NULL,&mod_size,1,1,0,0,n);

	size_t nSize=0;
	uint8_t* nBytes = NewEncoder(modulus_bytes, mod_size, &nSize);
//	printf("Output Length is :%d\n\n", nSize);
	/*
	for(int i=0; i<nSize; i++)
		printf("%02x", nBytes[i]);
	cout<<endl;
	*/
	//string checkString = TLVEncoder((char *)modulus_bytes);

	//string nString;
	//nString = TLVEncoder(mpz_get_str(NULL, 16, n));

	//Public key
	uint8_t *e_bytes = (uint8_t *)mpz_export(NULL,&mod_size,1,1,0,0,pub_key);
	size_t eSize=0;
	uint8_t* eBytes = NewEncoder(e_bytes, mod_size, &eSize);
//	printf("Output Length is :%d\n\n", eSize);


	//string eString;
	//eString = TLVEncoder(mpz_get_str(NULL, 16, pub_key));

	//Private Key
	uint8_t *d_bytes = (uint8_t *)mpz_export(NULL,&mod_size,1,1,0,0,pri_key);
	size_t dSize=0;
	uint8_t* dBytes = NewEncoder(d_bytes, mod_size, &dSize);
//	printf("Output Length is :%d\n\n", dSize);

	//string dString;
	//dString = TLVEncoder(mpz_get_str(NULL, 16, pri_key));

	//Prime p
	uint8_t *p_bytes = (uint8_t *)mpz_export(NULL,&mod_size,1,1,0,0,p);
	size_t pSize=0;
	uint8_t* pBytes = NewEncoder(p_bytes, mod_size, &pSize);
//	printf("Output Length is :%d\n\n", pSize);
	//string pString;
	//pString = TLVEncoder(mpz_get_str(NULL, 16, p));

	//Prime q
	uint8_t *q_bytes = (uint8_t *)mpz_export(NULL,&mod_size,1,1,0,0,q);
	size_t qSize=0;
	uint8_t* qBytes = NewEncoder(q_bytes, mod_size, &qSize);
//	printf("Output Length is :%d\n\n", qSize);

	//string qString;
	//qString = TLVEncoder(mpz_get_str(NULL, 16, q));

	//CRT EXP1
	uint8_t *exp1_bytes = (uint8_t *)mpz_export(NULL,&mod_size,1,1,0,0,exp1);
	size_t exp1Size=0;
	uint8_t* exp1Bytes = NewEncoder(exp1_bytes, mod_size, &exp1Size);
//	printf("Output Length is :%d\n\n", exp1Size);

	//string exp1String;
	//exp1String = TLVEncoder(mpz_get_str(NULL, 16, exp1));

	//CRT EXP2
	uint8_t *exp2_bytes = (uint8_t *)mpz_export(NULL,&mod_size,1,1,0,0,exp2);
	size_t exp2Size=0;
	uint8_t* exp2Bytes = NewEncoder(exp2_bytes, mod_size, &exp2Size);
//	printf("Output Length is :%d\n\n", exp2Size);

	//string exp2String;
	//exp2String = TLVEncoder(mpz_get_str(NULL, 16, exp2));

	//CRT COEF
	uint8_t *u_bytes = (uint8_t *)mpz_export(NULL,&mod_size,1,1,0,0,coef);
	size_t uSize=0;
	uint8_t* uBytes = NewEncoder(u_bytes, mod_size, &uSize);
//	printf("Output Length is :%d\n\n", uSize);
  
	//string uString;
	//uString = TLVEncoder(mpz_get_str(NULL, 16, coef));

	//Without Header
	size_t hSize = aSize+nSize+eSize+dSize+pSize+qSize+exp1Size+exp2Size+uSize;
//	cout<<"Length of the document w/o header length "<<hSize<<endl;

	//string totalWithoutHeader;
	//totalWithoutHeader = algoString+nString+eString+dString+pString+qString+exp1String+exp2String+uString;


	//int headerLength = totalWithoutHeader.size();
	//cout<<"Length of the document = header length "<<headerLength<<endl;

	cout<<endl<<endl;
	//cout<<totalWithoutHeader<<endl;

	//Header
	size_t hLength=0;
	uint8_t *hBytes = NewHeaderEncoder(hSize, &hLength);
//	printf("Output Length is :%d\n\n", hLength);

	//Total
	size_t docSize = hLength+hSize;
//	printf("Document size is :%d\n\n", docSize);

	uint8_t *docBytes = new uint8_t[docSize];
	memset(docBytes,0, sizeof(uint8_t)*docSize);
	//int count=0;
	// while(count<docSize)
  {
        memcpy(docBytes, hBytes, hLength);
        memcpy(docBytes+hLength, aBytes, aSize);
        memcpy(docBytes+hLength+aSize, nBytes, nSize);
        memcpy(docBytes+hLength+aSize+nSize, eBytes, eSize);
        memcpy(docBytes+hLength+aSize+nSize+eSize, dBytes, dSize);
        memcpy(docBytes+hLength+aSize+nSize+eSize+dSize, pBytes, pSize);
        memcpy(docBytes+hLength+aSize+nSize+eSize+dSize+pSize, qBytes, qSize);
        memcpy(docBytes+hLength+aSize+nSize+eSize+dSize+pSize+qSize, exp1Bytes, exp1Size);
        memcpy(docBytes+hLength+aSize+nSize+eSize+dSize+pSize+qSize+exp1Size, exp2Bytes, exp2Size);
        memcpy(docBytes+hLength+aSize+nSize+eSize+dSize+pSize+qSize+exp1Size+exp2Size, uBytes, uSize);           
  }

#if DEBUG  
	for(int i=0; i<docSize; i++)
		printf("%02x", docBytes[i]);
	cout<<endl<<endl;
#endif

	//string headerString;

	//headerString = TLVEncoderHeader(headerLength);

	//cout<<"Header String is : "<<headerString<<endl;

	//string document;
	//document = headerString+totalWithoutHeader;

	cout<<endl<<endl;
	//cout<<document<<endl;

	//ofstream HEXFile;
	//  HEXFile.open("private_1024.hex");
	//  HEXFile<<document;
	//  HEXFile.close();

	/*
	ofstream DERFile;
	DERFile.open("private_1024.der");
	int index = 0;

	vector<string> myList = myTokenizer(const_cast<char*>(document.c_str()));
	for (vector<string>::iterator i = myList.begin();i != myList.end();i++)
	{
	//cout<< *i <<endl;
	index = hexToInt(*i);
	DERFile << (unsigned char)index;
	} 
	DERFile.close();
	*/

	int DERFile;

#if DEBUG
	for(int i=0; i<docSize; i++)
	printf("%02x", docBytes[i]);
#endif
	DERFile =open("private_1k.der",O_RDWR|O_CREAT);
	if ( DERFile < 0 ) {
		printf("unable to open file\n");
	}
	for(int i=0; i<docSize; i++)
		write(DERFile, (const void*)&docBytes[i], 1);

	close(DERFile);


	string encoded = base64_encode(reinterpret_cast<const unsigned char*>(docBytes),docSize);
#if DEBUG
	cout<<endl<<"Base64Coded string is:"<<endl<<encoded<<endl;
#endif
	int PEMFile;
	int counter = 0;
	int index=0;
	const char* startPEM ="-----BEGIN RSA PRIVATE KEY-----";
	const char* endPEM="-----END RSA PRIVATE KEY-----";
	int encodedLength = encoded.size();
//	printf("The size of encoded string is : %d\n", encodedLength);
	char* base64encoded = (char*)(encoded.c_str());
	int newLineCheck = encodedLength;

	PEMFile =open(privateKeyFileName,O_WRONLY|O_CREAT);
	if ( PEMFile < 0 )
	{
		printf("unable to open file\n");
	}
	write(PEMFile, startPEM, strlen(startPEM));
	write(PEMFile,"\n", 1);
	for(int i=0; i<encodedLength ; i++)
	{
		write(PEMFile,(const char*)&base64encoded[i], 1);
		counter++;
		if(counter == 64)		
		{
			counter=0;
			if( i != (newLineCheck-1))
			write(PEMFile,"\n", 1);
		}
	}
	write(PEMFile,"\n", 1);
	write(PEMFile, endPEM, strlen(endPEM));

	close(PEMFile);
}


string readPEMFile(char* inputFile)
{
	string output;
    
    	string line;

    	ifstream myfile (inputFile);
    	if(myfile.is_open())
    	{
	
        	while(myfile.good())
        	{
                            getline(myfile,line);
                            //cout<<line<<endl;
				if(line[0]=='-')
					continue;
                            output.append(line.c_str());
                            //output.append("\n");
                            //break;
        	}
#if DEBUG
        	cout<<output<<endl;
#endif
        	myfile.close();     
    	}
        
#if DEBUG
	printf("Length of the string array : %d\n",output.size());
      	printf("Length of the string array to char : %d\n",strlen(output.c_str()));
#endif
	return output;
}

void encrypt(char* publicPEM, char* inputFileName, char* cipherFileName)
{
	struct publicKey* pubKey;

	string output = readPEMFile(publicPEM);
	
	char *decoded =  base64Decoder((char *)output.c_str());
	pubKey = decodePublicKey(decoded);
	
	int fmsg;
	int msgLen;
	//char* inputFileName = new char[255];
	//printf("Enter the Message filename :\n");
	//scanf("%s", inputFileName);
	
	fmsg = open(inputFileName, O_RDONLY);
	if(fmsg<0)
	{
		printf("Unable to open a read File\n");
	}
	char* textMessage = new char[SIZE-11];
	memset(textMessage, 0, SIZE-11);
	int numRead = read(fmsg, textMessage, SIZE-11);
#if DEBUG
	printf("The length read from file : %d\n", strlen(textMessage));
	printf("Message is:\n%s\n", textMessage);
#endif

	msgLen = strlen(textMessage);

	if(msgLen > MSGSIZE)
	{
		printf("Message too large for encryption\n");
		exit(1);
	}
	
	//gmp_printf("\n%Zd\n", pubKey->e);
	//gmp_printf("\n%Zd\n", pubKey->n);

	uint8_t* encryptedText = rsaEncryption(pubKey->n,pubKey->e,textMessage,msgLen);


//	printf("Returned from encryption\n");
	int cipherFile;

	//char* cipherFileName = new char[255];
	//printf("Enter the Cipher filename :\n");
	//scanf("%s", cipherFileName);

	cipherFile =open(cipherFileName,O_RDWR|O_CREAT);
	if ( cipherFile < 0 ) {
		printf("unable to open file\n");
	}
	for(int i=0; i<SIZE; i++)
		write(cipherFile, (const void*)&encryptedText[i], 1);

	close(cipherFile);

	
	mpz_clear(pubKey->n);
	mpz_clear(pubKey->e);
	free(pubKey);
}


uint8_t* rsaSignature(mpz_t n,mpz_t d,uint8_t* EM,int mLen)
{
	
	mpz_t msgNum;		mpz_init(msgNum);
	mpz_t cipherNum;	mpz_init(cipherNum);

	mpz_import(msgNum, SIZE, 1, sizeof(EM[0]),0,0, EM);
	
	//gmp_printf("\n%Zd\n", msgNum);
	//printf("Size of the number : %d\n", mpz_sizeinbase(msgNum, 2));	
	
	mpz_powm(cipherNum,msgNum,d,n);
	size_t cipherLen;
	uint8_t* cipher= (uint8_t *)mpz_export(NULL,&cipherLen,1,1,0,0,cipherNum);
	
//	printf("The length of the ciphertext = %d\n", cipherLen);
	if(cipherLen != SIGNSIZE)
	{
		printf("Encryption Failed: Cipher Length != BitRsa/8");
	}
	mpz_clear(msgNum);
	mpz_clear(cipherNum);
	return cipher;
}




uint8_t* calculateT(uint8_t* hashMessage)
{
	uint8_t* T = new uint8_t[SIGNSIZE];
	memset(T, 0, SIGNSIZE);
	uint8_t algoInfo[15] ={0x30,0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
	//20+15
	T[0]= 0x00;
	T[1]= 0x01;
	int lengthPS = SIZE - 35 - 3;
	const uint8_t constantPad = 0xff;
	
	int index=2;
	for(int i=0; i<lengthPS; i++)
	{
		T[index++]=0xff;
	}
	
	T[index++]=0x00;
		
	memcpy(T+index, algoInfo, sizeof(uint8_t)*15);
	memcpy(T+index+15, hashMessage, sizeof(uint8_t)*20);	

#if DEBUG
	for(int i=0; i<SIGNSIZE; i++)
		printf("%02x ",T[i]);
	printf("\n");
#endif	
	return T;
}


void signMessage(char* priPEM, char* inputFileName, char* cipherFileName)
{
	struct privateKey* priKey;

	string output = readPEMFile(priPEM);
	
	char *decoded =  base64Decoder((char *)output.c_str());
	priKey = decodePrivateKey(decoded);
	
	int fmsg;
	int msgLen;
	//char* inputFileName = new char[255];
	//printf("Enter the Message filename :\n");
	//scanf("%s", inputFileName);
	
	fmsg = open(inputFileName, O_RDONLY);
	if(fmsg<0)
	{
		printf("Unable to open a read File\n");
	}
	char* textMessage = new char[SIGNSIZE];
	memset(textMessage, 0, SIGNSIZE);
	int numRead = read(fmsg, textMessage, SIGNSIZE);
//	printf("The length read from file : %d\n", strlen(textMessage));
//	printf("Message is:\n%s\n", textMessage);
	msgLen = strlen(textMessage);
	
	uint8_t* hashMessage = new uint8_t[20];
	memset(hashMessage, 0, 20); 
	SHA1((const unsigned char*)textMessage,msgLen, hashMessage);

//	printf("Hash message = %s\n", hashMessage);

	 
	
	uint8_t* T = calculateT(hashMessage);

#if DEBUG
	for(int i=0; i<SIGNSIZE; i++)
		printf("%02x ",T[i]);
	printf("\n");
#endif	
	
	//gmp_printf("\n%Zd\n", pubKey->e);
	//gmp_printf("\n%Zd\n", pubKey->n);

	uint8_t* encryptedText = rsaSignature(priKey->n,priKey->d,T, SIZE);

//	printf("Returned from encryption\n");
	int cipherFile;

	//char* cipherFileName = new char[255];
	//printf("Enter the Cipher sign filename :\n");
	//scanf("%s", cipherFileName);

	cipherFile =open(cipherFileName,O_RDWR|O_CREAT);
	if ( cipherFile < 0 ) {
		printf("unable to open file\n");
	}
	for(int i=0; i<SIGNSIZE; i++)
		write(cipherFile, (const void*)&encryptedText[i], 1);

	close(cipherFile);

	
	freePrivateStructure(priKey);
}


void encryptByCertificate(char* certPEM, char* inputFileName, char* cipherFileName)
{
	string output;
    
    	string line;

    	ifstream myfile (certPEM);
    	if(myfile.is_open())
    	{
	
        	while(myfile.good())
        	{
                            getline(myfile,line);
                            //cout<<line<<endl;
				if(line[0]=='-')
					continue;
                            output.append(line.c_str());
                            //output.append("\n");
                            //break;
        	}
#if DEBUG
        	cout<<output<<endl;
#endif
        	myfile.close();     
    	}
        
      	char *decoded =  base64Decoder((char *)output.c_str());
    
	//char *decoded =  base64Decoder(input);
	
	struct certificate structure;

	structure = decodeX509(decoded);
	
	struct publicKey* pubKey = extractKeysFromCertificate(structure);

	int fmsg;
	int msgLen;
	//char* inputFileName = new char[255];
	//printf("Enter the Message filename :\n");
	//scanf("%s", inputFileName);
	
	fmsg = open(inputFileName, O_RDONLY);
	if(fmsg<0)
	{
		printf("Unable to open a read File\n");
	}
	char* textMessage = new char[SIZE-11];
	memset(textMessage, 0, SIZE-11);
	int numRead = read(fmsg, textMessage, SIZE-11);
#if DEBUG
	printf("The length read from file : %d\n", strlen(textMessage));
	printf("Message is:\n%s\n", textMessage);
#endif
	msgLen = strlen(textMessage);

	if(msgLen > MSGSIZE)
	{
		printf("Message too large for encryption\n");
		exit(1);
	}
	
	//gmp_printf("\n%Zd\n", pubKey->e);
	//gmp_printf("\n%Zd\n", pubKey->n);

	uint8_t* encryptedText = rsaEncryption(pubKey->n,pubKey->e,textMessage,msgLen);

//	printf("Returned from encryption\n");
	int cipherFile;

	//char* cipherFileName = new char[255];
	//printf("Enter the Cipher filename :\n");
	//scanf("%s", cipherFileName);

	cipherFile =open(cipherFileName,O_WRONLY|O_CREAT);
	if ( cipherFile < 0 ) {
		printf("unable to open file\n");
	}
	for(int i=0; i<SIZE; i++)
		write(cipherFile, (const void*)&encryptedText[i], 1);

	close(cipherFile);

	
	mpz_clear(pubKey->n);
	mpz_clear(pubKey->e);
	free(pubKey);
	

}



void decrypt(char* privatePEM, char* cipherFileName, char* decipherFileName)
{

	struct privateKey* priKey;

	string output = readPEMFile(privatePEM);
	
	char *decoded =  base64Decoder((char *)output.c_str());
	priKey = decodePrivateKey(decoded);
	
	//char* cipherFileName = new char[255];
	//printf("Enter the encrypted File name :\n");
	//scanf("%s", cipherFileName);
	
	int cmsg;
	cmsg = open(cipherFileName, O_RDONLY);
	if(cmsg<0)
	{
		printf("Unable to open a read File\n");
	}
		

	uint8_t* encryptedText = new uint8_t[SIZE];
	memset(encryptedText, 0, SIZE);
	int numRead = read(cmsg, encryptedText, SIZE);
	//printf("The length read from file : %d\n", strlen((unsigned char *)encryptedText));

	
	int finalLength;
	uint8_t* decryptedText = rsaDecryption(priKey->n, priKey->d, encryptedText, &finalLength);
	//printf("FinalLength = %d\n", finalLength);

	int decryptedFile;
	decryptedFile =open(decipherFileName,O_RDWR|O_CREAT);
    	if ( decryptedFile < 0 ) {
        	printf("unable to open file\n");
    	}
    	for(int i=0; i<finalLength; i++)
          write(decryptedFile, (const void*)&decryptedText[i], 1);

    close(decryptedFile);
}


void rsaVerify(mpz_t n, mpz_t e, uint8_t* cipher, int* finalLength, char* inputFileName)
{
	mpz_t cipherNum;	mpz_init(cipherNum);
	mpz_t msgNum;		mpz_init(msgNum);
	mpz_import(cipherNum, SIZE, 1, sizeof(cipher[0]),0,0, cipher);
	mpz_powm(msgNum, cipherNum, e, n);

	//gmp_printf("\n%Zd\n", msgNum);
	
	size_t tempmsgLen;
	uint8_t* tempMsg= (uint8_t *)mpz_export(NULL,&tempmsgLen,1,1,0,0,msgNum);

//	printf("The length of the message = %d\n", tempmsgLen);

	uint8_t* msg;
	
	if(tempmsgLen < SIZE)
	{
		msg = leftPad(tempMsg, tempmsgLen, SIZE);
		
		tempmsgLen = SIZE;
	}
	else if (tempmsgLen == SIZE)
		{
			msg = tempMsg;
		}
		else
		{
			printf("Decryption Failed:The size of the ecrypted message > BitRsa/8");
		}

	
	int fmsg;
	int msgLen;
	//char* inputFileName = new char[255];
	//printf("Enter the Message filename :\n");
	//scanf("%s", inputFileName);
	
	fmsg = open(inputFileName, O_RDONLY);
	if(fmsg<0)
	{
		printf("Unable to open a read File\n");
	}
	char* textMessage = new char[SIGNSIZE];
	memset(textMessage, 0, SIGNSIZE);
	int numRead = read(fmsg, textMessage, SIGNSIZE);
#if DEBUG
	printf("The length read from file : %d\n", strlen(textMessage));
	printf("Message is:\n%s\n", textMessage);
#endif
	msgLen = strlen(textMessage);
	
	uint8_t* hashMessage = new uint8_t[20];
	memset(hashMessage, 0, 20); 
	SHA1((const unsigned char*)textMessage,msgLen, hashMessage);

//	printf("Hash message = %s\n", hashMessage);

	 
	
	uint8_t* T = calculateT(hashMessage);
	
	if(memcmp(T, msg, SIGNSIZE) == 0)
	{
		printf("\nVerification OK\n");
	}		
	else
	{
		printf("\nVerification Failure\n");
	}
	

}

void verifySign(char* pubPEM, char* cipherFileName, char* inputFileName)
{

	struct publicKey* pubKey;

	string output = readPEMFile(pubPEM);
	
	char *decoded =  base64Decoder((char *)output.c_str());
	pubKey = decodePublicKey(decoded);
	



	//char* cipherFileName = new char[255];
	//printf("Enter the encrypted Sig File name :\n");
	//scanf("%s", cipherFileName);
	
	int cmsg;
	cmsg = open(cipherFileName, O_RDONLY);
	if(cmsg<0)
	{
		printf("Unable to open a read File\n");
	}
		

	uint8_t* encryptedText = new uint8_t[SIZE];
	memset(encryptedText, 0, SIZE);
	int numRead = read(cmsg, encryptedText, SIZE);
	//printf("The length read from file : %d\n", strlen((unsigned char *)encryptedText));

	
	int finalLength;
	rsaVerify(pubKey->n, pubKey->e, encryptedText, &finalLength, inputFileName);
	
}

void verifySignByCertificate(char* certPEM, char* cipherFileName, char* inputFileName)
{
	string output;
    	string line;
    	ifstream myfile (certPEM);
    	if(myfile.is_open())
    	{
	
        	while(myfile.good())
        	{
                            getline(myfile,line);
                            //cout<<line<<endl;
				if(line[0]=='-')
					continue;
                            output.append(line.c_str());
                            //output.append("\n");
                            //break;
        	}
#if DEBUG
        	cout<<output<<endl;
#endif
        	myfile.close();     
    	}
        
      	char *decoded =  base64Decoder((char *)output.c_str());
 
	//char *decoded =  base64Decoder(input);
	
	struct certificate structure;
	structure = decodeX509(decoded);
	struct publicKey* pubKey = extractKeysFromCertificate(structure);
	
	int cmsg;
	cmsg = open(cipherFileName, O_RDONLY);
	if(cmsg<0)
	{
		printf("Unable to open a read File\n");
	}
		

	uint8_t* encryptedText = new uint8_t[SIZE];
	memset(encryptedText, 0, SIZE);
	int numRead = read(cmsg, encryptedText, SIZE);
	//printf("The length read from file : %d\n", strlen((unsigned char *)encryptedText));

	
	int finalLength;
	rsaVerify(pubKey->n, pubKey->e, encryptedText, &finalLength, inputFileName);

}


void encodePublicKeyNew(mpz_t n, mpz_t e, char* publicKeyFileName)
{

//	printf("Public key Part\n");
	//Modulus
	size_t mod_size;
	uint8_t *modulus_bytes = (uint8_t *)mpz_export(NULL,&mod_size,1,1,0,0,n);
	  
	size_t nSize=0;
	uint8_t* nBytes = NewEncoder(modulus_bytes, mod_size, &nSize);
#if DEBUG
	printf("Output Length is :%d\n\n", nSize);
#endif
	uint8_t *e_bytes = (uint8_t *)mpz_export(NULL,&mod_size,1,1,0,0,e);
  	size_t eSize=0;
  	uint8_t* eBytes = NewEncoder(e_bytes, mod_size, &eSize);
#if DEBUG  
	printf("Output Length is :%d\n\n", eSize);
#endif	
	//Without Header
  	size_t hSize = nSize+eSize;
 // 	cout<<"Length of the document w/o header length "<<hSize<<endl;
	
	//Header
  	size_t hLength=0;
  	uint8_t *hBytes = NewHeaderEncoder(hSize, &hLength);
//  	printf("Output Length is :%d\n\n", hLength);
  
	size_t bitStringSequenceLength = hLength+hSize+1;

	size_t bitStringHeaderLength=0;
  	uint8_t *bitStringBytes = BitStringHeaderEncoder(bitStringSequenceLength, &bitStringHeaderLength);
#if DEBUG
  	printf("Output Length including bit string is :%d\n\n", bitStringHeaderLength);

	
	for(int i=0; i<(bitStringHeaderLength); i++)
		printf("%02x", bitStringBytes[i]);
  cout<<endl<<endl;
#endif
	
	uint8_t bitpadByte = 0x00;

	size_t sequenceLength = 15;
	size_t lengthWOHeader = sequenceLength+bitStringHeaderLength+bitStringSequenceLength;
	
//	printf("Output Length except header is :%d\n\n", lengthWOHeader);

	size_t docHeaderLength=0;
  	uint8_t *startBytes = NewHeaderEncoder(lengthWOHeader, &docHeaderLength);
#if DEBUG
  	printf("Output Header Length is :%d\n\n", docHeaderLength);

	for(int i=0; i<(docHeaderLength); i++)
		printf("%02x", startBytes[i]);
  cout<<endl<<endl;
#endif
  	//Total
  	size_t docSize = docHeaderLength+lengthWOHeader;
//  	printf("Document size is :%d\n\n", docSize);
	

	uint8_t *docBytes = new uint8_t[docSize];
  	memset(docBytes,0, sizeof(uint8_t)*(docSize));
  	//int count=0;
 	// while(count<docSize)

	int index=0;
	
	memcpy(docBytes, startBytes, docHeaderLength);
	//docBytes[index++]=0x30;
	

	//docBytes[index++]=0x81; 
	//docBytes[index++]=0x9f;
	index = docHeaderLength;
	
	docBytes[index++]=0x30; 
	docBytes[index++]=0x0d; 
	docBytes[index++]=0x06; 
	docBytes[index++]=0x09; 
	docBytes[index++]=0x2a; 
	docBytes[index++]=0x86; 
	docBytes[index++]=0x48; 
	docBytes[index++]=0x86; 
	docBytes[index++]=0xf7;
	docBytes[index++]=0x0d; 
	docBytes[index++]=0x01; 
	docBytes[index++]=0x01;
	docBytes[index++]=0x01; 
	docBytes[index++]=0x05; 
	docBytes[index++]=0x00;

	memcpy(docBytes+index,bitStringBytes, bitStringHeaderLength);

	index = index+bitStringHeaderLength;

	//docBytes[index++]=0x03; 
	//docBytes[index++]=0x81; 
	//docBytes[index++]=0x8d;
	docBytes[index++]=0x00;
  {
        memcpy(docBytes+index, hBytes, hLength);
        memcpy(docBytes+index+hLength, nBytes, nSize);
        memcpy(docBytes+index+hLength+nSize, eBytes, eSize);          
  }
 #if DEBUG 
  for(int i=0; i<(docSize); i++)
          printf("%02x", docBytes[i]);
  cout<<endl<<endl;
#endif
	

	int DERFile;
  //	for(int i=0; i<docSize; i++)
    //      	printf("%02x", docBytes[i]);
          
    	DERFile =open("public_1k.der",O_WRONLY|O_CREAT);
    	if ( DERFile < 0 ) {
        	printf("unable to open file\n");
    	}
    	for(int i=0; i<docSize; i++)
          	write(DERFile, (const void*)&docBytes[i], 1);
          
    	close(DERFile);
  
	
	 string encoded = base64_encode(reinterpret_cast<const unsigned char*>(docBytes),docSize);
#if DEBUG
	cout<<endl<<"Base64Coded string is:"<<endl<<encoded<<endl;
#endif
	int PEMFile;
	int counter = 0;
	index=0;
	const char* startPEM ="-----BEGIN PUBLIC KEY-----";
	const char* endPEM="-----END PUBLIC KEY-----";
	int encodedLength = encoded.size();
//	printf("The size of encoded string is : %d\n", encodedLength);
	char* base64encoded = (char*)(encoded.c_str());

	int newLineCheck = encodedLength;

	PEMFile =open(publicKeyFileName,O_RDWR|O_CREAT);
	if ( PEMFile < 0 )
	{
		printf("unable to open file\n");
	}
	write(PEMFile, startPEM, strlen(startPEM));
	write(PEMFile,"\n", 1);
	for(int i=0; i<encodedLength ; i++)
	{
		write(PEMFile,(const char*)&base64encoded[i], 1);
		counter++;
		if(counter == 64)		
		{
			counter=0;
			if( i != (newLineCheck-1))
			write(PEMFile,"\n", 1);
		}
	}
	write(PEMFile,"\n", 1);
	write(PEMFile, endPEM, strlen(endPEM));
	write(PEMFile,"\n", 1);
	close(PEMFile);
	

}



void genKeys(char* privateKeyFile, char* publicKeyFile)
{
	mpz_t pub_key;   mpz_init(pub_key);
	 mpz_t pri_key;   mpz_init(pri_key);
	 mpz_t p;         mpz_init(p);
	 mpz_t q;         mpz_init(q);
	 mpz_t phi;       mpz_init(phi);
	 
	 mpz_t n;         mpz_init(n);
	 mpz_t temp;      mpz_init(temp);
	 mpz_t temp1;     mpz_init(temp1);
	 mpz_t check;     mpz_init(check);
	 
	 mpz_t exp1;      mpz_init(exp1);
	 mpz_t exp2;      mpz_init(exp2);
	 mpz_t coef;      mpz_init(coef);

	char buf[BUFSIZE];
 
	 char infile[100];
	 char outfile[100];
	 FILE *fin, *fout;
	 long lFileLen;
	 int index=0;

	//Initializing my public key
  //65,537
  mpz_set_ui(pub_key, 0x10001);
#if DEBUG  
  printf("My Public key is :");
  gmp_printf("\n%Zd\n", pub_key);
 #endif
  //srand(time(NULL));
 
  
  for (int i=0; i< BUFSIZE; i++)
  {
     buf[i]= rand() % 0xFF;
  }
  //Set the initial bits of the buffer to 1, so te ensure we get a relatively large number
  buf[0] |= 0xC0;
 //Set the last bit of buffer to 1, so to get an odd number
 buf[BUFSIZE-1] |= 0x01;
 
 //Now convert this char buffer to an int
 mpz_import(temp, BUFSIZE, 1, sizeof(buf[0]), 0, 0, buf);
 
  //gmp_printf("\n%Zd\n", temp);
  
  mpz_nextprime(p, temp);
  //gmp_printf("\n%Zd\n", p);
  //printf("Check if p is coprime or not, Ideally it should be :) \n");
  //mpz_mod(check,p,pub_key);
  //gmp_printf("%Zd\n",check);
  //printf("......Finished checking......\n");
  
  memset(buf, 0, sizeof(buf));
  do{
           for (int i=0; i< BUFSIZE; i++)
           {
                 buf[i]= rand() % 0xFF;
           }
           //Set the initial bits of the buffer to 1, so te ensure we get a relatively large number
           buf[0] |= 0xC0;
           //Set the last bit of buffer to 1, so to get an odd number
           buf[BUFSIZE-1] |= 0x01;
           //Now convert this char buffer to an int
           mpz_import(temp, BUFSIZE, 1, sizeof(buf[0]), 0, 0, buf);
    //       gmp_printf("\n%Zd\n", temp);
           mpz_nextprime(q, temp);
    //       gmp_printf("\n%Zd\n", q);
    //       printf("Check if q is coprime or not, Ideally it should be :) \n");
    //       mpz_mod(check,q,pub_key);
    //       gmp_printf("%Zd\n",check);
    //       printf("......Finished checking......\n");
  }while(mpz_cmp(p,q) == 0);
  
  //Computing and storing the value of n = p.q
  mpz_mul(n,p,q);
  //gmp_printf("\n Value of n \n%Zd\n", n);
  
  //Compute phi = (p-1).(q-1)
  mpz_sub_ui(temp, p, 1);
  mpz_sub_ui(temp1, q, 1);
  mpz_mul(phi, temp, temp1);
  
  //gmp_printf("\n Value of phi \n%Zd\n", phi);
  //if(mpz_cmp(n,phi) > 0)
  //       printf("\n n > phi \n");
  
  mpz_gcd(temp, pub_key, phi);
  if(mpz_cmp_ui(temp,1) != 0)
  {
        printf("\n Rechoose your public key or use different primes: e mod(phi)!=1\n");
        exit(0);             
  }
  
  //Calculating private key
  mpz_invert(pri_key, pub_key, phi);
  //gmp_printf("\n Value of private key \n%Zd\n", pri_key);
  
  mpz_mul(temp, pub_key, pri_key);
  mpz_mod(temp1, temp, phi);
  gmp_printf("\n e.d mod(phi) = %Zd\n", temp1);
  
  //gmp_printf("\n%Zd\n", p);
  //gmp_printf("\n%Zd\n", q);
  //Checking p<q
  /*if(mpz_cmp(p,q) > 0)
  {
        mpz_set(temp, p);
        mpz_set(p, q);
        mpz_set(q, temp);

  }*/
       
  //gmp_printf("\n%Zd\n", p);
  //gmp_printf("\n%Zd\n", q);
                  
  
  
  //Generating the chinese remainder coefficient
  mpz_sub_ui(temp, p, 1);
  mpz_sub_ui(temp1, q, 1);
  
  mpz_mod(exp1, pri_key, temp);
  mpz_mod(exp2, pri_key, temp1);
  
  mpz_mod_inverse(coef,q ,p);

	encodePrivateKey(n, pub_key, pri_key, p, q, exp1, exp2, coef, privateKeyFile);
	

	encodePublicKeyNew(n, pub_key, publicKeyFile);
	

	mpz_clear(pub_key);
	mpz_clear(pri_key);

	mpz_clear(p);
	mpz_clear(q);
	mpz_clear(n);
	mpz_clear(phi);
	mpz_clear(exp1);
	mpz_clear(exp2);
	mpz_clear(coef);

	mpz_clear(temp);
	mpz_clear(temp1);
	mpz_clear(check);
	exit(0);	
}

void printUsage(char* execName)
{
	printf("For generating private and public key pair\n");
	printf("%s genra <privateKeyFileName> <publicKeyFileName>\n", execName);
	printf("For encryption\n");
	printf("%s -e -key <PrivatePemFile> -in PlainTextFile -out CipherTextFile\n", execName);
	printf("For encryption from certificate\n");
	printf("%s -e -crt <Certificate> -in PlainTextFile -out CipherTextFile\n", execName);
	printf("For decryption\n");
	printf("%s -d -key <PublicPemFile> -in CipherTextFile -out DecipheredTextFile\n", execName);
	printf("For Signing data with Private Key\n");
	printf("%s -s -key <PrivatePemFile> -in PlainTextFile -out SignedDataFile\n", execName);
	printf("For Verifying data with Public Key\n");
	printf("%s -v -key <PublicPemFile> -signature SignedDataFile PlainTextFile\n", execName);
	printf("For Verifying data with Certificate\n");
	printf("%s -v -crt <Certificate> -signature SignedDataFile PlainTextFile\n", execName);
	exit(0);
}




int main(int argc, char *argv[])
{
 
 char buf[BUFSIZE], message[MSGSIZE], *cipherText, *decreptedText;
 

 FILE *fin, *fout;
 long lFileLen;
 int index=0;
 
 const char *s1,*s2,*s3;
	const char *s4,*s5,*s6;
	const char *s7, *s8, *s9;
	const char *s10;
	const char *help;
	help="-h";
	s1 = "genrsa";
	s2 = "-e";
	s3 = "-d";
	s4 = "-key";
	s5 ="-in";
	s6 = "-out";
	s7 = "-crt";
	s8 = "-s";
	s9 = "-v";
	s10= "-signature";	

	int argCheck =0;

	//Command Line options

	if(argc == 2)
	{
		if(strcmp(argv[1],help) == 0)
		{
			printUsage(argv[0]);
		}
		exit(0);
	}

	if (argc == 4)
	{
	
		if(strcmp(argv[1], s1) == 0)
		{
			printf("Usage:\n%s genrsa\n", argv[0]);
			genKeys((char*)argv[2], (char*)argv[3]);
		}
		else if(strcmp(argv[1],help) == 0)
			{
				printUsage(argv[0]);
			}
			else
			{	
	         		printf("Type:\n%s -h for help commands \n", argv[0]);
	 			exit(0);	
    			}
		exit(0);
		
	}
	//printf("In ecryption\n");
	if((argc == 8) && ((strcmp(argv[1],s2)==0) || (strcmp(argv[1],s3)==0)))
	{
		//printf("In ecryption\n");
		if((strcmp(argv[1],s2)==0) && (strcmp(argv[2], s4)==0) && (strcmp(argv[4], s5)==0) && (strcmp(argv[6], s6)==0))
		{
			//printf("In ecryption\n");
			encrypt((char*)argv[3], (char*)argv[5], (char*)argv[7]);
			exit(0);
		}
		else if((strcmp(argv[1],s2)==0) && (strcmp(argv[2], s7)==0) && (strcmp(argv[4], s5)==0) && (strcmp(argv[6], s6)==0))
			{
				encryptByCertificate((char*)argv[3], (char*)argv[5], (char*)argv[7]);
				exit(0);
			}
			else if((strcmp(argv[1],s3)==0) && (strcmp(argv[2], s4)==0) && (strcmp(argv[4], s5)==0) && (strcmp(argv[6], s6)==0))
				{
					decrypt((char*)argv[3], (char*)argv[5], (char*)argv[7]);
					exit(0);
				}
				else
				{
					printf("Type:\n%s -h for help commands \n", argv[0]);
		 			exit(0);
				}
	}
	else if((argc == 8) && ((strcmp(argv[1],s8)==0)))
		{
			if((strcmp(argv[2], s4)==0) && (strcmp(argv[4], s5)==0) && (strcmp(argv[6], s6)==0))	
			{
				signMessage((char*)argv[3], (char*)argv[5], (char*)argv[7]);	
				exit(0);		
			}
			else
			{
				printf("Type:\n%s -h for help commands \n", argv[0]);
		 			exit(0);
			}
		}
		

	if(argc == 7)
	{
		if((strcmp(argv[1],s9)==0) && (strcmp(argv[2], s4)==0) && (strcmp(argv[4], s10)==0) )
		{
			verifySign((char*)argv[3], (char*)argv[5], (char*)argv[6]);	
			exit(0);		
		}
		else if((strcmp(argv[1],s9)==0) && (strcmp(argv[2], s7)==0) && (strcmp(argv[4], s10)==0))
			{
				verifySignByCertificate((char*)argv[3], (char*)argv[5], (char*)argv[6]);
				exit(0);
			}
	}
	else
	{
		printf("Type:\n%s -h for help commands \n", argv[0]);
	 	exit(0);
	}

	printf("Type:\n%s -h for help commands \n", argv[0]);
	 	exit(0);
	
	exit(0);

 


#if ENCRYPT


	char* pubFileName = new char[255];
	printf("Enter the Public Key File for encryption:\n");
	scanf("%s", pubFileName);
	encrypt((char *)pubFileName);



	char* priFileName = new char[255];
	printf("Enter the Private Key File for signature:\n");
	scanf("%s", priFileName);
	signMessage((char *)priFileName);




	char* pubSignFileName = new char[255];
	printf("Enter the Public Key File for signature:\n");
	scanf("%s", pubSignFileName);
	verifySign((char *)pubSignFileName);

#endif
#if ENCRYPT	
	char* priPemFileName = new char[255];
	printf("Enter the Private Key File for decryption:\n");
	scanf("%s", priPemFileName);
	decrypt((char *)priPemFileName);

	
	
#endif
	//encryptByCertificate();

	
	

 #if ENCRYPT
	

 
/**
**	Code take cares of the decryption
**/
  	
	char* decryptedText = rsaDecryption(n, pri_key, encryptedText);

	int decryptedFile;
	decryptedFile =open("decipheredText",O_WRONLY|O_CREAT);
    	if ( decryptedFile < 0 ) {
        	printf("unable to open file\n");
    	}
    	for(int i=0; i<SIZE; i++)
          write(decryptedFile, (const void*)&decryptedText[i], 1);

    close(decryptedFile);


#endif
  
 
}

