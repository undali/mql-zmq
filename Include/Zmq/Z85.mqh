//+------------------------------------------------------------------+
//| Module: Z85.mqh                                                  |
//| This file is part of the mql-zmq project:                        |
//|     https://github.com/dingmaotu/mql-zmq                         |
//|                                                                  |
//| Copyright 2016-2017 Li Ding <dingmaotu@hotmail.com>              |
//|                                                                  |
//| Licensed under the Apache License, Version 2.0 (the "License");  |
//| you may not use this file except in compliance with the License. |
//| You may obtain a copy of the License at                          |
//|                                                                  |
//|     http://www.apache.org/licenses/LICENSE-2.0                   |
//|                                                                  |
//| Unless required by applicable law or agreed to in writing,       |
//| software distributed under the License is distributed on an      |
//| "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,     |
//| either express or implied.                                       |
//| See the License for the specific language governing permissions  |
//| and limitations under the License.                               |
//+------------------------------------------------------------------+
#property strict

#include <Mql/Lang/Native.mqh>

#import "libzmq.dll"
// Encode data with Z85 encoding. Returns 0(NULL) if failed
/*
DESCRIPTION

The zmq_z85_encode() function shall encode the binary block specified by 'data' and 'size' into a string in 'dest'. The size of the binary block must be divisible by 4. The 'dest' must have sufficient space for size * 1.25 plus 1 for a null terminator. A 32-byte CURVE key is encoded as 40 ASCII characters plus a null terminator.

The encoding shall follow the ZMQ RFC 32 specification.
RETURN VALUE

The zmq_z85_encode() function shall return 'dest' if successful, else it shall return NULL.

#include <sodium.h>
uint8_t public_key [32];
uint8_t secret_key [32];
int rc = crypto_box_keypair (public_key, secret_key);
assert (rc == 0);
char encoded [41];
zmq_z85_encode (encoded, public_key, 32);
puts (encoded);
*/
// intptr_t zmq_z85_encode(char &str[],const uchar &data[],size_t size);
intptr_t zmq_z85_encode(uchar &dest[], const uchar &data[], ulong size);


// Decode data with Z85 encoding. Returns 0(NULL) if failed
/*
DESCRIPTION

The zmq_z85_decode() function shall decode 'string' into 'dest'. The length of 'string' shall be divisible by 5. 'dest' must be large enough for the decoded value (0.8 x strlen (string)).

The encoding shall follow the ZMQ RFC 32 specification.
RETURN VALUE

The zmq_z85_decode() function shall return 'dest' if successful, else it shall return NULL.
EXAMPLE
Decoding a CURVE key

const char decoded [] = "rq:rM>}U?@Lns47E1%kR.o@n%FcmmsL/@{H8]yf7";
uint8_t public_key [32];
zmq_z85_decode (public_key, decoded);

*/
//--- intptr_t zmq_z85_decode(uchar &dest[],const char &str[]);
intptr_t zmq_z85_decode(uchar &dest[], const uchar &str[]);


/*

NAME

zmq_curve_keypair - generate a new CURVE keypair
SYNOPSIS

int zmq_curve_keypair (char *z85_public_key, char *z85_secret_key);
DESCRIPTION

The zmq_curve_keypair() function shall return a newly generated random keypair consisting of a public key and a secret key. The caller provides two buffers, each at least 41 octets large, in which this method will store the keys. The keys are encoded using zmq_z85_encode.
RETURN VALUE

The zmq_curve_keypair() function shall return 0 if successful, else it shall return -1 and set 'errno' to one of the values defined below.
ERRORS

ENOTSUP

    The libzmq library was not built with cryptographic support (libsodium).

EXAMPLE
Generating a new CURVE keypair

char public_key [41];
char secret_key [41];
int rc = zmq_curve_keypair (public_key, secret_key);
assert (rc == 0);

*/
// Generate z85-encoded public and private keypair with tweetnacl/libsodium
//int zmq_curve_keypair(char &z85_public_key[],char &z85_secret_key[]);
int zmq_curve_keypair(uchar &z85_public_key[], uchar &z85_secret_key[]);
/*

DESCRIPTION

The zmq_curve_public() function shall derive the public key from a private key. The caller provides two buffers, each at least 41 octets large. In z85_secret_key the caller shall provide the private key, and the function will store the public key in z85_public_key. The keys are encoded using zmq_z85_encode.
RETURN VALUE

The zmq_curve_public() function shall return 0 if successful, else it shall return -1 and set 'errno' to one of the values defined below.
ERRORS

ENOTSUP

    The libzmq library was not built with cryptographic support (libsodium).

EXAMPLE
Deriving the public key from a CURVE private key

char public_key [41];
char secret_key [41];
int rc = zmq_curve_keypair (public_key, secret_key);
assert (rc == 0);
char derived_public[41];
rc = zmq_curve_public (derived_public, secret_key);
assert (rc == 0);
assert (!strcmp (derived_public, public_key));

*/

// Derive the z85-encoded public key from the z85-encoded secret key
//int zmq_curve_public(char &z85_public_key[],const char &z85_secret_key[]);
int zmq_curve_public(uchar &z85_public_key[], uchar &z85_secret_key[]);

#import
//+------------------------------------------------------------------+
//| Z85 encoding/decoding                                            |
//+------------------------------------------------------------------+
class Z85
  {
public:
   static bool       encode(string &secret,const uchar &data[]);
   static bool       decode(const string secret,uchar &data[]);

   static string     encode(string data);
   static string     decode(string secret);

   static bool       generateKeyPair(uchar &publicKey[],uchar &secretKey[]);
   static bool       derivePublic(uchar &publicKey[], uchar &secretKey[]);

   static bool       generateKeyPair(string &publicKey,string &secretKey);
   static string     derivePublic(const string secretKey);
  };
//+------------------------------------------------------------------+
//| data must have size multiple of 4                                |
//+------------------------------------------------------------------+
bool Z85::encode(string &secret,const uchar &data[])
  {
   int size=ArraySize(data);
   if(size%4 != 0) return false;

   uchar str[];
   ArrayResize(str,(int)(1.25*size+1));

   intptr_t res=zmq_z85_encode(str,data,size);
   if(res == 0) return false;
   secret = StringFromUtf8(str);
   return true;
  }
//+------------------------------------------------------------------+
//| secret must be multiples of 5                                    |
//+------------------------------------------------------------------+
bool Z85::decode(const string secret,uchar &data[])
  {
   int len=StringLen(secret);
   if(len%5 != 0) return false;

   uchar str[];
   StringToUtf8(secret,str);
   ArrayResize(data,(int)(0.8*len));
   return 0 != zmq_z85_decode(data,str);
  }
//+------------------------------------------------------------------+
//| data length should be multiples of 4 and only ascii is supported |
//+------------------------------------------------------------------+
string Z85::encode(string data)
  {
   uchar str[];
   StringToUtf8(data,str,false);
   string res;
   if(encode(res,str))
      return res;
   else
      return "";
  }
//+------------------------------------------------------------------+
//| secret must be multiples of 5                                    |
//+------------------------------------------------------------------+
string  Z85::decode(string secret)
  {
   uchar data[];
   decode(secret,data);
   return StringFromUtf8(data);
  }
//+------------------------------------------------------------------+
//|                                                                  |
//+------------------------------------------------------------------+
bool Z85::generateKeyPair(uchar &publicKey[],uchar &secretKey[])
  {
   ArrayResize(publicKey,41);
   ArrayResize(secretKey,41);
   return 0==zmq_curve_keypair(publicKey, secretKey);
  }
//+------------------------------------------------------------------+
//|                                                                  |
//+------------------------------------------------------------------+
bool Z85::derivePublic(uchar &publicKey[], uchar &secretKey[])
  {
   ArrayResize(publicKey,41);
   return 0==zmq_curve_public(publicKey, secretKey);
  }
//+------------------------------------------------------------------+
//|                                                                  |
//+------------------------------------------------------------------+
bool Z85::generateKeyPair(string &publicKey,string &secretKey)
  {
   uchar sec[],pub[];
   bool res=generateKeyPair(pub,sec);
   if(res)
     {
      secretKey=StringFromUtf8(sec);
      publicKey=StringFromUtf8(pub);
     }
   ArrayFree(sec);
   ArrayFree(pub);
   return res;
  }
//+------------------------------------------------------------------+
//|                                                                  |
//+------------------------------------------------------------------+
string Z85::derivePublic(const string secrect)
  {
   uchar sec[],pub[];
   StringToUtf8(secrect,sec);
   derivePublic(pub,sec);
   string pubstr=StringFromUtf8(pub);
   ArrayFree(sec);
   ArrayFree(pub);
   return pubstr;
  }
//+------------------------------------------------------------------+
