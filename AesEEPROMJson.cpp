
#include "AesEEPROMJson.h"




#ifdef EEPROM_AES_DEBUG

#ifndef ESP8266 
#include "./printf.h"
#endif

#define DEBUG_PRINT Serial.print
#define DEBUG_PRINTLN Serial.println

#else

#define DEBUG_PRINT(x) do {} while(0)
#define DEBUG_PRINTLN(x) do {} while(0)

#endif

#ifdef ESP8266 

#include "ESP8266TrueRandom.h"

#define randomByte(...) ESP8266TrueRandom.random(0,256)

#else

/*
 * 
   from https://gist.github.com/bloc97/b55f684d17edd8f50df8e918cbc00f94 *
*   
*/
const int waitTime = 16;

byte lastByte = 0;

byte leftStack = 0;
byte rightStack = 0;

byte rotate(byte b, int r) {
  return (b << r) | (b >> (8-r));
}

void pushLeftStack(byte bitToPush) {
  leftStack = (leftStack << 1) ^ bitToPush ^ leftStack;
}
void pushRightStackRight(byte bitToPush) {
  rightStack = (rightStack >> 1) ^ (bitToPush << 7) ^ rightStack;
}


byte getTrueRotateRandomByte() {
  byte finalByte = 0;
  
  byte lastStack = leftStack ^ rightStack;
  
  for (int i=0; i<4; i++) {
    delayMicroseconds(waitTime);
    int leftBits = analogRead(1);
    
    delayMicroseconds(waitTime);
    int rightBits = analogRead(1);
    
    finalByte ^= rotate(leftBits, i);
    finalByte ^= rotate(rightBits, 7-i);
    
    for (int j=0; j<8; j++) {
      byte leftBit = (leftBits >> j) & 1;
      byte rightBit = (rightBits >> j) & 1;
  
      if (leftBit != rightBit) {
        if (lastStack % 2 == 0) {
          pushLeftStack(leftBit);
        } else {
          pushRightStackRight(leftBit);
        }
      }
    }
    
  }
  lastByte ^= (lastByte >> 3) ^ (lastByte << 5) ^ (lastByte >> 4);
  lastByte ^= finalByte;
  
  return lastByte ^ leftStack ^ rightStack;
}
#define randomByte(...) getTrueRotateRandomByte()
#endif
/****************************************************************************/


AES aes ;

byte EEPROM_key [32] = {
    // pseudo random default key, replace this with actual key
    0x04, 0x4B, 0x57, 0xF7, 0x85, 0x87, 0x43, 0xB4, 
    0x28, 0x1C, 0xF0, 0x84, 0x08, 0x13, 0x8C, 0xB6, 
    0x47, 0xBF, 0x38, 0x6D, 0x0F, 0x44, 0x2B, 0x13, 
    0x25, 0x24, 0x6F, 0xE9, 0x2F, 0x05, 0x88, 0xC9
};

   


#define MAX_ENCODE_CHUNK 48
#define ENCODE_CHUNK_SPLIT 32

int encryptString_chunk (
    int bits,
    const char * plain,
    int plainLength,
    unsigned long long int use_iv, 
    int offset,
    void (*store)(int,int)) {
        
        int paddedLength = plainLength + N_BLOCK - plainLength % N_BLOCK;
        byte cipher [paddedLength];
        byte iv [N_BLOCK] ;
        
        aes.set_IV(use_iv);
        aes.get_IV(iv);
  
        //Serial.println("aes.do_aes_encrypt()");
        aes.do_aes_encrypt((byte *) plain,plainLength,cipher,EEPROM_key,bits,iv);
        //Serial.print("storing via loop:");
        //Serial.print(paddedLength);
        //Serial.println(" bytes");
        for (int i = 0; i< paddedLength; i ++) {
            byte data = cipher[i];
            store (i + offset,data);
        }
        //Serial.println("done");
        return paddedLength;
}


void encryptString (
    int bits,
    const char * plain,
    int plainLength,
    void (*store)(int,int)) {

        unsigned long long int store_iv ;
        unsigned long long int *iv_addr = (unsigned long long int *) &store_iv;
        byte *iv_addr2 = (byte *) iv_addr;
        for (int i = 0 ; i < sizeof(store_iv) ; i ++) {
            iv_addr2[i] = randomByte();
            store(i,iv_addr2[i]);
        }

        int offset = sizeof(store_iv);
        
        store(offset++,plainLength & 0xff);
        store(offset++,(plainLength & 0xff00) >> 8);
        
        int ptr = 0;
        
        if (plainLength > MAX_ENCODE_CHUNK ) {
            while (plainLength > ENCODE_CHUNK_SPLIT) {
                
                
                offset += encryptString_chunk(
                    bits,
                    &plain[ptr], ENCODE_CHUNK_SPLIT,
                    store_iv,
                    offset,
                    store
                ); 
                
                for (int i = 0 ; i < sizeof(store_iv) ; i ++) {
                    iv_addr2[i] = plain[ptr+i];
                }

                ptr         += ENCODE_CHUNK_SPLIT;
                plainLength -= ENCODE_CHUNK_SPLIT;
                
            }
        }
        
        encryptString_chunk(
            bits,
            &plain[ptr], plainLength,
            store_iv,
            offset,
            store
        ); 
        
}

char *decryptString ( int bits, char *output_buffer, int output_buffer_size, int (*fetch)(int) ) {
    int addr = 0;
    unsigned long long int use_iv = 0; 
    unsigned long long int *iv_addr = (unsigned long long int *) &use_iv;
    byte *iv_addr2 = (byte *) iv_addr;
    
    byte decryptInBuffer[ MAX_ENCODE_CHUNK + N_BLOCK  ];
    byte iv [N_BLOCK] ;
    
    for ( ; addr < sizeof(use_iv) ; addr ++) {
        iv_addr2[addr] = (byte) fetch(addr);
    }
    
    // addr points to length word (after stored iv)
    int decryptPlainSize   = fetch(addr) | ((int) fetch(addr+1) << 8);
    int decryptRemainSize  = decryptPlainSize;
    int paddedLength;
    if (!output_buffer) {
        DEBUG_PRINT("output_buffer is NULL");
        return NULL;
    } else {
        if (output_buffer_size < decryptPlainSize) {
            DEBUG_PRINT("output_buffer_size too small:");
            DEBUG_PRINT(output_buffer_size);
            DEBUG_PRINT(" < ");
            DEBUG_PRINTLN(decryptPlainSize);
            return NULL;
        }
    }
    
    int output_ptr = 0;
    
    // move past the length word
    addr += 2;
    
    if (decryptPlainSize > MAX_ENCODE_CHUNK) {
    
        while (decryptRemainSize > ENCODE_CHUNK_SPLIT) {
           
            paddedLength = ENCODE_CHUNK_SPLIT + N_BLOCK - ENCODE_CHUNK_SPLIT % N_BLOCK;

            for (int i = 0; i < paddedLength ; i++) {
                byte data = fetch(addr+i);
                decryptInBuffer[i] = data;
            }
            
            aes.set_IV(*iv_addr);
            aes.get_IV(iv);
            aes.do_aes_decrypt(decryptInBuffer,paddedLength,(byte *) &output_buffer[output_ptr],EEPROM_key,bits,iv);
            
            iv_addr = (unsigned long long int *) &output_buffer[output_ptr];
            
            decryptRemainSize -= ENCODE_CHUNK_SPLIT;
            output_ptr += ENCODE_CHUNK_SPLIT;
            addr += paddedLength;
            
        } 
    }
    
    paddedLength = decryptRemainSize + N_BLOCK - decryptRemainSize % N_BLOCK;

    for (int i = 0; i < paddedLength ; i++,addr ++) {
        byte data = fetch(addr);
        decryptInBuffer[i] = data;
    }
    aes.set_IV(*iv_addr);
    aes.get_IV(iv);

    aes.do_aes_decrypt(decryptInBuffer,paddedLength,(byte *) &output_buffer[output_ptr],EEPROM_key,bits,iv);
    
    // null terminate the returned char array
    output_buffer[decryptPlainSize]=0;
    return output_buffer;
}

int EEPROM_bits = 256;
char EEPROM_get_str_default[EEPROM_SIZE];

const char *EEPROM_get_str () {
    
    decryptString(EEPROM_bits,EEPROM_get_str_default,EEPROM_SIZE,
      [] (int addr) -> int {
          return EEPROM.read(addr);
      });
      
    return (const char *)EEPROM_get_str_default;
}
    
int EEPROM_load_str (char *output_buffer, int output_buffer_size) {
    decryptString(EEPROM_bits,output_buffer,output_buffer_size,
        [] (int addr) -> int {
            return EEPROM.read(addr);
        });
    return strlen(output_buffer);
}

void EEPROM_set_str(const char * str) {
    encryptString (
        EEPROM_bits,
        str,strlen(str),
        [](int addr,int data){
            EEPROM.write(addr,data);
        }
    );
    #ifdef ESP8266 
        EEPROM.commit();
    #endif
    
}

byte hex2dec (char h) {
    if (h >= '0' && h <= '9') {
        return h-'0';
    } else {
       if (h >= 'a' && h <= 'f') {
           return 0x0a + (h-'a');
       } else {
           if (h >= 'A' && h <= 'F') {
               return 0x0a + (h-'A');
           } else {
               return 0xff;
           }
       }
    }
}

void dec2hex (byte b, char *h) {
    byte B = (b >> 4) & 0x0f;
    h[0] = B < 0x0a ? '0'+B : 'a' + (B-0x0a);
    B = b & 0x0f;
    h[1] = B < 0x0a ? '0'+B : 'a' + (B-0x0a);
}

bool EEPROM_addEntropyPin (unsigned long PIN) {
   byte mask1 = PIN & 0xff;
   byte mask2 = (PIN >> 8) & 0xff;
   byte mask3 = (PIN >> 16) & 0xff;
   byte mask4 = (PIN >> 24) & 0xff;
   
   for (int i = 0; i < 32; i ++) {
         byte data = EEPROM_key[i];
         switch (i % 4) {
             case 0 : EEPROM_key[i] = data ^ mask1; continue;
             case 1 : EEPROM_key[i] = data ^ mask2; continue;
             case 2 : EEPROM_key[i] = data ^ mask3; continue;
             case 3 : EEPROM_key[i] = data ^ mask4; continue;
         }
   }
  
   return true;
}

bool EEPROM_setKey (const char * hex) {
  if (!hex) return false;
  
  for (int i = 0 ; i < 64 ; i ++ ) {
      byte c=hex2dec(hex[i]);
      if (c==0xff) {
          return false;
      }
     
      if ((i % 2) == 0) {
         EEPROM_key[i/2] = c << 4;
      } else {
         EEPROM_key[i/2] = EEPROM_key[i/2] | c;
      }
  }
  return hex[64]==0;
}

bool EEPROM_setKeyWithPin (const char *hex, unsigned long PIN) {
  if (EEPROM_setKey(hex)==false) return false;
  return EEPROM_addEntropyPin(PIN);
}




bool EEPROM_setSplitKey (const char * hex1, const char *hex2) {
  if (!hex1 || !hex2) return false;
  
  for (int i = 0 ; i < 32 ; i ++ ) {
      
      byte c1=hex2dec(hex1[i]);
      if (c1==0xff) {
          return false;
      }
      byte c2=hex2dec(hex2[i]);
      if (c2==0xff) {
          return false;
      }
      EEPROM_key[i]   = (c1 << 4) | c2;
  }    
  return (hex1[32]==hex2[32]) && (hex1[32]==0);
}

bool EEPROM_setSplitKeyWithPin (const char * hex1, const char *hex2, unsigned long PIN) {
  if (EEPROM_setSplitKey(hex1,hex2)==false) return false;
  return EEPROM_addEntropyPin(PIN);
}


void EEPROM_set_json (const char * key, const char *value ) {
    DynamicJsonDocument jsonBuffer(EEPROM_SIZE);
    deserializeJson(jsonBuffer,EEPROM_get_str());
    JsonObject root = jsonBuffer.as<JsonObject>();
    
    root[String(key)] = String(value);
    String json;
    serializeJson(jsonBuffer, json);
    EEPROM_set_str(json.c_str());
}


void EEPROM_set_json_int (const char * key, int value ) {
    DynamicJsonDocument jsonBuffer(EEPROM_SIZE);
    deserializeJson(jsonBuffer,EEPROM_get_str());
    JsonObject root = jsonBuffer.as<JsonObject>();
    
    root[String(key)] = value;
    String json;
    serializeJson(jsonBuffer, json);
    EEPROM_set_str(json.c_str());
}


void EEPROM_set_json_array_char (const char * key, int index, const char *value ) {
    
    DynamicJsonDocument jsonBuffer(EEPROM_SIZE);
    deserializeJson(jsonBuffer,EEPROM_get_str());
    JsonObject root = jsonBuffer.as<JsonObject>();
    
    root[String(key)][index] = String(value);
    String json;
    serializeJson(jsonBuffer, json);
    EEPROM_set_str(json.c_str());

}

void EEPROM_set_json_array_element_char (const char * key1, int index, const char * key2, const char *value ) {
    DynamicJsonDocument jsonBuffer(EEPROM_SIZE);
    deserializeJson(jsonBuffer,EEPROM_get_str());
    JsonObject root = jsonBuffer.as<JsonObject>();

    
    root[String(key1)][index][String(key2)] = String(value);
    String json;
    serializeJson(jsonBuffer, json);
    EEPROM_set_str(json.c_str());
}

const char *EEPROM_get_json (const char * key) {
    DynamicJsonDocument jsonBuffer(EEPROM_SIZE);
    deserializeJson(jsonBuffer,EEPROM_get_str());
    JsonObject root = jsonBuffer.as<JsonObject>();
    return (const char *) root[String(key)];
}

int EEPROM_get_json_int (const char * key) {
    DynamicJsonDocument jsonBuffer(EEPROM_SIZE);
    deserializeJson(jsonBuffer,EEPROM_get_str());
    JsonObject root = jsonBuffer.as<JsonObject>();
    return (int) root[String(key)];
}

int EEPROM_get_json_increment (const char * key, int incr) {
    DynamicJsonDocument jsonBuffer(EEPROM_SIZE);
    deserializeJson(jsonBuffer,EEPROM_get_str());
    JsonObject root = jsonBuffer.as<JsonObject>();
    int value = root[String(key)];
    value += incr;
    root[String(key)] = value;
    String json;
    serializeJson(jsonBuffer, json);
    EEPROM_set_str(json.c_str());
    return value;
}

const char *EEPROM_get_json_2deep (const char * key1,const char * key2) {
    DynamicJsonDocument jsonBuffer(EEPROM_SIZE);
    deserializeJson(jsonBuffer,EEPROM_get_str());
    JsonObject root = jsonBuffer.as<JsonObject>();
    return (const char *) root[String(key1)][String(key2)];
}

const char *EEPROM_get_array_char (const char * key,int index) {
    DynamicJsonDocument jsonBuffer(EEPROM_SIZE);
    deserializeJson(jsonBuffer,EEPROM_get_str());
    JsonObject root = jsonBuffer.as<JsonObject>();
    return (const char *) root[String(key)][index];
}

const char *EEPROM_get_array_element_char (const char * key1,int index,const char * key2) {
    DynamicJsonDocument jsonBuffer(EEPROM_SIZE);
    deserializeJson(jsonBuffer,EEPROM_get_str());
    JsonObject root = jsonBuffer.as<JsonObject>();
    return (const char *) root[String(key1)][index][String(key2)];
}

const char *EEPROM_local_key (char *buf) {
    for (int i = 0; i < 16; i ++) {
        dec2hex (EEPROM.read(EEPROM_SIZE + i), &buf[ (i*2) ]);
    }
    buf[32]=0;
    return (const char *) buf;
};

const char *EEPROM_new_local_key (char *buf) {
    for (int i = 0; i < 16; i ++) {
        byte b = randomByte();
        EEPROM.write(EEPROM_SIZE + i,b);
        dec2hex (b, &buf[ (i*2) ]);
    }
    buf[32]=0;
#ifdef ESP8266 
    EEPROM.commit();
#endif
    return (const char *) buf;
};

bool jsonFrame(
        int size,
        const char *json,
        bool (*callback) (JsonObject &,DynamicJsonDocument &) 
    
    ) {
    DynamicJsonDocument jsonBuffer(size);
    deserializeJson(jsonBuffer,json ? json : (const char *) "{}");
    JsonObject root = jsonBuffer.as<JsonObject>();
    return callback(root,jsonBuffer);
}


bool execJsonCmd(char*json, int buf_size) {
     return jsonFrame(buf_size,json,[] (JsonObject &args,DynamicJsonDocument &jsonBuffer) -> bool {
        const char *cmd=args["cmd"];
        for (int i=0;true;i++) {
            if (json_funcs[i](cmd,args,jsonBuffer)) {
               return true;
            }
        }
        return false;
     });

}


    
