
#ifndef EEPROM_AES_STR_H
#define EEPROM_AES_STR_H

//#define EEPROM_AES_DEBUG

#ifdef ESP8266 
#include <AESLib.h>
#else
#include <AES.h>
#endif

#include <EEPROM.h>
#include <ArduinoJson.h>


extern void printf_begin();

#ifdef ESP8266 
#define EEPROM_SIZE 4080
#else
#define EEPROM_SIZE 128
#endif

extern AES aes ;

extern byte EEPROM_key [32];

// decrypt EEPROM storage as a string and return in a char * (uses malloc)
// repeatedly calling this destructively reuses the prior value (ie only one can exit at a time)
extern const char *EEPROM_get_str ();
// after calling EEPROM_get_str(), the string will be retained and accessible as EEPROM_get_malloc_last 
extern char EEPROM_get_str_default[EEPROM_SIZE];

//decrypt EEPROM storage into a buffer
extern int EEPROM_load_str (char *output_buffer, int output_buffer_size);

// encrypt and store a string into EEPROM
extern void EEPROM_set_str(const char * str);

// replace the default EEPROM_key with a new key
// must supply a hex encoded 64 byte string eg "044B57F7858743B4281CF08408138CB647BF386D0F442B91325246FE92F0588C"
extern bool EEPROM_setKey (const char * hex);

// replace the default EEPROM_key with a new key
// manipulates the key using a numeric PIN which can be used to add human supplied entropy
extern bool EEPROM_setKeyWithPin (const char *hex, unsigned long PIN) ;

// replace the default EEPROM_key by merging two hex strings into one
// must supply 2 x 32 byte hex encoded strings
// eg "ABCD", "1234" ---> "A1B2C3D4"
// primarily used to spread a key across two devices 
extern bool EEPROM_setSplitKey (const char * hex1, const char *hex2) ;

// replace the default EEPROM_key by merging two hex strings into one
// manipulates the key using a numeric PIN which can be used to add human supplied entropy
extern bool EEPROM_setSplitKeyWithPin (const char * hex1, const char *hex2, unsigned long PIN) ;


extern void EEPROM_set_json (const char * key, const char *value ) ;

extern void EEPROM_set_json_int (const char * key, int value ) ;

extern void EEPROM_set_json_array_char (const char * key, int index, const char *value ) ;

extern void EEPROM_set_json_array_element_char (const char * key1, int index, const char * key2, const char *value );


// read a top level string from the EEPROM json object
// eg assuming json contains '{"ssid" :"myssid", "psk" : "open sesame"}'
// EEPROM_get_char("ssid") - returns a char * to "myssid" 
extern const char *EEPROM_get_json (const char * key) ;
extern int EEPROM_get_json_int (const char * key) ;
extern int EEPROM_get_json_increment (const char * key, int incr) ;



// read a second teir string from the EEPROM json object
// eg assuming json contains '{"wifi" :  { "ssid" :"myssid", "psk" : "open sesame"} }'
// EEPROM_get_char_2deep("wifi","ssid") - returns a char * to "myssid" 
extern const char *EEPROM_get_json_2deep (const char * key1,const char * key2);

extern const char *EEPROM_get_array_char (const char * key,int index);
extern const char *EEPROM_get_array_element_char (const char * key1,int index,const char * key2) ;

extern const char *EEPROM_local_key (char *buf) ; 
const char *EEPROM_new_local_key (char *buf);

extern bool jsonFrame(
    int size,
    const char *json,
    bool (*callback) (JsonObject &,DynamicJsonDocument &) 

);

extern bool execJsonCmd(char*json, int buf_size);

#define JSON_QUOTE(...) #__VA_ARGS__


#define JSON_CMD(MyCmd) [] (const char *cmd,JsonObject &args,DynamicJsonDocument &jsonBuffer) -> bool {if (strcmp(cmd,#MyCmd )==0) {
#define JSON_CMD_END(...) return true;} return false;}

extern bool (*json_funcs[])(const char *,JsonObject &,DynamicJsonDocument &);
#define JSON_CMDS(...) bool (*json_funcs[])(const char *,JsonObject &,DynamicJsonDocument &) = 
#define JSON_CMDS_END(...) [](const char *cmd,JsonObject &args,DynamicJsonDocument &jsonBuffer) -> bool { return true; } 
    

#endif
