/* subst.c - Standard substitution cipher.
 * Copyright 2010 Raymond Martineau
 */

#include <string.h>
 
/*
 * char *subst_encode(const char *plaintext, const char *key)
 * Encodes a plaintext string based on the key.  Returns a pointer to 
 * the encoded string.
 * plaintext: A null-terminated input string. 
 * key: A string of 26 characters.  The first character represents the 
 *   substitution for 'A', the next for 'B', and so on. All characters
 *   in this string should be capitalized. 
 * Return value: The newly allocated string, in encrypted form.
 */
char *subst_encode(const char *plaintext, const char *key)
{
    char *encodetext;
    int i;
    /* Sanity check */
    if (plaintext==NULL || key==NULL || strlen(key)<26)
      return NULL;
      
    encodetext=malloc(strlen(plaintext)+1);
    
    for (i=0; plaintext[i]!='\0'; ++i)
    {
        encodetext[i]=plaintext[i];
        if (encodetext[i]>='A' && encodetext[i]<='Z')
        {
            encodetext[i]=key[plaintext[i]-'A'];
        }
        if (encodetext[i]>='a' && encodetext[i]<='z')
        {
            encodetext[i]=key[plaintext[i]-'a'];
        }
    }
    
    encodetext[i]='\0';
    
    return encodetext;
}

/*
 * char *subst_encode(const char *plaintext, const char *key)
 * Encodes a plaintext string based on the key.  Returns a pointer to 
 * the encoded string.
 * plaintext: A null-terminated input string. 
 * key: A string of 26 characters.  The first character represents the 
 *   substitution for 'A', the next for 'B', and so on. All characters
 *   in this string should be capitalized. Missing letters in the
 *   key are replaced by a question mark. 
 * Return value: The newly allocated string, in encrypted form.
 */
char *subst_decode(const char *encodetext, const char *key)
{
    char *plaintext;
    int i;
    char invkey[26];
    /* Sanity check */
    if (plaintext==NULL || key==NULL || strlen(key)<26)
      return NULL;
      
    plaintext=malloc(strlen(encodetext)+1);
    
    for (i=0; i<26; ++i)
    {
        invkey[i]='?';
    }

    for (i=0; i<26; ++i)
    {
        if (key[i]>='A' && key[i]<='Z')
            invkey[key[i]-'A']='A'+i;
        if (key[i]>='a' && key[i]<='z')
            invkey[key[i]-'a']='a'+i;
    }
    
    for (i=0; encodetext[i]!='\0'; ++i)
    {
        plaintext[i]=encodetext[i];
        if (encodetext[i]>='A' && plaintext[i]<='Z')
        {
            plaintext[i]=invkey[encodetext[i]-'A'];
        }
        if (plaintext[i]>='a' && plaintext[i]<='z')
        {
            plaintext[i]=invkey[encodetext[i]-'a'];
        }
    }
    plaintext[i]='\0';
    
    return plaintext;
}

#if 0
int main (void)
{
    char *a, *b;
    
    a = subst_encode("The quick brown fox.", "BCDEFGHIJKLMNOPQRSTUVWXYZA");
    printf ("%s\n", a);
    b = subst_decode(a, "BCDEFGHIJKLMNOPQRSTUVWXYZA");
    
    printf ("%s\n", b);
    return 0;
}
#endif