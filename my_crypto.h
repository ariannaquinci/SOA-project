#include <crypto/hash.h>
#define SHA_256 "sha256"
#define SHA256_DIGEST_SIZE 32

static struct shash_desc shash;


static int calc_hash(struct crypto_shash *alg, const unsigned char *data, unsigned int datalen, unsigned char *digest){
	int ret;
	shash.tfm = alg;
	ret = crypto_shash_digest(&shash, data, datalen, digest);
	return ret;
}
void hash_to_string(const unsigned char *hash, char *output) {
    int i;
    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[32 * 2+1] = '\0';
}
static int do_sha256(const unsigned char *data, unsigned char *out_digest, size_t datalen){
	
    struct crypto_shash *alg;
    char *hash_alg_name = SHA_256;
    

	/*Allocate a cipher handle for a message digest. 
	The returned struct crypto_shash is the cipher 
	handle required for any subsequent API invocation
	 for that message digest.*/
    alg = crypto_alloc_shash(hash_alg_name, 0, 0);
 
    if(IS_ERR(alg)){
        pr_info("can't alloc alg %s\n", hash_alg_name);
        return PTR_ERR(alg);
    }
    calc_hash(alg, data, datalen, out_digest);

   
    /*printk(KERN_INFO "HASH(%s, %i): %02x%02x%02x%02x%02x%02x%02x%02x\0\n",
          data, datalen, out_digest[0], out_digest[1], out_digest[2], out_digest[3], out_digest[4], 
          out_digest[5], out_digest[6], out_digest[7]);*/

    crypto_free_shash(alg);
    return 0;
}


static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_encode(const unsigned char *input, char *output, int len) {
    int i = 0, j = 0;
    unsigned char char_array_3[3], char_array_4[4];

    while (len--) {
        char_array_3[i++] = *(input++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++) {
                output[j++] = base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i) {
    int k ;
        for (k= i; k < 3; k++) {
            char_array_3[k] = '\0';
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (k= 0; (k < i + 1); k++) {
            output[j++] = base64_chars[char_array_4[k]];
        }

        while ((i++ < 3)) {
            output[j++] = '=';
        }
    }

    output[j] = '\0';

    return j;
}

void print_hash(const unsigned char *hash) {
    int i;
    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        printk("%02x", hash[i]);
    }
    printk("\n");
}
