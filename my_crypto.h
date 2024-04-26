#include <crypto/hash.h>
#define SHA_256 "sha256"
#define SHA256_DIGEST_SIZE 33

static struct shash_desc shash;


static int calc_hash(struct crypto_shash *alg, const unsigned char *data, unsigned int datalen, unsigned char *digest){
	int ret;
	shash.tfm = alg;
	ret = crypto_shash_digest(&shash, data, datalen, digest);
	return ret;
}
void hash_to_string(const unsigned char *hash, char *output) {
    int i;
    for (i = 0; i < 33; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[32 * 2+1] = '\0';
}
static int do_sha256(const unsigned char *data, unsigned char *out_digest, size_t datalen){
	printk("into do_sha256");
    struct crypto_shash *alg;
    char *hash_alg_name = SHA_256;
    

	/*Allocate a cipher handle for a message digest. 
	The returned struct crypto_shash is the cipher 
	handle required for any subsequent API invocation
	 for that message digest.*/
    alg = crypto_alloc_shash(hash_alg_name, 0, 0);
    printk("fin qui tutto bene");
    if(IS_ERR(alg)){
        pr_info("can't alloc alg %s\n", hash_alg_name);
        return PTR_ERR(alg);
    }
    calc_hash(alg, data, datalen, out_digest);

    // Very dirty print of 8 first bytes for comparaison with sha256sum
    printk(KERN_INFO "HASH(%s, %i): %02x%02x%02x%02x%02x%02x%02x%02x\n",
          data, datalen, out_digest[0], out_digest[1], out_digest[2], out_digest[3], out_digest[4], 
          out_digest[5], out_digest[6], out_digest[7]);

    crypto_free_shash(alg);
    return 0;
}
void print_hash(const unsigned char *hash) {
    int i;
    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        printk("%02x", hash[i]);
    }
    printk("\n");
}
