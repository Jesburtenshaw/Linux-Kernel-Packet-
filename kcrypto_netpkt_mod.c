#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/byteorder/generic.h>
#include <crypto/aes.h>
#include <linux/crypto.h>
#include <crypto/skcipher.h>

#define KCN_KEY_SIZE 32
#define KCN_IV_SIZE 16
#define KCN_BLOCK_SIZE 16
#define CIPHER_ALG "cbc-aes-aesni"
//"cbc-aes-aesni" or "aes-generic", "aes"

static struct nf_hook_ops *kcrypto_netpkt_in_ops = NULL;
static struct nf_hook_ops *kcrypto_netpkt_out_ops = NULL;

unsigned char kcn_key[KCN_KEY_SIZE] = {0xA1, 0xA2, 0xA3, 0xA4,
                              0xB1, 0xB2, 0xB3, 0xB4,  
                              0xC1, 0xC2, 0xC3, 0xC4,  
                              0xD1, 0xD2, 0xD3, 0xD4,  
                              0x1A, 0x2A, 0x3A, 0x4A,
                              0x1B, 0x2B, 0x3B, 0x4B,  
                              0x1C, 0x2C, 0x3C, 0x4C,  
                              0x1D, 0x2D, 0x3D, 0x4D,  
                            };

unsigned char kcn_iv[KCN_IV_SIZE] = { 0xE5, 0xE6, 0xE7, 0xE8,
                              0xF5, 0xF6, 0xF7, 0xF8,
                              0x5E, 0x6E, 0x7E, 0x8E,  
                              0x5F, 0x6F, 0x7F, 0x8F
                            };

struct kcn_result_t {
    struct completion completion;
    int err;
};

/* Tie all data structures together */
struct kcn_skcipher_t {
    struct scatterlist sg;
    struct crypto_skcipher *skcipher;
    struct skcipher_request *req;
    struct kcn_result_t result;
};

struct kcn_skcipher_t kcnEnc, kcnDec;

/* Callback function */
static void kcrypto_netpkt_skcipher_cb(struct crypto_async_request *req, int error)
{
    struct kcn_result_t *result = req->data;

    if (error == -EINPROGRESS)
        return;

    result->err = error;

    complete(&result->completion);

    pr_info("kcrypto_netpkt_skcipher_cb:Encryption finished successfully\n");
}

static void kcrypto_netpkt_ciphers_init(struct kcn_skcipher_t *skc) {

    skc->skcipher = crypto_alloc_skcipher(CIPHER_ALG, 0, 0);
    if (IS_ERR(skc->skcipher)) {
        pr_err("kcrypto_netpkt_ciphers_init:Could not allocate skcipher handle\n");
        return;
    } else {
        pr_info("kcrypto_netpkt_ciphers_init:Allocated skcipher handle\n");
    }

    skc->req = skcipher_request_alloc(skc->skcipher, GFP_KERNEL);
    if (!skc->req) {
        pr_err("kcrypto_netpkt_ciphers_init: Could not allocate skcipher request\n");
        /* error -ENOMEM */
        goto ExitDoor;
    } else {
        pr_info("kcrypto_netpkt_ciphers_init:Allocated skcipher request\n");
    }

    skcipher_request_set_callback(skc->req, CRYPTO_TFM_REQ_MAY_BACKLOG, kcrypto_netpkt_skcipher_cb, &skc->result);
    pr_info("kcrypto_netpkt_ciphers_init:Set the skcipher callback\n");

    if (crypto_skcipher_setkey(skc->skcipher, kcn_key, KCN_KEY_SIZE)) {
        pr_err("kcrypto_netpkt_ciphers_init: Key could not be set\n");
        /* error -EAGAIN */
        goto ExitDoor;
    } else {
        pr_info("kcrypto_netpkt_ciphers_init:Set the skcipher key\n");
    }


    ExitDoor:
        return;
}

static void kcrypto_netpkt_init_all(void) {

    if (!crypto_has_skcipher(CIPHER_ALG, 0, 0)) {
        pr_err("kcrypto_netpkt_ciphers_init:skcipher %s not found\n", CIPHER_ALG);
        /* error -EINVAL */
        return;
    } else {
        pr_info("kcrypto_netpkt_ciphers_init:skcipher %s found\n", CIPHER_ALG);
    }

    kcrypto_netpkt_ciphers_init(&kcnEnc);
    kcrypto_netpkt_ciphers_init(&kcnDec);

}

static void kcrypto_netpkt_cleanup(void) {

    /* kcnEnc */
    if (kcnEnc.skcipher)
        crypto_free_skcipher(kcnEnc.skcipher);

    if (kcnEnc.req)
        skcipher_request_free(kcnEnc.req);

    /* kcnDec */
    if (kcnDec.skcipher)
        crypto_free_skcipher(kcnDec.skcipher);

    if (kcnDec.req)
        skcipher_request_free(kcnDec.req);


}

void kcrypto_netpkt_encrypt_block(char *plaintext, size_t blkSz, char *ciphertext) {

    /* Encrypt the packet now */
    sg_init_one(&kcnEnc.sg, plaintext, blkSz);
    skcipher_request_set_crypt(kcnEnc.req, &kcnEnc.sg, &kcnEnc.sg, blkSz, kcn_iv);
    crypto_skcipher_encrypt(kcnEnc.req);
    sg_copy_to_buffer(&kcnEnc.sg, 1, ciphertext, blkSz);

}

void kcrypto_netpkt_encrypt_data(char *plaintext, size_t pdataSz, char *ciphertext) {
    int i;

    for (i = 0;i < pdataSz; i += KCN_BLOCK_SIZE) {
        kcrypto_netpkt_encrypt_block(plaintext + i, KCN_BLOCK_SIZE, ciphertext + i);
    }

    //TBD: handle padding
}

void kcrypto_netpkt_decrypt_block(char *ciphertext, size_t blkSz, char *plaintext) {

    /* Decrypt the packet now */
    sg_init_one(&kcnDec.sg, ciphertext, blkSz);
    skcipher_request_set_crypt(kcnDec.req, &kcnDec.sg, &kcnDec.sg, blkSz, kcn_iv);
    crypto_skcipher_decrypt(kcnDec.req);
    sg_copy_to_buffer(&kcnDec.sg, 1, plaintext, blkSz);

}

void kcrypto_netpkt_decrypt_data(char *ciphertext, size_t cdataSz, char *plaintext) {
    int i;

    for (i = 0;i < cdataSz; i += KCN_BLOCK_SIZE) {
        kcrypto_netpkt_decrypt_block(ciphertext + i, KCN_BLOCK_SIZE, plaintext + i);
    }

    //TBD: handle padding
}

/* Handles outgoing packets */
static unsigned int kcrypto_netpkt_encrypt_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    char *plaintext, *ciphertext;
    size_t dataLen;

    if(skb==NULL) {
        return NF_ACCEPT;
    }

    iph = ip_hdr(skb);

    if(iph && iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = tcp_hdr(skb);

        pr_info("kcrypto_netpkt_encrypt_handler:: source : %pI4:%hu | dest : %pI4:%hu | seq : %u | ack_seq : %u | window : %hu | csum : 0x%hx | urg_ptr %hu\n", &(iph->saddr),ntohs(tcph->source),&(iph->saddr),ntohs(tcph->dest), ntohl(tcph->seq), ntohl(tcph->ack_seq), ntohs(tcph->window), ntohs(tcph->check), ntohs(tcph->urg_ptr));

        /* Encrypt the outgoing data */
        plaintext = (char *)tcph; //TBD: Get proper offset of data in tcph
        //TBD: Init dataLen, ciphertext
        kcrypto_netpkt_encrypt_data(plaintext, dataLen, ciphertext);
    }


    return NF_ACCEPT;
}

/* Handles incoming packets */
static unsigned int kcrypto_netpkt_decrypt_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    char *plaintext, *ciphertext;
    size_t dataLen;

    if(skb==NULL) {
        return NF_ACCEPT;
    }

    iph = ip_hdr(skb);

    if(iph && iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = tcp_hdr(skb);

        pr_info("kcrypto_netpkt_decrypt_handler:: source : %pI4:%hu | dest : %pI4:%hu | seq : %u | ack_seq : %u | window : %hu | csum : 0x%hx | urg_ptr %hu\n", &(iph->saddr),ntohs(tcph->source),&(iph->saddr),ntohs(tcph->dest), ntohl(tcph->seq), ntohl(tcph->ack_seq), ntohs(tcph->window), ntohs(tcph->check), ntohs(tcph->urg_ptr));

        /* Decrypt the incoming data */
        ciphertext = (char *)tcph; //TBD: Get proper offset of data in tcph
        //TBD: Init dataLen, plaintext 
        kcrypto_netpkt_decrypt_data(ciphertext, dataLen, plaintext);
    }


    return NF_ACCEPT;
}

static int __init kcrypto_netpkt_init(void) {

    kcrypto_netpkt_init_all();

    kcrypto_netpkt_in_ops = (struct nf_hook_ops *)kcalloc(1,  sizeof(struct nf_hook_ops), GFP_KERNEL);

    if(kcrypto_netpkt_in_ops!=NULL) {
        kcrypto_netpkt_in_ops->hook = (nf_hookfn *)kcrypto_netpkt_decrypt_handler;
        kcrypto_netpkt_in_ops->hooknum = NF_INET_LOCAL_IN;
        kcrypto_netpkt_in_ops->pf = NFPROTO_IPV4;
        kcrypto_netpkt_in_ops->priority = NF_IP_PRI_FIRST;

        nf_register_net_hook(&init_net, kcrypto_netpkt_in_ops);
    }

    kcrypto_netpkt_out_ops = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

    if(kcrypto_netpkt_out_ops!=NULL) {
        kcrypto_netpkt_out_ops->hook = (nf_hookfn *)kcrypto_netpkt_encrypt_handler;
        kcrypto_netpkt_out_ops->hooknum = NF_INET_LOCAL_OUT;
        kcrypto_netpkt_out_ops->pf = NFPROTO_IPV4;
        kcrypto_netpkt_out_ops->priority = NF_IP_PRI_FIRST;

        nf_register_net_hook(&init_net, kcrypto_netpkt_out_ops);
    }

    return 0;
}

static void __exit kcrypto_netpkt_exit(void) {

    kcrypto_netpkt_cleanup();

    if(kcrypto_netpkt_in_ops != NULL) {
        nf_unregister_net_hook(&init_net, kcrypto_netpkt_in_ops);
        kfree(kcrypto_netpkt_in_ops);
    }

    if(kcrypto_netpkt_out_ops != NULL) {
        nf_unregister_net_hook(&init_net, kcrypto_netpkt_out_ops);
        kfree(kcrypto_netpkt_out_ops);
    }
}

module_init(kcrypto_netpkt_init);
module_exit(kcrypto_netpkt_exit);

MODULE_LICENSE("GPL");
