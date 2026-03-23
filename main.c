#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <yara.h>
#include <unistd.h>
#define BUFFER_SIZE 32768
#define red    "\x1b[31m"
#define mag "\x1b[35m"
#define no  "\x1b[0m"
void gen_hash(const char *filename, unsigned char *hash, unsigned int *hash_len) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("File error");
        exit(1);
    }
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        perror("EVP_MD_CTX_new failed");
        fclose(file);
        exit(1);
    }
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        perror("DigestInit failed");
        exit(1);
    }
    unsigned char buffer[BUFFER_SIZE];
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        EVP_DigestUpdate(mdctx, buffer, bytesRead);
    }
    if (ferror(file)) {
        perror("Read error");
        fclose(file);
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }
    EVP_DigestFinal_ex(mdctx, hash, hash_len);
    EVP_MD_CTX_free(mdctx);
    fclose(file);
}

void hash_to_string(unsigned char *hash, unsigned int len, char *output) {
    for (unsigned int i = 0; i < len; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[len * 2] = '\0';
}

int hash_checker(const char *hash_str) {
   const char *bad_hashes[] = {
"615ff3313445a532c4f04866cea2898e28945f0dcebfb7c09d424fd3579f393d",
"d1886b189474b02467ed2845df0938cec9785e99c3d4b04e0b7de3cafbee4182",
"8e07beb854f77e90c174829bd4e01e86779d596710ad161dbc0e02a219d6227f",
"71d94479d58c32d5618ca1e2329d8fa62f930e0612eb108ba3298441c6ba0302",
"fffc0aa05ef975cbf0ce936aff9da63fc3ac05fef7f0260306011338f09d09b1",
"fff8ec58e389bfcec03ca66fe8bee39b849a948174472de91eb160ae35b78365",
"fff82053caa61c62742f955608e1f72cdef875aebb2996ade9f7b59cfdbe105b",
"ffd2f5c2d39b5b8d5d1d2754e91b1e6181384f05f8f7f4ddac07c6c13d9b97cf",
"ffd23c7ace5f6f9e6b9939bd521407694fd7a4c21e9065944130b92a6f0e2720",
"ffc68a370d1ab39ae179dbdf280018431b2c06eb13a39a7f189cba05499709c8",
"ffc53cecf918d28b50d1ea26e77869fe3c40e8455369e79cddb6ca6b285e4361",
"ffc4251071ae031dac799b3c445da328f62a9a6063a7c4bd615e0f67c306471b",
"ffc33a5918e23b96f28353cb5f5b84a5906c39d7fa5843d8d867360738109652",
"ffc10217f903e2b3c90e43c9297ce4829e15506a0d213a1f090afd190fdd7ee5",
"ffbd3e25571494348392f9db5c353560fe433e73f5efdbaf3fa3d8b9cca5c010",
"ffb3a2239bfdd3373db080f2b89dc5064084c0962353054b3e92e53eff33373c",
"ffa685241743e9f829d362231384bb59c66af15998021410811cd52b82724f3f",
"ffa4f084fedb8e0b3657fa1ab27f47cb89a98efc59aa71b6f7ab9661df97afb7",
"ff884b18295b7250a7f0b09d235839cc3c8a3e80355f3d19dbe72965d62796bd",
"ff80274d8832049c0e89290148450bdb38f40cf1a9c65c85685bf197c49656f8",
"ff7abe97e0fc15a834ac5ec241fc5dbb76b5f40a2f7bc973a24f9f1d2c5254d3",
"ff5f8087afeadcf3125f99a2272494f85caf1d6905114a63f10d10794c484b2b",
"ff4dbb67ca25bc5e18bc25bfd9ccfeb56caf1eb625e5db797e9d489456de7777",
"ff406c0d6071899aa7ea34feb8154769895596f0a0b2e680e0f0f9340121a9d2",
"ff3bef23b6823f29c118eb3cc6e93672f6c61f3f863f0018446f238ef4c77e30",
"ff38c4c73fbe1c98624a3dba227f51f7c61d10e75a6e0c3ff36b8926a4edb30e",
"ff268fb324b69cfbf60d93d5f214e0a935fe6dc117f62a91c43b63e297226a87",
"ff24138b6d70fc0ce1142188ac799c743ac0cd16344fc4d515d82fb9fd475f4d",
"ff1102d22747b85d9afd3244c02638ea0a0774d7eb287ba45aa431d0bb79fc6f",
"ff100a7e7784df48b0078687ed9cd32da7a4329e9f7777f47a1e0a6011b18f27",
"feff98e7975442cded06b6196ff97b99f01b9386eb1d8a5a0a846ed89db7b8af",
"fef447b8a74dac02760330fd0c48973391d05014597bab95b01c3424476306d8",
"fef2eb6f39205bb097d7e44f7804fc04616c00a6d0db98e03ef96874244f7083",
"feed9b5bfeca6aac7d6a6bfba370ffacd25c6293ba8053550bb57d3a9c3f3caf",
"feece25968226c60293663e1c1b134ec1aacbd8a3e5c998618cde8a1b995593b",
"fed77d5d6d50cc5d1708cb0956d627e4d778ed375ea31631f53b5924dd8e158f",
"fed408c881008e7394077c415b0f90d5af274585c387af1feb34aabdc574b02f",
"febc6b284c24a2dac67c3286eeed3de1ec5eb63ee0b4bce269659ba5a660ec4d",
"febae7eb78dd08b8ed22f7ee8f8c72c54be12e4e61f95972eb310f0c8bf0051f",
"feae0f8e003e8e2f450160570284537cdb153b94bd50775ff2286da9c8e49375",
"fea31e901389f476014152795ffe55103f575b48845e3a744e3e7be3071605b1",
"fe9af57a6d907d5d693355b397b00a676845ab23a778ab6485ead6a7bb802190",
"fe842fa0501b400284e16e101478c1e33c846145079227aa9c9ad499dbc7158f",
"fe7f47c1447e9d48014ef6c1853b06c94554b2f93185ad5e0a94d2da7086222e"
        ,NULL
    };

    for (int i = 0; bad_hashes[i] != NULL; i++) {
        if (strcmp(hash_str, bad_hashes[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

int filetype_check(const char *filename) {
  
    const char *suspicious_exts[] = {".vbs", ".bat", ".ps1", ".exe",NULL};

    const char *ext = strrchr(filename, '.');  
    if (!ext) return 0; 

    for (int i = 0; suspicious_exts[i] != NULL; i++) {
        if (strcasecmp(ext, suspicious_exts[i]) == 0) {
            return 1;
        }
    }
    return 0;
}
int yara_callback(YR_SCAN_CONTEXT *ctx, int message, void *message_data, void *user_data) {
    int *malicious_flag = (int *)user_data;

    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE *rule = (YR_RULE *)message_data;
        printf("YARA match: %s\n", rule->identifier);
        *malicious_flag = 1;
    }
    return CALLBACK_CONTINUE;
}


int yara_scan(const char *filename, const char *rule_file, int *malicious_flag) {
    YR_COMPILER *compiler = NULL;
    YR_RULES *rules = NULL;

    if (yr_initialize() != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to initialize YARA\n");
        return -1;
    }

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to create YARA compiler\n");
        return -1;
    }

    FILE *fh = fopen(rule_file, "r");
    if (!fh) {
        perror("Rule file error");
        return -1;
    }

    if (yr_compiler_add_file(compiler, fh, NULL, rule_file) != 0) {
        fprintf(stderr, "Error compiling YARA rules\n");
        fclose(fh);
        return -1;
    }
    fclose(fh);

    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to get compiled YARA rules\n");
        return -1;
    }

    int result = yr_rules_scan_file(rules, filename, 0, yara_callback, malicious_flag, 0);

    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    yr_finalize();

    return result;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }
 int malicious = 0;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    gen_hash(argv[1], hash, &hash_len);

    char hash_str[65];
    hash_to_string(hash, hash_len, hash_str);

 printf("Scanning the file");
    for (int i = 0; i < 2; i++) {
        fflush(stdout);
        printf("..");
        fflush(stdout);
        sleep(1);
        fflush(stdout);
    }   
printf("\n");
    for (int i = 0; i < 52; i++) {
                printf("* ");
        }

    printf("\nSHA-256: %s\n", hash_str);
if (filetype_check(argv[1])) {
    printf(red"suspicious file type: %s\n"no, argv[1]);
    malicious = 1;
}

    if (hash_checker(hash_str)) {
        printf(red"Hash: Matched\n"no);
       
        malicious = 1;
    } else {
        printf("Hash: Unmatched\n");
    }
    if (yara_scan(argv[1], "rules.yar", &malicious) == 0) {
        if (malicious) {
             printf(red"Threat: Detected\n"no);
             printf(red"Removing the file.\n"no);
        } else {
          printf("Threat: None\n");
        }
    } else {
        printf(mag"Scan failed.\n"no);
    }
    for (int i = 0; i < 52; i++) {
                printf("* ");
        }printf("\n");
   if (malicious) {
    remove(argv[1]);

}
    return 0;
}
