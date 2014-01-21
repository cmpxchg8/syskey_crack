#define SYSTEM_KEY_LEN   16
 
#define QWERTY "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%"
#define DIGITS "0123456789012345678901234567890123456789"

#define SAM_KEY_LEN      16
#define SAM_SALT_LEN     16
#define SAM_CHECKSUM_LEN 16

typedef struct _SAM_KEY_DATA {
  uint32_t Revision;
  uint32_t Length;
  uint8_t Salt[SAM_SALT_LEN];
  uint8_t Key[SAM_KEY_LEN];
  uint8_t CheckSum[SAM_CHECKSUM_LEN];
  uint32_t Reserved[2];
} SAM_KEY_DATA, *PSAM_KEY_DATA;

typedef enum _DOMAIN_SERVER_ENABLE_STATE {
  DomainServerEnabled = 1,
  DomainServerDisabled
} DOMAIN_SERVER_ENABLE_STATE, *PDOMAIN_SERVER_ENABLE_STATE;

typedef enum _DOMAIN_SERVER_ROLE {
  DomainServerRoleBackup  = 2,
  DomainServerRolePrimary = 3
} DOMAIN_SERVER_ROLE, *PDOMAIN_SERVER_ROLE;

typedef struct _OLD_LARGE_INTEGER {
  unsigned long LowPart;
  long HighPart;
} OLD_LARGE_INTEGER, *POLD_LARGE_INTEGER;

#pragma pack(4)
typedef struct _DOMAIN_ACCOUNT_F {
  uint32_t Revision;
  uint32_t unknown1;
  
  OLD_LARGE_INTEGER CreationTime;
  OLD_LARGE_INTEGER DomainModifiedCount;
  OLD_LARGE_INTEGER MaxPasswordAge;
  OLD_LARGE_INTEGER MinPasswordAge;
  OLD_LARGE_INTEGER ForceLogoff;
  OLD_LARGE_INTEGER LockoutDuration;
  OLD_LARGE_INTEGER LockoutObservationWindow;
  OLD_LARGE_INTEGER ModifiedCountAtLastPromotion;
  
  uint32_t NextRid;
  uint32_t PasswordProperties;
  uint16_t MinPasswordLength;
  uint16_t PasswordHistoryLength;
  uint16_t LockoutThreshold;
  uint16_t unknown2;
  
  DOMAIN_SERVER_ENABLE_STATE ServerState;
  DOMAIN_SERVER_ROLE ServerRole;
  
  uint8_t UasCompatibilityRequired;
  uint32_t unknown3[2]; 
  
  SAM_KEY_DATA keys[2];
  uint32_t unknown4;
} DOMAIN_ACCOUNT_F, *PDOMAIN_ACCOUNT_F;
#pragma pack()

NTSTATUS DecryptSamKey(PSAM_KEY_DATA key_data, uint8_t syskey[]) {
  MD5_CTX ctx;
  RC4_KEY key;
  uint8_t dgst[MD5_DIGEST_LEN];
  
  // create key with salt and decrypt data
  MD5_Init(&ctx);
  MD5_Update(&ctx, key_data->Salt, SAM_SALT_LEN);
  MD5_Update(&ctx, QWERTY, strlen(QWERTY) + 1);
  MD5_Update(&ctx, syskey, SYSTEM_KEY_LEN);
  MD5_Update(&ctx, DIGITS, strlen(DIGITS) + 1);
  MD5_Final(dgst, &ctx);
  
  RC4_set_key(&key, MD5_DIGEST_LEN, dgst);
  RC4(&key, SAM_CHECKSUM_LEN + SAM_KEY_LEN, 
      key_data->Key, key_data->Key);
  
  // verify decryption was successful by generating checksum
  MD5_Init(&ctx);
  MD5_Update(&ctx, key_data->Key, SAM_KEY_LEN);
  MD5_Update(&ctx, DIGITS, strlen(DIGITS) + 1);
  MD5_Update(&ctx, key_data->Key, SAM_KEY_LEN);
  MD5_Update(&ctx, QWERTY, strlen(QWERTY) + 1);
  MD5_Final(dgst, &ctx);
  
  // compare with checksum and return status
  if (memcmp(dgst, key_data->CheckSum, SAM_CHECKSUM_LEN) == 0) {
    return STATUS_SUCCESS;
  }
  return STATUS_WRONG_PASSWORD;
}
