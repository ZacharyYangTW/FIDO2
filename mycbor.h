/*
 * CBOR
 */
typedef enum
{
    TAG_GEN      = (1 << 0),
    TAG_MC       = (1 << 1),
    TAG_GA       = (1 << 2),
    TAG_CP       = (1 << 3),
    TAG_ERR      = (1 << 4),
    TAG_PARSE    = (1 << 5),
    TAG_CTAP     = (1 << 6),
    TAG_U2F      = (1 << 7),
    TAG_DUMP     = (1 << 8),
    TAG_GREEN    = (1 << 9),
    TAG_RED      = (1 << 10),
    TAG_TIME     = (1 << 11),
    TAG_HID      = (1 << 12),
    TAG_USB      = (1 << 13),
    TAG_WALLET   = (1 << 14),
    TAG_STOR     = (1 << 15),
    TAG_DUMP2    = (1 << 16),
    TAG_BOOT     = (1 << 17),
    TAG_EXT      = (1 << 18),
    TAG_NFC      = (1 << 19),
    TAG_NFC_APDU = (1 << 20),
    TAG_CCID     = (1 << 21),
    TAG_CM       = (1 << 22),

    TAG_NO_TAG   = (1UL << 30),
    TAG_FILENO   = (1UL << 31)
} LOG_TAG;
 static uint32_t LOGMASK = TAG_FILENO;

#define dump_hex1(tag,data,len) LOG_HEX(tag,data,len)

#define CTAPHID_BUFFER_SIZE         7609
#define CTAP_RESPONSE_BUFFER_SIZE   4096

static uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
;


#define CTAP1_ERR_SUCCESS                   0x00
#define CTAP1_ERR_INVALID_COMMAND           0x01
#define CTAP2_ERR_PIN_BLOCKED               0x32
#define CTAP2_ERR_PIN_AUTH_BLOCKED          0x34


void test_cbor(int argc, char **argv);

