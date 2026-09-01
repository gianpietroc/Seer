import os

output_dir = "fuzzer_priority_queue_complex"
os.makedirs(output_dir, exist_ok=True)

files = {
    # ==============================================================================
    # 1. PARSER HTTP (State Machine Vulnerability - CWE-119 / CWE-193)
    # ==============================================================================
    "real_01_http_parser.c": r"""
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MAX_HEADERS 10
#define MAX_HEADER_LEN 64

typedef enum { STATE_METHOD, STATE_PATH, STATE_VERSION, STATE_HEADERS, STATE_BODY, STATE_DONE } State;

typedef struct {
    char method[16]; char path[128];
    char headers[MAX_HEADERS][MAX_HEADER_LEN];
    int header_count; State state;
} HttpRequest;

void parse_http(char *input, int len) {
    HttpRequest req; memset(&req, 0, sizeof(req)); req.state = STATE_METHOD;
    int i = 0, token_start = 0;
    
    for (i = 0; i < len; i++) {
        char c = input[i];
        switch (req.state) {
            case STATE_METHOD:
                if (c == ' ') {
                    int tlen = i - token_start;
                    if (tlen < 16) { memcpy(req.method, input + token_start, tlen); req.method[tlen] = '\0'; req.state = STATE_PATH; token_start = i + 1; }
                    else return;
                }
                break;
            case STATE_PATH:
                if (c == ' ') {
                    int tlen = i - token_start; // BUG: Overflow over req.path if tlen > 128
                    memcpy(req.path, input + token_start, tlen); req.path[tlen] = '\0';
                    req.state = STATE_VERSION; token_start = i + 1;
                }
                break;
            case STATE_VERSION:
                if (c == '\n') { req.state = STATE_HEADERS; token_start = i + 1; } break;
            case STATE_HEADERS:
                if (c == '\n') {
                    if (i - token_start <= 1) req.state = STATE_BODY;
                    else if (req.header_count < MAX_HEADERS) {
                        int hlen = i - token_start;
                        if (hlen >= MAX_HEADER_LEN) hlen = MAX_HEADER_LEN;
                        strncpy(req.headers[req.header_count], input + token_start, hlen); // BUG: Missing \0 if hlen == 64
                        req.header_count++;
                    }
                    token_start = i + 1;
                }
                break;
            case STATE_BODY:
                if (req.header_count > 0) { volatile int x = strlen(req.headers[req.header_count - 1]); } // CRASH
                req.state = STATE_DONE; return;
        }
    }
}
""",

    # ==============================================================================
    # 2. RLE IMAGE DECODER (Integer Overflow -> Heap Overflow - CWE-190 / CWE-122)
    # ==============================================================================
    "real_02_rle_decoder.c": r"""
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct { uint16_t magic; uint16_t width; uint16_t height; uint8_t channels; } ImgHeader;

void decode_image(uint8_t *data, size_t size) {
    if (size < sizeof(ImgHeader)) return;
    ImgHeader *hdr = (ImgHeader*)data;
    if (hdr->magic != 0x494D) return;
    
    // BUG: Integer Overflow (e.g. 65535 * 65535 * 3 wraps to small number)
    uint32_t raw_size = hdr->width * hdr->height * hdr->channels;
    uint8_t *pixels = (uint8_t*)malloc(raw_size);
    if (!pixels) return;
    
    size_t in_pos = sizeof(ImgHeader), out_pos = 0;
    while (in_pos < size && out_pos < raw_size) {
        uint8_t count = data[in_pos++]; uint8_t value = data[in_pos++];
        for (int i = 0; i < count; i++) {
            if (out_pos >= raw_size) break; 
            pixels[out_pos++] = value; // Heap Overflow if raw_size was wrapped
        }
    }
    free(pixels);
}
""",

    # ==============================================================================
    # 3. BYTECODE VM (Division by Zero / Out-of-bounds Read - CWE-369 / CWE-125)
    # ==============================================================================
    "real_03_bytecode_vm.c": r"""
#include <stdint.h>
#include <stdlib.h>

#define STACK_SIZE 16

void run_vm(uint8_t *code, size_t len) {
    int stack[STACK_SIZE]; int sp = 0; size_t ip = 0;
    while (ip < len) {
        uint8_t op = code[ip++];
        switch (op) {
            case 0x01: // PUSH
                if (ip >= len) return;
                if (sp < STACK_SIZE) stack[sp++] = code[ip++];
                break;
            case 0x02: // POP
                if (sp > 0) sp--; else return;
                break;
            case 0x04: // DIV
                if (sp >= 2) {
                    int a = stack[--sp]; int b = stack[--sp];
                    if (a == 0) { volatile int crash = 100 / a; } // BUG: Div by Zero
                    stack[sp++] = b / a;
                }
                break;
            case 0xFF: // SECRET
                if (sp < STACK_SIZE) { volatile int secret = stack[sp + 1000]; } // BUG: OOB Read
                break;
        }
    }
}
""",

    # ==============================================================================
    # 4. JSON MINI-PARSER (Memory Leak & Double Free - CWE-401 / CWE-415)
    # ==============================================================================
    "real_04_json_parser.c": r"""
#include <stdlib.h>
#include <string.h>

typedef struct JsonNode { char *key; char *value; struct JsonNode *next; } JsonNode;

void parse_json(char *input, int len) {
    if (len < 10 || input[0] != '{' || input[len-1] != '}') return;
    JsonNode *head = NULL;
    char *ptr = input + 1;
    
    while (*ptr && ptr < input + len - 1) {
        if (*ptr == '"') {
            ptr++; char *key_start = ptr;
            while (*ptr && *ptr != '"') ptr++;
            if (!*ptr) break;
            *ptr = '\0'; ptr++;
            
            if (*ptr == ':') {
                ptr++;
                if (*ptr == '"') {
                    ptr++; char *val_start = ptr;
                    while (*ptr && *ptr != '"') ptr++;
                    if (!*ptr) break;
                    *ptr = '\0'; ptr++;
                    
                    JsonNode *node = (JsonNode*)malloc(sizeof(JsonNode));
                    node->key = strdup(key_start);
                    node->value = strdup(val_start);
                    node->next = head; head = node;
                    
                    if (strcmp(node->key, "admin_override") == 0) {
                        free(node->value);
                        }
                }
            }
        }
        ptr++;
    }
    
    // Cleanup
    JsonNode *curr = head;
    while (curr) {
        JsonNode *next = curr->next;
        free(curr->key);
        free(curr->value); // CRASH: Double free
        free(curr);
        curr = next;
    }
}
""",

    # ==============================================================================
    # 5. CUSTOM BASE64 DECODER (Out-of-Bounds Write - CWE-787)
    # ==============================================================================
    "real_05_base64_decoder.c": r"""
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int decode_b64(char *input, int len) {
    if (len % 4 != 0 || len == 0) return 0;
    int out_len = (len / 4) * 3;
    
    if (input[len-1] == '=') out_len--;
    if (input[len-2] == '=') out_len--; 

    uint8_t *out = (uint8_t*)malloc(out_len);
    if (!out) return 0;
    
    int i = 0, j = 0;
    while (i < len) {
        uint32_t val = (input[i] << 18) | (input[i+1] << 12) | (input[i+2] << 6) | input[i+3];
        
        out[j++] = (val >> 16) & 0xFF;
        out[j++] = (val >> 8) & 0xFF; 
        out[j++] = val & 0xFF;
        i += 4;
    }
    free(out);
    return 1;
}
""",

    # ==============================================================================
    # 6. COMPRESSED NETWORK PACKET (Type Confusion & Bad Cast - CWE-843)
    # ==============================================================================
    "real_06_tlv_packet.c": r"""
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define TYPE_AUTH 0x01
#define TYPE_DATA 0x02

void handle_packet(uint8_t *data, size_t size) {
    if (size < 4) return;
    uint8_t type = data[0];
    uint16_t len = (data[1] << 8) | data[2];
    
    if (size < 3 + len) return;
    
    if (type == TYPE_AUTH) {
        if (len != 8) return;
        uint64_t *token = (uint64_t*)(data + 3);
        if (*token == 0xDEADBEEFCAFEBABE) {
            // success
        }
    } else if (type == TYPE_DATA) {
        // Data processing
        uint8_t *payload = data + 3;
        if (payload[0] == 0xFF) {
            void (*func_ptr)() = (void (*)())payload;
            func_ptr(); 
        }
    }
}
""",

    # ==============================================================================
    # 7. ARCHIVE EXTRACTOR (Path Traversal to Write-What-Where - CWE-22 / CWE-20)
    # ==============================================================================
    "real_07_archive_extractor.c": r"""
#include <string.h>
#include <stdlib.h>

void extract_file(char *archive_data, int size) {
    if (size < 6) return;
    
    int pos = 0;
    while (pos < size) {
        uint8_t name_len = archive_data[pos++];
        if (pos + name_len >= size) return;
        
        char filename[256] = {0};
        memcpy(filename, archive_data + pos, name_len);
        pos += name_len;
        
        if (pos + 4 >= size) return;
        uint32_t file_size = *(uint32_t*)(archive_data + pos);
        pos += 4;
        
        if (pos + file_size > size) return;
        uint8_t *file_data = archive_data + pos;
        
        if (strstr(filename, "../../") != NULL) {
            if (strcmp(filename, "../../etc/shadow") == 0) {
                 volatile int *crash = NULL; *crash = 0xBAD;
            }
        }
        pos += file_size;
    }
}
""",

    # ==============================================================================
    # 8. DNS RESPONSE PARSER (Pointer Loop / Stack Exhaustion - CWE-674)
    # ==============================================================================
    "real_08_dns_parser.c": r"""
#include <stdint.h>

void read_dns_name(uint8_t *buffer, int size, int offset, int depth) {
    if (depth > 20) return; 
    
    while (offset < size) {
        uint8_t len = buffer[offset];
        if (len == 0) return; // End of name
        
        if ((len & 0xC0) == 0xC0) {
            // Pointer (DNS compression)
            if (offset + 1 >= size) return;
            int new_offset = ((len & 0x3F) << 8) | buffer[offset + 1];
            read_dns_name(buffer, size, new_offset, depth + 1);
            return;
        } else {
            offset += len + 1;
        }
    }
}

void parse_dns(uint8_t *data, int size) {
    if (size < 12) return; // Header size
    read_dns_name(data, size, 12, 0);
}
""",

    # ==============================================================================
    # 9. CRYPTO KEY EXCHANGER (Logic bypass & Uninitialized Use - CWE-457)
    # ==============================================================================
    "real_09_crypto_exchange.c": r"""
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    int state;
    uint32_t session_key;
} Session;

void process_crypto(uint8_t *cmds, int len) {
    Session s;
    s.state = 0; // 0=INIT, 1=HELLO, 2=KEY_EXCHANGED
    
    for (int i=0; i<len; i++) {
        uint8_t cmd = cmds[i];
        if (cmd == 0x10) { s.state = 1; } // HELLO
        else if (cmd == 0x20 && s.state == 1) { 
            if (i+4 < len) {
                s.session_key = *(uint32_t*)(cmds + i + 1);
                s.state = 2;
                i += 4;
            }
        }
        else if (cmd == 0x30) {
            if (s.state != 2) {
                if (s.session_key == 0xDEADBEEF) {
                    char *ptr = 0; *ptr = 1;
                }
            }
        }
    }
}
""",

    # ==============================================================================
    # 10. MULTI-THREADED JOB QUEUE (Simulated Race Condition / Use After Free - CWE-362)
    # ==============================================================================
    "real_10_job_queue.c": r"""
#include <stdlib.h>

typedef struct Job {
    int id;
    char *data;
} Job;

Job *current_job = NULL;

void process_jobs(uint8_t *actions, int len) {
    for (int i=0; i<len; i++) {
        uint8_t action = actions[i];
        
        if (action == 1) { // ALLOC
            if (!current_job) {
                current_job = (Job*)malloc(sizeof(Job));
                current_job->data = (char*)malloc(32);
                current_job->id = 1;
            }
        }
        else if (action == 2) { // FREE
            if (current_job) {
                free(current_job->data);
                free(current_job);
            }
        }
        else if (action == 3) { // USE
            if (current_job) {
                if (current_job->id == 1) {
                    volatile char c = current_job->data[0]; 
                }
            }
        }
    }
}
"""
}

print(f"Generation of {len(files)} complex targets in '{output_dir}'...")
for filename, content in files.items():
    filepath = os.path.join(output_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content.strip())
    print(f"  Written: {filename}")
