import os
import subprocess
import time
import re
from openai import OpenAI

WISARD_ORACLE = {
    "cjson_parse.c": "CWE-119 (Improper Restriction of Operations within the Bounds of a Memory Buffer)",
    "cjson_free.c": "CWE-415 (Double Free)",
    "cjson_utils.c": "CWE-476 (NULL Pointer Dereference)",
}

INPUT_DIR = "fuzzer_priority_queue_complex"
CRASH_DIR = "fuzz_crashes"
HARNESS_DIR = "saved_harnesses"
REPORT_FILE = "benchmark_20_report_compliance.txt"

MODEL_NAME = "gpt-4o-mini"
MAX_REFLECTION_ROUNDS = 5
MAX_COMPILE_RETRIES = 3
FUZZ_TIME = 45
CLANG_CMD = "clang++ -fsanitize=fuzzer,address,undefined -g -gdwarf-4 -O1 -lm"

client = OpenAI(api_key=OPENAI_API_KEY)
CAMPAIGN_STATS = []

def ask_llm(messages):
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME, messages=messages, temperature=0.4
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"   API error: {e}")
        return ""

def clean_code(response_content):
    if not response_content: return ""
    match = re.search(r"```(?:cpp|c)?\n(.*?)```", response_content, re.DOTALL)
    if match: return match.group(1).strip()
    return response_content.replace("```cpp", "").replace("```c", "").replace("```", "").strip()

def sanitize_target_code(code):
    return re.sub(r'\b(int|void)\s+main\s*\(', r'\1 dead_main(', code)

def save_report():
    print("\nFinal report...")
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(f"{'FILENAME':<30} | {'STATUS':<10} | {'ROUND':<5} | {'NOTES'}\n")
        f.write("-" * 80 + "\n")
        for item in CAMPAIGN_STATS:
            status_icon = "CRASH" if item['crashed'] else "SECURE"
            f.write(f"{item['filename']:<30} | {status_icon:<10} | {item['round']:<5} | {item['note']}\n")
    print(f"Report saved to: {REPORT_FILE}")

def process_single_file(filepath, project_name):
    filename = os.path.basename(filepath)
    base_name = filename.replace(".c", "")
    
    cwe_target = WISARD_ORACLE.get(filename, "Generic memory corruption")
    
    print(f"\n[TARGET] {filename} | HUNTING FOR: {cwe_target}")

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            raw_code = f.read()
            vulnerable_code = sanitize_target_code(raw_code)
    except: return

    harness_path = f"temp_{base_name}.cpp"
    bin_path = f"./bin_{base_name}"
    previous_harness = ""
    file_stat = {'filename': filename, 'crashed': False, 'round': '-', 'note': 'Timeout'}

    fuzz_stream_class = """
class FuzzStream {
    const uint8_t *data;
    size_t size;
    size_t pos;
public:
    FuzzStream(const uint8_t *d, size_t s) : data(d), size(s), pos(0) {}
    
    template <typename T>
    T Consume() {
        if (pos + sizeof(T) > size) return T();
        T val = *((T*)(data + pos));
        pos += sizeof(T);
        return val;
    }

    char* ConsumeString() {
        if (pos >= size) return strdup(""); 
        size_t len = size - pos;
        if (len > 0) len = len / 2 + 1; 
        char *str = (char*)malloc(len + 1);
        if (len > 0) memcpy(str, data + pos, len);
        str[len] = '\\0';
        pos += len;
        return str;
    }
    
    void* ConsumeRemainingBytes(size_t *out_len) {
        if (pos >= size) { *out_len = 0; return malloc(1); }
        *out_len = size - pos;
        void *ptr = malloc(*out_len);
        memcpy(ptr, data + pos, *out_len);
        pos = size; 
        return ptr;
    }
};
"""

    cpp_template = f"""
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <vector>

{fuzz_stream_class}

/*{{MOCKS}}*/

/*{{TARGET_CODE}}*/

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{
    FuzzStream stream(Data, Size);
    /*{{HARNESS_BODY}}*/
    return 0;
}}
"""

    for round_idx in range(MAX_REFLECTION_ROUNDS):
        print(f"   ROUND {round_idx + 1}/{MAX_REFLECTION_ROUNDS}")
        
        if round_idx == 0:
            template_filled = cpp_template.replace("/*{{TARGET_CODE}}*/", vulnerable_code)
            system_prompt = "You are a security researcher specializing in exploit development and C++ fuzzing."
            user_prompt = f"""
            Create a C++ fuzzing harness for the following code.
            
            WARNING (TARGET ORACLE)
            Static/ML analysis indicates that this function is highly vulnerable to: {cwe_target}.
            
            Your goal is NOT generic coverage, but to write a harness that specifically stresses
            the code paths needed to trigger {cwe_target}.
            - If it is a buffer overflow, ignore string terminators or pass inconsistent sizes.
            - If it is a double free or use-after-free, manipulate pointer lifetimes and error paths.
            - If it is a null dereference, pass partially initialized structures.
            
            CODE: {vulnerable_code}
            TEMPLATE: {template_filled}
            Use `stream.Consume<T>()` to generate data. Return ONLY the complete C++ code.
            """
        else:
            system_prompt = "You are an advanced security researcher. Analyze the fuzzer's failures."
            user_prompt = f"""
            The previous harness compiled and ran, but it did NOT trigger the target vulnerability ({cwe_target}).
            We need to be more aggressive and change our approach to force that specific error state.
            
            TARGET CODE:
            {vulnerable_code}
            
            PREVIOUS HARNESS:
            {previous_harness}
            
            NEW SELF-HEALING STRATEGY FOR {cwe_target}:
            1. Review how the input is processed: are you artificially limiting its size? Remove the caps.
            2. Reverse or mix the order of API calls if the target is a state-related vulnerability (for example, use-after-free).
            3. Inject extreme edge cases (0, -1, INT_MAX) directly into critical memory-management arguments.
            
            Logically analyze why the previous harness failed to find {cwe_target}, then generate a complete NEW harness.
            """

        messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}]
        compiled = False
        current_code = ""
        
        for attempt in range(MAX_COMPILE_RETRIES):
            response_code = ask_llm(messages)
            if not response_code: break
            
            current_code = clean_code(response_code)
            with open(harness_path, "w", encoding="utf-8") as f: f.write(current_code)

            cmd = f"{CLANG_CMD} {harness_path} -o {bin_path} -w"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.returncode == 0:
                print("   Compiled.")
                compiled = True
                previous_harness = current_code
                break
            else:
                if attempt < MAX_COMPILE_RETRIES - 1:
                    messages.append({"role": "assistant", "content": response_code})
                    messages.append({"role": "user", "content": f"Compilation error: {result.stderr}\nFix it."})

        if compiled:
            print("   Fuzzing...")
            try:
                run_res = subprocess.run(f"{bin_path} -max_total_time={FUZZ_TIME}", shell=True, capture_output=True, text=True)
                
                if "ERROR: AddressSanitizer" in run_res.stderr or "leak" in run_res.stderr or "runtime error" in run_res.stderr:
                    print("   CRASH FOUND!")
                    
                    if not os.path.exists(CRASH_DIR): os.makedirs(CRASH_DIR)
                    log_file = os.path.join(CRASH_DIR, f"CRASH_{base_name}.txt")
                    with open(log_file, "w") as lf:
                        lf.write(f"TARGET: {filename}\nROUND: {round_idx+1}\nLOG:\n{run_res.stderr}\nCODE:\n{current_code}")
                    
                    if not os.path.exists(HARNESS_DIR): os.makedirs(HARNESS_DIR)
                    harness_save_path = os.path.join(HARNESS_DIR, f"{base_name}_harness.cpp")
                    with open(harness_save_path, "w") as hf:
                        hf.write(current_code)
                    print(f"   Harness saved to: {harness_save_path}")

                    file_stat['crashed'] = True
                    file_stat['round'] = round_idx + 1
                    file_stat['note'] = "Vuln confirmed"
                    CAMPAIGN_STATS.append(file_stat)
                    
                    if os.path.exists(bin_path): os.remove(bin_path)
                    if os.path.exists(harness_path): os.remove(harness_path)
                    return 
            except: pass
            if os.path.exists(bin_path): os.remove(bin_path)

    print("   No crash.")
    CAMPAIGN_STATS.append(file_stat)
    if os.path.exists(harness_path): os.remove(harness_path)

def main():
    if not os.path.exists(INPUT_DIR):
        print("The input directory is missing. Run generate_benchmark_20.py")
        return
    print("AUTO-FUZZING BATCH 20 (MAX ROUNDS: 5)")
    
    files = sorted([f for f in os.listdir(INPUT_DIR) if f.endswith(".c")])
    for f in files:
        process_single_file(os.path.join(INPUT_DIR, f), "BATCH_20")
    save_report()

if __name__ == "__main__":
    main()
