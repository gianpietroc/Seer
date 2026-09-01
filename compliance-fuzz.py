import os
import subprocess
import time
import re
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from openai import OpenAI


INPUT_DIR = "fuzzer_priority_queue_complex"
OUTPUT_DIR = "benchmark_results"
CRASH_DIR = os.path.join(OUTPUT_DIR, "crashes")
HARNESS_DIR = os.path.join(OUTPUT_DIR, "harnesses")

MODEL_NAME = "gpt-4o-mini"
NUM_RUNS = 3                  
MAX_REFLECTION_ROUNDS = 5
MAX_COMPILE_RETRIES = 3
FUZZ_TIME = 45                
CLANG_CMD = "clang++ -fsanitize=fuzzer,address,undefined -g -gdwarf-4 -O1 -lm"

WISARD_ORACLE = {
    "real_01_http_parser.c": "CWE-119 / CWE-193 (Improper Restriction of Memory Buffer / Off-by-one)",
    "real_02_rle_decoder.c": "CWE-190 / CWE-122 (Integer Overflow to Heap Overflow)",
    "real_03_bytecode_vm.c": "CWE-369 / CWE-125 (Divide By Zero / Out-of-bounds Read)",
    "real_04_json_parser.c": "CWE-415 (Double Free on admin_override)",
    "real_05_base64_decoder.c": "CWE-787 (Out-of-Bounds Write caused by incorrect padding)",
    "real_06_tlv_packet.c": "CWE-843 (Type Confusion / Access of Resource Using Incompatible Type)",
    "real_07_archive_extractor.c": "CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)",
    "real_08_dns_parser.c": "CWE-674 (Uncontrolled Recursion / Stack Exhaustion)",
    "real_09_crypto_exchange.c": "CWE-457 (Use of Uninitialized Variable)",
    "real_10_job_queue.c": "CWE-362 / CWE-416 (Race Condition to Use After Free)"
}

client = OpenAI(api_key=OPENAI_API_KEY)

def ask_llm(messages):
    try:
        response = client.chat.completions.create(model=MODEL_NAME, messages=messages, temperature=0.4)
        return response.choices[0].message.content
    except Exception as e:
        print(f"  API error: {e}")
        return ""

def clean_code(response_content):
    if not response_content: return ""
    pattern = r"`{3}(?:cpp|c)?\n(.*?)`{3}"
    match = re.search(pattern, response_content, re.DOTALL)
    if match: return match.group(1).strip()
    return response_content.replace("```cpp", "").replace("```c", "").replace("```", "").strip()

def sanitize_target_code(code):
    return re.sub(r'\b(int|void)\s+main\s*\(', r'\1 dead_main(', code)

FUZZSTREAM_CLASS = """
class FuzzStream {
    const uint8_t *data; size_t size; size_t pos;
public:
    FuzzStream(const uint8_t *d, size_t s) : data(d), size(s), pos(0) {}
    template <typename T> T Consume() {
        if (pos + sizeof(T) > size) return T();
        T val = *((T*)(data + pos)); pos += sizeof(T); return val;
    }
    char* ConsumeString() {
        if (pos >= size) return strdup(""); 
        size_t len = size - pos; if (len > 0) len = len / 2 + 1; 
        char *str = (char*)malloc(len + 1);
        if (len > 0) memcpy(str, data + pos, len);
        str[len] = '\\0'; pos += len; return str;
    }
};
"""

def run_experiment(filepath, mode="vanilla", run_id=1):
    filename = os.path.basename(filepath)
    base_name = filename.replace(".c", "")
    cwe_target = WISARD_ORACLE.get(filename, "Generic Vulnerability")
    
    print(f"\n[{mode.upper()} - RUN {run_id}/{NUM_RUNS}] Target: {filename}")
    
    with open(filepath, "r", encoding="utf-8") as f:
        vulnerable_code = sanitize_target_code(f.read())
        
    harness_path = os.path.join(OUTPUT_DIR, f"temp_{base_name}_{mode}_r{run_id}.cpp")
    bin_path = os.path.join(OUTPUT_DIR, f"bin_{base_name}_{mode}_r{run_id}")
    
    metrics = {
        "Target": filename,
        "Mode": mode,
        "Run_ID": run_id,
        "Compiled": False,
        "Compile_Retries": 0,
        "Crashed": 0, 
        "Reflection_Rounds": 0,
        "TTC_Seconds": FUZZ_TIME 
    }
    
    previous_harness = ""
    cpp_template = f"#include <stdint.h>\n#include <stddef.h>\n#include <stdlib.h>\n#include <string.h>\n#include <stdio.h>\n{FUZZSTREAM_CLASS}\n/*{{TARGET_CODE}}*/\nextern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{\n    FuzzStream stream(Data, Size);\n    /*{{HARNESS_BODY}}*/\n    return 0;\n}}"
    template_filled = cpp_template.replace("/*{{TARGET_CODE}}*/", vulnerable_code)

    allowed_rounds = MAX_REFLECTION_ROUNDS

    for round_idx in range(allowed_rounds):
        metrics["Reflection_Rounds"] = round_idx + 1
        print(f"  Round {round_idx + 1}/{allowed_rounds}")
        
        if mode == "vanilla" or mode == "ablated":
            if round_idx == 0:
                sys_prompt = "You are a C++ fuzzing expert."
                user_prompt = f"Create a harness for this code.\nCODE: {vulnerable_code}\nTEMPLATE: {template_filled}\nUse `stream.Consume<T>()`."
            else:
                sys_prompt = "You are an advanced security researcher."
                user_prompt = f"The previous harness did not find a crash. Change the strategy.\nCODE: {vulnerable_code}\nPREVIOUS HARNESS: {previous_harness}\nTry magic numbers, empty strings, or huge arrays. Generate a complete NEW harness."
        
        elif mode == "full":
            if round_idx == 0:
                sys_prompt = "You are a security researcher specializing in exploit development."
                user_prompt = f"Create a fuzzing harness. WARNING: The function is highly vulnerable to: {cwe_target}. Your goal is NOT generic coverage, but to stress the paths needed to trigger {cwe_target}.\nCODE: {vulnerable_code}\nTEMPLATE: {template_filled}\nReturn ONLY code."
            else:
                sys_prompt = "You are an advanced security researcher. Analyze the failures."
                user_prompt = f"Fuzzing FAILED to find {cwe_target}. Take an extreme approach to force that specific error state.\nCODE: {vulnerable_code}\nPREVIOUS HARNESS: {previous_harness}\nInject edge cases (-1, INT_MAX, NULL) related to {cwe_target}. Generate a complete NEW harness."

        messages = [{"role": "system", "content": sys_prompt}, {"role": "user", "content": user_prompt}]
        compiled = False
        current_code = ""
        
        for attempt in range(MAX_COMPILE_RETRIES):
            metrics["Compile_Retries"] += 1
            response_code = ask_llm(messages)
            current_code = clean_code(response_code)
            
            with open(harness_path, "w", encoding="utf-8") as f: f.write(current_code)
            cmd = f"{CLANG_CMD} {harness_path} -o {bin_path} -w"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.returncode == 0:
                compiled = True
                metrics["Compiled"] = True
                previous_harness = current_code
                break
            else:
                if attempt < MAX_COMPILE_RETRIES - 1:
                    messages.extend([
                        {"role": "assistant", "content": response_code},
                        {"role": "user", "content": f"Compilation error: {result.stderr}\nFix it."}
                    ])
        
        if compiled:
            print("  Fuzzing in progress...")
            start_time = time.time()
            run_res = subprocess.run(f"{bin_path} -max_total_time={FUZZ_TIME}", shell=True, capture_output=True, text=True)
            end_time = time.time()
            elapsed = round(end_time - start_time, 2)
            
            if "ERROR: AddressSanitizer" in run_res.stderr or "leak" in run_res.stderr or "runtime error" in run_res.stderr:
                print(f"  CRASH FOUND in {elapsed}s!")
                metrics["Crashed"] = 1
                metrics["TTC_Seconds"] = elapsed
                
                with open(os.path.join(CRASH_DIR, f"{base_name}_{mode}_r{run_id}_crash.txt"), "w") as f:
                    f.write(run_res.stderr)
                with open(os.path.join(HARNESS_DIR, f"{base_name}_{mode}_r{run_id}_harness.cpp"), "w") as f:
                    f.write(current_code)
                    
                if os.path.exists(bin_path): os.remove(bin_path)
                break 
            
            if os.path.exists(bin_path): os.remove(bin_path)

        if not compiled:
            print("  Final compilation failed.")
            break 
            
    print(f"  Result: {'CRASH' if metrics['Crashed'] else 'TIMEOUT'}")
    return metrics

def generate_reports(df):
    print("\nStatistical aggregation and chart generation...")
    
    df.to_csv(os.path.join(OUTPUT_DIR, "benchmark_metrics_raw.csv"), index=False)
    
    agg_df = df.groupby(['Target', 'Mode']).agg(
        TTC_Mean=('TTC_Seconds', 'mean'),
        TTC_Std=('TTC_Seconds', 'std'),
        Rounds_Mean=('Reflection_Rounds', 'mean'),
        Crash_Count=('Crashed', 'sum'),
        Total_Runs=('Run_ID', 'count')
    ).reset_index()
    
    agg_df['TTC_Std'] = agg_df['TTC_Std'].fillna(0)
    agg_df = agg_df.round(2)
    
    agg_df.to_csv(os.path.join(OUTPUT_DIR, "benchmark_metrics_aggregated.csv"), index=False)
    markdown_table = agg_df.to_markdown(index=False)
    with open(os.path.join(OUTPUT_DIR, "benchmark_table.md"), "w") as f:
        f.write(f"# Three-Way Experiment Results ({NUM_RUNS} runs per target)\n\n")
        f.write(markdown_table)
    
    plt.figure(figsize=(16, 8))
    targets = df['Target'].unique()
    
    def get_metric(mode, metric):
        mask = agg_df['Mode'] == mode
        return [agg_df[mask & (agg_df['Target'] == t)][metric].values[0] for t in targets]

    vanilla_means = get_metric('vanilla', 'TTC_Mean')
    vanilla_stds = get_metric('vanilla', 'TTC_Std')
    
    ablated_means = get_metric('ablated', 'TTC_Mean')
    ablated_stds = get_metric('ablated', 'TTC_Std')
    
    full_means = get_metric('full', 'TTC_Mean')
    full_stds = get_metric('full', 'TTC_Std')
    
    x = np.arange(len(targets))
    width = 0.25
    
    plt.bar(x - width, vanilla_means, width, yerr=vanilla_stds, capsize=5, 
            label='Vanilla (One-Shot, No CWE)', color='white', edgecolor='black', hatch='///')
            
    plt.bar(x, ablated_means, width, yerr=ablated_stds, capsize=5, 
            label='Ablated Seer (5 Rounds, No CWE)', color='lightgray', edgecolor='black', hatch='...')
    
    plt.bar(x + width, full_means, width, yerr=full_stds, capsize=5, 
            label='Full Seer (5 Rounds + CWE Guided)', color='dimgray', edgecolor='black', hatch='xxx')
    
    plt.ylabel('Time To Crash (Seconds in Log Scale)', fontsize=14)
    
    plt.yscale('log')
    
    import matplotlib.ticker as ticker
    plt.gca().yaxis.set_major_formatter(ticker.ScalarFormatter())

    short_targets = [t.replace("real_", "").replace(".c", "") for t in targets]
    
    plt.xticks(x, short_targets, rotation=45, ha='right', fontsize=17)
    plt.yticks(fontsize=17)
    
    plt.axhline(y=FUZZ_TIME, color='black', linestyle='--', label='Timeout (45s)')
    
    plt.legend(fontsize=12)
    
    plt.tight_layout()
    
    plt.savefig(os.path.join(OUTPUT_DIR, "ttc_ablation_plot.pdf"))
    print(f"Markdown table saved to {OUTPUT_DIR}/benchmark_table.md")
    print(f"PDF chart saved to {OUTPUT_DIR}/ttc_ablation_plot.pdf")

    plt.figure(figsize=(10, 6))

    def plot_cdf(mode, label, color, linestyle):
        crashed_runs = df[(df['Mode'] == mode) & (df['Crashed'] == 1)]['TTC_Seconds'].sort_values()
        
        x_vals = crashed_runs.values
        
        total_runs_per_mode = len(df[df['Mode'] == mode])
        y_vals = np.arange(1, len(x_vals) + 1) / total_runs_per_mode * 100
        
        x_vals = np.insert(x_vals, 0, 0.1) 
        y_vals = np.insert(y_vals, 0, 0)
        
        max_time = df['TTC_Seconds'].max() + 10
        x_vals = np.append(x_vals, max_time)
        y_vals = np.append(y_vals, y_vals[-1])

        plt.step(x_vals, y_vals, where='post', label=label, color=color, linestyle=linestyle, linewidth=2.5)

    plot_cdf('vanilla', 'Vanilla (One-Shot)', 'gray', ':')
    plot_cdf('ablated', 'Ablated Seer (Iterative)', 'black', '--')
    plot_cdf('full', 'Full Seer (CWE Guided)', 'black', '-')

    plt.xscale('log')
    import matplotlib.ticker as ticker
    plt.gca().xaxis.set_major_formatter(ticker.ScalarFormatter())

    plt.xlabel('Time to Crash (Seconds) [Log Scale]', fontsize=14)
    plt.ylabel('Percentage of Solved Runs (%)', fontsize=14)
    plt.xticks(fontsize=15)
    plt.yticks(fontsize=15)
    plt.ylim(0, 105)
    
    plt.grid(True, which="both", ls="--", alpha=0.3)
    
    plt.legend(loc='lower right', fontsize=12)
    plt.tight_layout()
    
    plt.savefig(os.path.join(OUTPUT_DIR, "cumulative_crashes_plot.pdf"))
    print(f"Cumulative PDF chart saved to {OUTPUT_DIR}/cumulative_crashes_plot.pdf")

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(CRASH_DIR, exist_ok=True)
    os.makedirs(HARNESS_DIR, exist_ok=True)
    
    if not os.path.exists(INPUT_DIR):
        print(f"The {INPUT_DIR} directory does not exist.")
        return

    files = sorted([f for f in os.listdir(INPUT_DIR) if f.endswith(".c")])
    if not files:
        print("No targets found.")
        return

    all_metrics = []
    
    all_metrics = pd.read_csv("benchmark_results/benchmark_metrics_raw.csv")
    df = pd.DataFrame(all_metrics)
    generate_reports(df)

if __name__ == "__main__":
    main()
