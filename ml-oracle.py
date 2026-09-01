import torch
import os
import gc
import pandas as pd
import numpy as np
import safetensors.torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification, AutoConfig
from tqdm import tqdm 




INPUT_FOLDER = "Functions_to_cover"  
OUTPUT_FOLDER = "experiment_results"
ROOT_DIRS = ["PrimeVul", "DiverseVul"]

THRESHOLDS_TO_TEST = [0.35, 0.50, 0.70]

MAX_LEN = 512
BATCH_SIZE = 4 

MODEL_MAPPINGS = {
    "codet5":       "Salesforce/codet5-base",
    "codebert":     "microsoft/codebert-base",
    "graphcodebert": "microsoft/graphcodebert-base",
    "unixcoder":    "microsoft/unixcoder-base",
}


def find_all_models(roots):
    found_models = []
    print(f"[*] Scanning models in: {roots}")
    
    for root_dir in roots:
        if not os.path.exists(root_dir): continue
        for model_folder in os.listdir(root_dir):
            full_model_path = os.path.join(root_dir, model_folder)
            if not os.path.isdir(full_model_path): continue
            
            checkpoints = []
            for item in os.listdir(full_model_path):
                if item.startswith("checkpoint-"):
                    try:
                        step = int(item.split("-")[-1])
                        checkpoints.append((step, os.path.join(full_model_path, item)))
                    except: pass
            
            if not checkpoints: continue
            checkpoints.sort(key=lambda x: x[0], reverse=True)
            best_step, best_path = checkpoints[0]
            
            base_model_id = next((mid for k, mid in MODEL_MAPPINGS.items() if k in model_folder.lower()), None)
            
            if base_model_id:
                w_file = os.path.join(best_path, "model.safetensors")
                if not os.path.exists(w_file): w_file = os.path.join(best_path, "pytorch_model.bin")
                
                if os.path.exists(w_file):
                    name = f"{model_folder.split('_')[-1]}_{best_step}"
                    found_models.append({"name": name, "base": base_model_id, "path": w_file})
    return found_models

def load_dataset(root_path):
    data = []
    print(f"[*] Loading functions from {root_path}...")
    
    for project_name in os.listdir(root_path):
        proj_path = os.path.join(root_path, project_name)
        if not os.path.isdir(proj_path): continue
        
        for file_name in os.listdir(proj_path):
            file_path = os.path.join(proj_path, file_name)
            
            if os.path.isfile(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()
                        
                        data.append({
                            "id": f"{project_name}/{file_name}",
                            "project": project_name,
                            "filename": file_name,
                            "code": code
                        })
                except Exception as e:
                    print(f"    ! Error reading {file_name}: {e}")
    
    print(f"    - Loaded {len(data)} functions.")
    return pd.DataFrame(data)

def run_inference_on_dataframe(df, models_list):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    for model_cfg in models_list:
        col_name = f"Prob_{model_cfg['name']}"
        print(f"\n>>> Model elaboration: {model_cfg['name']}")
        
        try:
            
            tokenizer = AutoTokenizer.from_pretrained(model_cfg['base'], trust_remote_code=True)
            config = AutoConfig.from_pretrained(model_cfg['base'], num_labels=2, trust_remote_code=True)
            model = AutoModelForSequenceClassification.from_pretrained(
                model_cfg['base'], config=config, trust_remote_code=True, ignore_mismatched_sizes=True
            )
            
            if model_cfg['path'].endswith(".safetensors"):
                model.load_state_dict(safetensors.torch.load_file(model_cfg['path'], device="cpu"), strict=False)
            else:
                model.load_state_dict(torch.load(model_cfg['path'], map_location="cpu"), strict=False)
                
            model.to(device)
            model.eval()
            
            
            probs_list = []
            code_list = df['code'].tolist()
            
            for i in tqdm(range(0, len(code_list), BATCH_SIZE), desc="Inferenza"):
                batch_code = code_list[i : i + BATCH_SIZE]
                
                inputs = tokenizer(
                    batch_code, padding=True, truncation=True, max_length=MAX_LEN, return_tensors="pt"
                ).to(device)
                
                with torch.no_grad():
                    outputs = model(**inputs)
                    
                    probs = torch.softmax(outputs.logits, dim=-1).cpu().numpy()
                    
                    probs_list.extend(probs[:, 1])
            
            
            df[col_name] = probs_list
            
            
            del model, tokenizer, inputs
            torch.cuda.empty_cache()
            gc.collect()
            
        except Exception as e:
            print(f"!!! Critical error on {model_cfg['name']}: {e}")
            df[col_name] = 0.0 
            
    return df

def apply_oracle_logic(df, threshold):
    prob_cols = [c for c in df.columns if c.startswith("Prob_")]
    
    verdicts = []
    reasons = []
    
    for _, row in df.iterrows():
        
        probs = [row[c] for c in prob_cols]
        
        
        suspicious_count = sum(1 for p in probs if p >= threshold)
        max_risk = max(probs) if probs else 0
        avg_risk = sum(probs)/len(probs) if probs else 0
        
        is_vuln = False
        reason = "Safe"
        
        
        if suspicious_count >= 2:
            is_vuln = True
            reason = f"Consensus ({suspicious_count} models > {threshold})"
            
        
        elif max_risk > max(0.60, threshold + 0.15):
            is_vuln = True
            reason = f"Peak Risk ({max_risk:.2f})"
            
        
        elif avg_risk > (threshold - 0.05):
            is_vuln = True
            reason = f"High Average ({avg_risk:.2f})"
            
        verdicts.append(is_vuln)
        reasons.append(reason)
        
    df[f"Verdict_T{threshold}"] = verdicts
    df[f"Reason_T{threshold}"] = reasons
    return df




def main():
    if not os.path.exists(OUTPUT_FOLDER): os.makedirs(OUTPUT_FOLDER)
    
    
    models = find_all_models(ROOT_DIRS)
    df_results = load_dataset(INPUT_FOLDER)
    
    if df_results.empty:
        print("!!! No functions found. Check the INPUT_FOLDER path.")
        return

    
    
    df_results = run_inference_on_dataframe(df_results, models)
    
    
    df_results.to_csv(os.path.join(OUTPUT_FOLDER, "raw_probabilities.csv"), index=False)
    
    
    print("\n" + "="*60)
    print("STARTING EXPERIMENTS WITH VARIABLE THRESHOLDS")
    print("="*60)
    
    summary_stats = []

    for th in THRESHOLDS_TO_TEST:
        print(f"\n---> Testing Threshold: {th}")
        
        
        df_experiment = df_results.copy()
        df_experiment = apply_oracle_logic(df_experiment, th)
        
        
        df_fuzzer = df_experiment[df_experiment[f"Verdict_T{th}"] == True]
        
        
        full_csv_name = os.path.join(OUTPUT_FOLDER, f"report_full_T{th}.csv")
        df_experiment.to_csv(full_csv_name, index=False)
        
        
        fuzz_csv_name = os.path.join(OUTPUT_FOLDER, f"to_fuzz_T{th}.csv")
        cols_to_keep = ['id', 'project', 'filename', 'code', f"Reason_T{th}"]
        
        cols_to_keep.extend([c for c in df_experiment.columns if c.startswith("Prob_")])
        
        df_fuzzer[cols_to_keep].to_csv(fuzz_csv_name, index=False)
        
        count_vuln = len(df_fuzzer)
        count_safe = len(df_experiment) - count_vuln
        print(f"    - Functions sent to Fuzzer: {count_vuln} (Out of {len(df_experiment)})")
        print(f"    - File saved in: {fuzz_csv_name}")
        
        summary_stats.append({"Threshold": th, "To_Fuzz": count_vuln, "Ignored": count_safe})

    
    print("\n" + "="*60)
    print("Experiment Summary")
    print(pd.DataFrame(summary_stats))
    print("="*60)

if __name__ == "__main__":
    main()
