import sys
import re
import os

def parse_log(filepath, kind="Static"):
    """
    Parses a log file looking for 'ID:<id> RES:<res>'.
    Returns a dict: { id: result }
    For Runtime logs, since the same ID can be hit multiple times, 
    we aggregate: if ANY execution was an alias (1), the ground truth for that ID is Alias (1).
    """
    results = {}
    pattern = re.compile(r"ID:(\d+)\s+RES:(\d+)")
    
    print(f"Parsing {kind} log: {filepath}...")
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    id_val = int(match.group(1))
                    res_val = int(match.group(2))
                    
                    if kind == "Runtime":
                        # Runtime aggregation: Ground Truth is 1 if it EVER aliases.
                        current = results.get(id_val, 0)
                        if res_val == 1:
                            results[id_val] = 1
                        else:
                            # Keep it 0 if it was 0, or 1 if it was already 1
                            results[id_val] = current
                    else:
                        # Static: Should be unique per ID, but last write wins if dupes
                        results[id_val] = res_val
                        
    except FileNotFoundError:
        print(f"Error: File {filepath} not found.")
        sys.exit(1)
        
    print(f"Loaded {len(results)} unique IDs from {kind} log.")
    return results

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 analyze_results.py <runtime_log> <static_log>")
        sys.exit(1)

    runtime_path = sys.argv[1]
    static_path = sys.argv[2]

    runtime_data = parse_log(runtime_path, "Runtime")
    static_data = parse_log(static_path, "Static")

    # Confusion Matrix
    # Positive (1) = Alias
    # Negative (0) = NoAlias
    tp = 0 # Runtime=1, Static=1 (Correctly Identified Alias)
    tn = 0 # Runtime=0, Static=0 (Correctly Identified NoAlias)
    fp = 0 # Runtime=0, Static=1 (False Alarm: SVF says Alias, Runtime says Safe)
    fn = 0 # Runtime=1, Static=0 (Missed Bug: Runtime says Alias, SVF says Safe) -- CRITICAL

    intersection_ids = set(runtime_data.keys()).intersection(set(static_data.keys()))
    
    print(f"\nAnalyzing {len(intersection_ids)} common IDs...")

    for uid in intersection_ids:
        r_res = runtime_data[uid]
        s_res = static_data[uid]

        if r_res == 1 and s_res == 1:
            tp += 1
        elif r_res == 0 and s_res == 0:
            tn += 1
        elif r_res == 0 and s_res == 1:
            fp += 1
        elif r_res == 1 and s_res == 0:
            fn += 1

    # Metrics
    total = tp + tn + fp + fn
    if total == 0:
        print("No intersection found between logs.")
        sys.exit(0)

    print("\n=== Results ===")
    print(f"Total Analyzed Pairs: {total}")
    print(f"True Positives  (Both Alias):    {tp}")
    print(f"True Negatives  (Both NoAlias):  {tn}")
    print(f"False Positives (Static Over):   {fp} (Imprecision)")
    print(f"False Negatives (Static Under):  {fn} (Unsoundness/Bug)")

    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\nAccuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f} (How many predicted aliases were real?)")
    print(f"Recall:    {recall:.4f}    (How many real aliases did we find?)")
    print(f"F1 Score:  {f1:.4f}")

if __name__ == "__main__":
    main()
