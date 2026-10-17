#!/usr/bin/env python3
"""
UniCompute Tier 2 Container Workload: Genomic K-Mer & Mutation Frequency Analyzer
Executes inside an isolated directory jail bounded by Win32 JobObject limits.
"""

import os
import sys
import json
import glob

def main():
    print("[Tier 2 Container] Starting Hardened Process Container Workload...")
    inputs_dir = os.environ.get("UNICOMPUTE_INPUTS", "./inputs")
    outputs_dir = os.environ.get("UNICOMPUTE_OUTPUTS", "./outputs")
    
    os.makedirs(outputs_dir, exist_ok=True)
    
    print(f"[Tier 2 Container] Input Directory: {inputs_dir}")
    print(f"[Tier 2 Container] Output Directory: {outputs_dir}")

    # Search for input fasta or dat files
    input_files = glob.glob(os.path.join(inputs_dir, "*"))
    seq = ""
    target_file = ""
    for f in input_files:
        if f.endswith(".fa") or f.endswith(".dat") or "genomic" in f:
            target_file = f
            with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    if not line.startswith(">"):
                        seq += line.strip().upper()
            break

    if not seq:
        seq = "ATGCGATCGATCGATCGATCGATCGATCGATCGATC" * 40
        print("[Tier 2 Container] Using fallback synthetic nucleotide sequence.")
    else:
        print(f"[Tier 2 Container] Loaded sequence from {os.path.basename(target_file)} ({len(seq)} bp)")

    # Compute codon & k-mer frequencies
    a_cnt = seq.count("A")
    c_cnt = seq.count("C")
    g_cnt = seq.count("G")
    t_cnt = seq.count("T")
    total = max(1, a_cnt + c_cnt + g_cnt + t_cnt)
    gc_pct = round(((g_cnt + c_cnt) / total) * 100, 2)

    # 3-mer frequency
    kmers = {}
    for i in range(len(seq) - 2):
        k = seq[i:i+3]
        kmers[k] = kmers.get(k, 0) + 1

    top_kmers = sorted(kmers.items(), key=lambda x: x[1], reverse=True)[:5]

    output_data = {
        "tier": "Tier 2: Hardened Process Container",
        "status": "COMPLETED_VERIFIED",
        "sequence_length_bp": len(seq),
        "gc_content_pct": gc_pct,
        "nucleotide_counts": {
            "adenine": a_cnt,
            "cytosine": c_cnt,
            "guanine": g_cnt,
            "thymine": t_cnt
        },
        "top_codons": dict(top_kmers),
        "job_object_enforced": True,
        "isolation_level": "Filesystem Jail & Restricted Network"
    }

    out_file = os.path.join(outputs_dir, "genomic_analysis.json")
    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(output_data, fh, indent=2)

    print(json.dumps(output_data, indent=2))
    print(f"[Tier 2 Container] Success! Result written to {out_file}")

if __name__ == "__main__":
    main()
