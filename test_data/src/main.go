package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type GenomicResult struct {
	SequencesProcessed int                `json:"sequences_processed"`
	TotalBases         int                `json:"total_bases"`
	GCContentPercent   float64            `json:"gc_content_percent"`
	BaseCounts         map[string]int     `json:"base_counts"`
	TopKMers           map[string]int     `json:"top_kmers"`
	Status             string             `json:"status"`
}

func main() {
	fmt.Println("==================================================================")
	fmt.Println(" UniCompute Distributed Scientific Worker - Genomic Analyzer v1.0")
	fmt.Println(" Execution Environment: WASI Preview 1 Sandbox")
	fmt.Println("==================================================================")

	var fastaFiles []string
	searchDirs := []string{"/data/inputs", "inputs", "."}

	for _, dir := range searchDirs {
		entries, err := os.ReadDir(dir)
		if err == nil {
			for _, e := range entries {
				name := strings.ToLower(e.Name())
				if !e.IsDir() {
					isFasta := strings.HasSuffix(name, ".fa") || strings.HasSuffix(name, ".fasta") || strings.HasSuffix(name, ".fna") || strings.HasSuffix(name, ".dat") || strings.HasSuffix(name, ".txt")
					if !isFasta {
						fullPath := filepath.Join(dir, e.Name())
						if f, errOpen := os.Open(fullPath); errOpen == nil {
							buf := make([]byte, 16)
							if n, _ := f.Read(buf); n > 0 && strings.HasPrefix(strings.TrimSpace(string(buf[:n])), ">") {
								isFasta = true
							}
							f.Close()
						}
					}
					if isFasta {
						fastaFiles = append(fastaFiles, filepath.Join(dir, e.Name()))
					}
				}
			}
		}
	}

	totalBases := 0
	gcBases := 0
	sequences := 0
	baseCounts := map[string]int{"A": 0, "C": 0, "G": 0, "T": 0, "N": 0}
	kmers := make(map[string]int)

	var sequenceData strings.Builder

	if len(fastaFiles) > 0 {
		for _, file := range fastaFiles {
			fmt.Printf("[+] Processing mounted FASTA dataset: %s\n", file)
			data, err := os.ReadFile(file)
			if err != nil {
				fmt.Printf("[-] Warning reading %s: %v\n", file, err)
				continue
			}

			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, ">") {
					sequences++
					fmt.Printf("    Record Header: %s\n", line)
				} else {
					sequenceData.WriteString(line)
				}
			}
		}
	} else {
		fmt.Println("[*] No external FASTA dataset mounted; executing default benchmark sequence...")
		defaultSeq := "ATGTTTGTTTTTCTTGTTTTATTGCCACTAGTCTCTAGTCAGTGTGTTAATCTTACAACCAGAACTCAATTACCCCCTGCATACACTAATTCT"
		sequenceData.WriteString(defaultSeq)
		sequences = 1
	}

	fullSeq := strings.ToUpper(sequenceData.String())
	for i := 0; i < len(fullSeq); i++ {
		ch := fullSeq[i]
		switch ch {
		case 'A':
			baseCounts["A"]++
			totalBases++
		case 'C':
			baseCounts["C"]++
			gcBases++
			totalBases++
		case 'G':
			baseCounts["G"]++
			gcBases++
			totalBases++
		case 'T':
			baseCounts["T"]++
			totalBases++
		case 'N':
			baseCounts["N"]++
			totalBases++
		}

		// 3-mer profiling
		if i+3 <= len(fullSeq) {
			kmer := fullSeq[i : i+3]
			kmers[kmer]++
		}
	}

	gcPercent := 0.0
	if totalBases > 0 {
		gcPercent = (float64(gcBases) / float64(totalBases)) * 100.0
	}

	fmt.Println("------------------------------------------------------------------")
	fmt.Printf(" Results Summary:\n")
	fmt.Printf("   Sequences Analyzed: %d\n", sequences)
	fmt.Printf("   Total Base Pairs:   %d bp\n", totalBases)
	fmt.Printf("   A: %d | C: %d | G: %d | T: %d | N: %d\n",
		baseCounts["A"], baseCounts["C"], baseCounts["G"], baseCounts["T"], baseCounts["N"])
	fmt.Printf("   GC Content:         %.2f%%\n", gcPercent)
	fmt.Println("------------------------------------------------------------------")

	result := GenomicResult{
		SequencesProcessed: sequences,
		TotalBases:         totalBases,
		GCContentPercent:   gcPercent,
		BaseCounts:         baseCounts,
		TopKMers:           kmers,
		Status:             "SUCCESS",
	}

	outJSON, _ := json.MarshalIndent(result, "", "  ")

	// Write outputs to /data/outputs (and fallback to current working directory)
	outDirs := []string{"/data/outputs", "outputs", "."}
	for _, outDir := range outDirs {
		_ = os.MkdirAll(outDir, 0755)
		_ = os.WriteFile(filepath.Join(outDir, "genomic_analysis.json"), outJSON, 0644)
		_ = os.WriteFile(filepath.Join(outDir, "report.txt"), []byte(fmt.Sprintf(
			"Genomic Analysis Report\nTotal BP: %d\nGC Content: %.2f%%\nStatus: SUCCESS\n",
			totalBases, gcPercent,
		)), 0644)
	}

	fmt.Println("[✓] Genomic analysis completed. Output files generated.")
}
