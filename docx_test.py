
import json
import sys
from src.file_analyzer.analyzer import analyze_file
from src.file_analyzer.deep_analyzer import deep_analyze_file

# Get file path from command line or use default
if len(sys.argv) > 1:
    file_path = sys.argv[1]
else:
    # Default file path (can be changed to test different files)
    file_path = '/Users/shubhamnagar/Downloads/cyberbullying-survey.docx'
    print(f"No file path provided, using default: {file_path}")
    print("Usage: python docx_test.py <file_path>\n")

# PART 1: File Ingestion & Type Resolution
print("Running PART 1: File Ingestion & Type Resolution...")
part1 = analyze_file(file_path)
print("\nPART 1 Results:")
print(json.dumps(part1, indent=2, default=str))

# PART 2: Deep File-Type-Aware Static Analysis
print("\n" + "="*80)
print("Running PART 2: Deep File-Type-Aware Static Analysis...")
part2 = deep_analyze_file(file_path, part1)
print("\nPART 2 Results:")
print(json.dumps(part2, indent=2, default=str))
