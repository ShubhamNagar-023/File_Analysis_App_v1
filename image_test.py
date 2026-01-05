import json
from src.file_analyzer.analyzer import analyze_file
from src.file_analyzer.deep_analyzer import deep_analyze_file

# PART 1: File Ingestion & Type Resolution
print("Running PART 1: File Ingestion & Type Resolution...")
part1 = analyze_file('/Users/shubhamnagar/Downloads/IMG_5508.jpeg')
print("\nPART 1 Results:")
print(json.dumps(part1, indent=2, default=str))

# PART 2: Deep File-Type-Aware Static Analysis
print("\n" + "="*80)
print("Running PART 2: Deep File-Type-Aware Static Analysis...")
part2 = deep_analyze_file('/Users/shubhamnagar/Downloads/IMG_5508.jpeg', part1)
print("\nPART 2 Results:")
print(json.dumps(part2, indent=2, default=str))
