from src.file_analyzer.analyzer import analyze_file
from src.file_analyzer.deep_analyzer import deep_analyze_file

part1 = analyze_file('/Users/shubhamnagar/Downloads/IMG_5508.jpeg')
part2 = deep_analyze_file('/Users/shubhamnagar/Downloads/IMG_5508.jpeg', part1)
