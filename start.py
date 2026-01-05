#!/usr/bin/env python3
"""
File Analysis Application - Integrated Launcher
Starts both backend and frontend for production use.

Usage:
    python start.py                    # Start with UI
    python start.py --cli              # CLI mode only
    python start.py --analyze <file>   # Analyze and open UI
"""

import sys
import os
import subprocess
import argparse
from pathlib import Path
import time

def check_dependencies():
    """Check if required dependencies are installed"""
    print("Checking dependencies...")
    
    # Check Python dependencies
    try:
        import magic
        import olefile
        print("✓ Python dependencies installed")
    except ImportError as e:
        print(f"✗ Missing Python dependency: {e.name}")
        print("\nRun: pip install -r requirements.txt")
        return False
    
    # Check Node.js for UI
    try:
        result = subprocess.run(['node', '--version'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ Node.js {result.stdout.strip()} installed")
            return True
    except FileNotFoundError:
        print("✗ Node.js not found (needed for UI)")
        print("\nFor CLI-only mode: python start.py --cli")
        print("To install Node.js: https://nodejs.org/")
        return "cli_only"
    
    return True

def setup_electron():
    """Install Electron dependencies if needed"""
    electron_dir = Path("electron")
    node_modules = electron_dir / "node_modules"
    
    if not node_modules.exists():
        print("\nInstalling Electron dependencies...")
        print("This may take a few minutes on first run...")
        result = subprocess.run(['npm', 'install'], 
                              cwd=electron_dir,
                              capture_output=True,
                              text=True)
        if result.returncode != 0:
            print(f"Error installing dependencies:\n{result.stderr}")
            return False
        print("✓ Electron dependencies installed")
    return True

def analyze_file(file_path):
    """Run analysis on a file"""
    print(f"\nAnalyzing: {file_path}")
    result = subprocess.run([sys.executable, 'analyze_file.py', file_path])
    return result.returncode == 0

def start_ui(db_path=None):
    """Start the Electron UI"""
    print("\nStarting File Analysis UI...")
    print("The desktop application will open in a new window.")
    print("Press Ctrl+C in this terminal to stop.\n")
    
    electron_dir = Path("electron")
    env = os.environ.copy()
    if db_path:
        env['ANALYSIS_DB_PATH'] = str(db_path)
    
    try:
        subprocess.run(['npm', 'start'], cwd=electron_dir, env=env)
    except KeyboardInterrupt:
        print("\n\nShutting down...")

def find_latest_database():
    """Find the most recent analysis database"""
    exports_dir = Path("exports")
    if not exports_dir.exists():
        return None
    
    # Find all subdirectories
    subdirs = [d for d in exports_dir.iterdir() if d.is_dir()]
    if not subdirs:
        return None
    
    # Sort by modification time, get latest
    latest = max(subdirs, key=lambda d: d.stat().st_mtime)
    db_file = latest / "analysis.db"
    
    if db_file.exists():
        return db_file
    return None

def cli_mode():
    """Run in CLI-only mode"""
    print("\n" + "="*70)
    print("FILE ANALYSIS APPLICATION - CLI MODE")
    print("="*70)
    print("\nUsage:")
    print("  python analyze_file.py <file>     - Analyze a file")
    print("  python -m pytest tests/ -v        - Run tests")
    print("\nExamples:")
    print("  python analyze_file.py test_files/sample.pdf")
    print("  python analyze_file.py /path/to/suspicious-file.exe")
    print("\nResults are saved to exports/ directory.")
    print("="*70 + "\n")

def main():
    parser = argparse.ArgumentParser(description="File Analysis Application")
    parser.add_argument('--cli', action='store_true', 
                       help='CLI mode only (no UI)')
    parser.add_argument('--analyze', metavar='FILE',
                       help='Analyze a file, then open UI')
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("FILE ANALYSIS APPLICATION")
    print("="*70 + "\n")
    
    # Check dependencies
    deps_status = check_dependencies()
    if deps_status is False:
        return 1
    
    # CLI-only mode
    if args.cli or deps_status == "cli_only":
        cli_mode()
        return 0
    
    # Analyze file first if requested
    db_path = None
    if args.analyze:
        if not Path(args.analyze).exists():
            print(f"Error: File not found: {args.analyze}")
            return 1
        
        if not analyze_file(args.analyze):
            print("Analysis failed")
            return 1
        
        # Find the database that was just created
        db_path = find_latest_database()
        print(f"\n✓ Analysis complete. Database: {db_path}")
        time.sleep(1)
    
    # Setup and start UI
    print("\nPreparing desktop UI...")
    if not setup_electron():
        print("\nFalling back to CLI mode...")
        cli_mode()
        return 0
    
    start_ui(db_path)
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
