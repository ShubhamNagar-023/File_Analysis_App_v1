#!/usr/bin/env python3
"""
File Analysis Application - Main Launcher
Launches the File Analysis Application with GUI or CLI mode.

Usage:
    python start.py                    # Start with GUI
    python start.py --cli              # CLI mode only
    python start.py --api              # Start API server only
    python start.py --analyze <file>   # Analyze a file first, then open GUI
"""

import sys
import os
import subprocess
import argparse
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed"""
    print("Checking dependencies...")
    
    # Check Python dependencies
    missing = []
    try:
        import magic
    except (ImportError, ModuleNotFoundError):
        missing.append('python-magic')
    
    try:
        import olefile
    except (ImportError, ModuleNotFoundError):
        missing.append('olefile')
    
    if missing:
        print(f"✗ Missing Python dependencies: {', '.join(missing)}")
        print("\nRun: pip install -r requirements.txt")
        return False
    
    print("✓ Core Python dependencies installed")
    
    # Check PyQt6 for GUI
    try:
        import PyQt6
        print("✓ PyQt6 installed - GUI available")
        return True
    except (ImportError, ModuleNotFoundError):
        print("⚠ PyQt6 not installed - GUI not available")
        print("\nFor GUI mode: pip install PyQt6")
        print("For CLI-only mode: python start.py --cli")
        return "cli_only"

def analyze_file(file_path):
    """Run analysis on a file"""
    print(f"\nAnalyzing: {file_path}")
    result = subprocess.run([sys.executable, 'analyze_file.py', file_path])
    return result.returncode == 0

def start_gui():
    """Start the PyQt6 GUI"""
    print("\nStarting File Analysis GUI...")
    print("The desktop application will open in a new window.")
    print("Press Ctrl+C in this terminal to stop.\n")
    
    try:
        # Check if app.py exists
        if not Path('app.py').exists():
            print("Error: app.py not found")
            print("Please ensure you're running from the repository root directory")
            return False
        
        result = subprocess.run([sys.executable, 'app.py'])
        return result.returncode == 0
    except FileNotFoundError:
        print("Error: Python interpreter not found")
        return False
    except subprocess.CalledProcessError as e:
        print(f"Error launching GUI: {e}")
        return False
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        return True

def cli_mode():
    """Run in CLI-only mode"""
    print("\n" + "="*70)
    print("FILE ANALYSIS APPLICATION - CLI MODE")
    print("="*70)
    print("\nUsage:")
    print("  python analyze_file.py <file>     - Analyze a file")
    print("  python api_server.py              - Start API server")
    print("  python -m pytest tests/ -v        - Run tests")
    print("\nExamples:")
    print("  python analyze_file.py test_files/sample.pdf")
    print("  python analyze_file.py /path/to/suspicious-file.exe")
    print("  python api_server.py --port 5000")
    print("\nResults are saved to exports/ directory.")
    print("="*70 + "\n")

def start_api_server(port=5000):
    """Start the API server"""
    print("\nStarting API server...")
    print(f"Server will be available at http://localhost:{port}")
    print("Press Ctrl+C to stop.\n")
    
    try:
        result = subprocess.run([sys.executable, 'api_server.py', '--port', str(port)])
        return result.returncode == 0
    except KeyboardInterrupt:
        print("\n\nServer stopped")
        return True

def main():
    parser = argparse.ArgumentParser(
        description="File Analysis Application",
        epilog="Production-Grade File Security and Forensic Analysis Tool"
    )
    parser.add_argument('--cli', action='store_true', 
                       help='CLI mode only (no GUI)')
    parser.add_argument('--api', action='store_true',
                       help='Start API server only')
    parser.add_argument('--port', type=int, default=5000,
                       help='API server port (default: 5000)')
    parser.add_argument('--analyze', metavar='FILE',
                       help='Analyze a file first, then open GUI')
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("FILE ANALYSIS APPLICATION")
    print("Production-Grade File Security Analysis")
    print("="*70 + "\n")
    
    # Check dependencies
    deps_status = check_dependencies()
    if deps_status is False:
        return 1
    
    # API server mode
    if args.api:
        return 0 if start_api_server(args.port) else 1
    
    # CLI-only mode
    if args.cli or deps_status == "cli_only":
        cli_mode()
        return 0
    
    # Analyze file first if requested
    if args.analyze:
        if not Path(args.analyze).exists():
            print(f"Error: File not found: {args.analyze}")
            return 1
        
        if not analyze_file(args.analyze):
            print("Analysis failed")
            return 1
        
        print("\n✓ Analysis complete. Opening GUI to view results...")
    
    # Start GUI
    return 0 if start_gui() else 1

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
