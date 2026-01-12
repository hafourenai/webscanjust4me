#!/usr/bin/env python3
import sys
import os

# Ensure the current directory is in the path so we can import honey_scanner
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from honey_scanner.cli import main
except ImportError as e:
    print(f"Error: Could not import honey_scanner. Please ensure the 'honey_scanner' directory exists and dependencies are installed.\nError details: {e}")
    sys.exit(1)

if __name__ == "__main__":
    main()
