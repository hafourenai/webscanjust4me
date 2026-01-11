import argparse
import sys
import logging
import os
from honey_scanner.core.scanner import VulnScanner

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('honey_scanner.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

def print_banner():
    banner = """
    \033[38;5;160m██╗  ██╗\033[38;5;161m ██████╗\033[38;5;162m ███╗   ██╗\033[38;5;163m███████╗\033[38;5;164m██╗   ██╗
    \033[38;5;165m██║  ██║\033[38;5;166m██╔═══██╗\033[38;5;167m████╗  ██║\033[38;5;168m██╔════╝\033[38;5;169m╚██╗ ██╔╝
    \033[38;5;170m███████║\033[38;5;171m██║   ██║\033[38;5;172m██╔██╗ ██║\033[38;5;173m█████╗   \033[38;5;174m╚████╔╝ 
    \033[38;5;175m██╔══██║\033[38;5;176m██║   ██║\033[38;5;177m██║╚██╗██║\033[38;5;178m██╔══╝    \033[38;5;179m╚██╔╝  
    \033[38;5;21m██║  ██║\033[38;5;20m╚██████╔╝\033[38;5;19m██║ ╚████║\033[38;5;18m███████╗  \033[38;5;17m ██║   
    \033[38;5;56m╚═╝  ╚═╝\033[38;5;55m ╚═════╝ \033[38;5;54m╚═╝  ╚═══╝\033[38;5;53m╚══════╝  \033[38;5;52m ╚═╝   
    \033[0m
    \033[1;38;5;200mHONEY Modular Vulnerability Scanner\033[0m
    \033[38;5;208mAdvanced ML-Style Web Security Assessment Tool\033[0m
    """
    print(banner)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description='Honey Modular Vulnerability Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=15, help='Number of threads (default: 15)')
    parser.add_argument('-d', '--depth', type=int, default=5, help='Crawl depth (default: 5)')
    parser.add_argument('--aggressive', action='store_true', help='Enable aggressive mode')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode')
    parser.add_argument('--proxy-file', help='Path to proxy list file')
    parser.add_argument('--use-tor', action='store_true', help='Use TOR network')
    parser.add_argument('--rate', type=float, default=1.0, help='Requests per second (default: 1.0)')
    
    args = parser.parse_args()
    
    target = args.target
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
        
    print(f"[*] Starting scan on: {target}")
    
    scanner = VulnScanner(
        target_url=target,
        max_threads=args.threads,
        crawl_depth=args.depth,
        stealth_mode=args.stealth,
        aggressive_mode=args.aggressive,
        proxy_file=args.proxy_file,
        use_tor=args.use_tor,
        rate_limit=args.rate
    )
    
    try:
        print("[*] Phase 1: Discovery & Fingerprinting...")
        scanner.crawl()
        
        print("[*] Phase 2: Vulnerability Testing...")
        # In the modular version, we will call test methods from scanner
        # For now, let's assume we implement a run_tests method in VulnScanner
        # scanner.run_tests()
        
        print("[*] Phase 3: Generating Reports...")
        reports = scanner.generate_report()
        
        print("\n[+] Scan Complete!")
        for fmt, path in reports.items():
            print(f"  - [{fmt.upper()}] {path}")
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Critical error: {e}")
        logging.exception("Scan failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
