#!/usr/bin/env python3
"""
PhishSense CLI - Standalone Command Line Interface
Phishing URL Detection System
"""

import sys
import os
import argparse
import json

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from phishsense.detector import PhishDetector


def print_banner():
    """Print PhishSense ASCII art banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║     ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗    ███████╗███████╗███╗   ║
║     ██╔══██╗██║  ██║██║██╔════╝██║  ██║    ██╔════╝██╔════╝████╗  ║
║     ██████╔╝███████║██║███████╗███████║    ███████╗█████╗  ██╔██╗ ║
║     ██╔═══╝ ██╔══██║██║╚════██║██╔══██║    ╚════██║██╔══╝  ██║╚██╗║
║     ██║     ██║  ██║██║███████║██║  ██║    ███████║███████╗██║ ╚█ ║
║     ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝    ╚══════╝╚══════╝╚═╝  ══╝
║                                                                   ║
║          🛡️  Advanced Phishing URL Detection System  🛡️            ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='PhishSense - Advanced Phishing URL Detection System (CLI)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python phishsense_cli.py https://example.com
  python phishsense_cli.py https://suspicious-site.tk --json
  python phishsense_cli.py https://example.com --verbose
        """
    )
    
    parser.add_argument(
        'url',
        help='URL to check for phishing'
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results in JSON format'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed feature information'
    )
    
    parser.add_argument(
        '--model',
        help='Path to custom ML model file'
    )
    
    args = parser.parse_args()
    
    # Print banner (skip for JSON output)
    if not args.json:
        print_banner()
    
    # Initialize detector
    try:
        detector = PhishDetector(model_path=args.model)
    except Exception as e:
        print(f"Error initializing detector: {e}", file=sys.stderr)
        sys.exit(2)
    
    # Detect
    try:
        result = detector.detect(args.url)
        
        if args.json:
            # JSON output
            output = {
                'url': result['url'],
                'is_phishing': result['is_phishing'],
                'confidence': round(result['confidence'], 3),
                'threat_level': result['threat_level'],
                'reasons': result['reasons']
            }
            if args.verbose:
                output['features'] = result['features']
                output['heuristic_score'] = round(result['heuristic_score'], 3)
                if result['ml_score'] is not None:
                    output['ml_score'] = result['ml_score']
                    output['ml_confidence'] = round(result['ml_confidence'], 3)
            
            print(json.dumps(output, indent=2))
        else:
            # Human-readable output
            print("\n" + "="*60)
            print("PhishSense - Phishing URL Detection Results")
            print("="*60)
            print(f"\nURL: {result['url']}")
            print(f"\nStatus: {'⚠️  PHISHING DETECTED' if result['is_phishing'] else '✅ SAFE'}")
            print(f"Confidence: {result['confidence']:.1%}")
            print(f"Threat Level: {result['threat_level']}")
            
            print(f"\nDetection Reasons:")
            for i, reason in enumerate(result['reasons'], 1):
                print(f"  {i}. {reason}")
            
            if args.verbose:
                print(f"\nDetailed Scores:")
                print(f"  Heuristic Score: {result['heuristic_score']:.3f}")
                if result['ml_score'] is not None:
                    print(f"  ML Score: {result['ml_score']}")
                    print(f"  ML Confidence: {result['ml_confidence']:.3f}")
                
                print(f"\nKey Features:")
                key_features = [
                    ('URL Length', result['features']['url_length']),
                    ('Domain Age (days)', result['features']['domain_age']),
                    ('Has HTTPS', bool(result['features']['has_https'])),
                    ('Valid SSL', bool(result['features']['has_valid_ssl'])),
                    ('Suspicious Keywords', result['features']['suspicious_keywords']),
                    ('Is Shortened', bool(result['features']['is_shortened'])),
                ]
                for name, value in key_features:
                    print(f"  {name}: {value}")
            
            print("\n" + "="*60 + "\n")
        
        # Exit code: 0 for safe, 1 for phishing
        sys.exit(0 if not result['is_phishing'] else 1)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        if args.verbose:
            traceback.print_exc()
        sys.exit(2)


if __name__ == '__main__':
    main()

