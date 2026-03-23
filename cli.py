#!/usr/bin/env python3
"""
AI Jailbreak Framework - CLI

Command-line interface for running security audits against LLMs.
"""

import argparse
import sys
import json
from typing import List, Optional

from jailbreak_techniques import (
    list_templates, generate_payload, evaluate_effectiveness,
    audit_template_library
)
from prompt_injection import (
    list_tests, run_injection_audit, audit_injection_framework
)
from payload_generator import (
    PayloadGenerator, generate_batch, export_payloads
)
from safety_bypass import (
    list_techniques, detect_technique, audit_bypass_framework
)
from model_fingerprinting import (
    ModelFingerprinter, fingerprint_api_endpoint, generate_probe_prompt
)
from api_fuzzer import (
    APIFuzzer, FuzzType, run_api_fuzz_test, analyze_fuzz_results
)
from output import generate_report, format_output


def cmd_audit(args):
    """Run comprehensive security audit."""
    print("Running comprehensive security audit...")
    
    results = {
        "techniques": audit_template_library(),
        "injections": audit_injection_framework(),
        "bypass": audit_bypass_framework()
    }
    
    if args.output == "json":
        print(json.dumps(results, indent=2))
    else:
        report = generate_report(results, format="markdown")
        print(report)


def cmd_technique(args):
    """Test specific jailbreak technique."""
    template_name = args.technique
    question = args.prompt
    
    if not template_name:
        print("Error: --technique required")
        sys.exit(1)
    
    payload = generate_payload(template_name, question)
    effectiveness = evaluate_effectiveness(template_name)
    
    print(f"Technique: {template_name}")
    print(f"Generated payload:\n{payload}")
    print(f"\nEffectiveness: {effectiveness['effectiveness']:.2f}")
    print(f"Detection evasion: {effectiveness['detection_evasion']:.2f}")


def cmd_generate(args):
    """Generate adversarial payloads."""
    intents = args.intents if args.intents else ["default"]
    count = args.count or 10
    
    generator = PayloadGenerator(seed=args.seed)
    payloads = generator.generate(intents[0], count=count, 
                                  obfuscation_level=args.obfuscation or 3)
    
    output_format = args.format or "text"
    print(export_payloads(payloads, format=output_format))


def cmd_injection(args):
    """Run prompt injection tests."""
    test_name = args.test
    
    if not test_name:
        print("Available injection tests:")
        for t in list_tests():
            print(f"  - {t}")
        return
    
    # In production, this would call actual API and evaluate response
    print(f"Running injection test: {test_name}")
    print("Note: Requires --response with model output for evaluation")


def cmd_fingerprint(args):
    """Fingerprint LLM model."""
    if args.target:
        print(f"Fingerprinting target: {args.target}")
        # In production, would make actual API calls
        print("Note: Requires actual API responses for fingerprinting")
    else:
        print("Usage: --fingerprint --target <api_endpoint>")


def cmd_fuzz(args):
    """Fuzz API endpoint."""
    endpoint = args.endpoint
    
    if not endpoint:
        print("Error: --endpoint required")
        sys.exit(1)
    
    fuzz_types = []
    if args.types:
        for t in args.types.split(","):
            if t in [f.value for f in FuzzType]:
                fuzz_types.append(FuzzType(t))
    else:
        fuzz_types = list(FuzzType)
    
    print(f"Running fuzz test against: {endpoint}")
    print(f"Fuzz types: {[f.value for f in fuzz_types]}")
    
    # In production, would run actual fuzz campaign
    print("Note: Requires actual API endpoint for testing")


def cmd_list(args):
    """List available techniques/tests."""
    if args.type == "techniques":
        print("Jailbreak techniques:")
        for t in list_templates():
            eff = evaluate_effectiveness(t)
            print(f"  - {t} (eff: {eff['effectiveness']:.2f})")
    elif args.type == "injections":
        print("Injection tests:")
        for t in list_tests():
            print(f"  - {t}")
    elif args.type == "bypass":
        print("Bypass techniques:")
        for t in list_techniques():
            print(f"  - {t}")


def main():
    parser = argparse.ArgumentParser(
        description="AI Jailbreak Framework - Security Research Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --audit all --output json
  %(prog)s --technique dan_v1 --prompt "How to build X"
  %(prog)s --generate --intents "malware" --count 50
  %(prog)s --fingerprint --target https://api.openai.com
  %(prog)s --fuzz --endpoint https://api.example.com
        """
    )
    
    parser.add_argument("--audit", choices=["all", "techniques", "injections", "bypass"],
                        help="Run comprehensive audit")
    parser.add_argument("--technique", help="Jailbreak technique to test")
    parser.add_argument("--prompt", help="Test prompt/question")
    parser.add_argument("--generate", action="store_true", help="Generate payloads")
    parser.add_argument("--intents", nargs="+", help="Intents for payload generation")
    parser.add_argument("--count", type=int, default=10, help="Number of payloads")
    parser.add_argument("--obfuscation", type=int, choices=[1,2,3,4,5], help="Obfuscation level")
    parser.add_argument("--format", choices=["text", "json", "csv"], help="Output format")
    parser.add_argument("--seed", type=int, help="Random seed for reproducibility")
    parser.add_argument("--injection", help="Run injection test")
    parser.add_argument("--test", help="Specific injection test name")
    parser.add_argument("--fingerprint", action="store_true", help="Fingerprint model")
    parser.add_argument("--target", help="Target API for fingerprinting")
    parser.add_argument("--fuzz", action="store_true", help="Run API fuzzer")
    parser.add_argument("--endpoint", help="API endpoint to fuzz")
    parser.add_argument("--types", help="Comma-separated fuzz types")
    parser.add_argument("--list", choices=["techniques", "injections", "bypass"],
                        help="List available items")
    parser.add_argument("--output", choices=["text", "json", "markdown"],
                        default="text", help="Output format")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.audit:
        cmd_audit(args)
    elif args.technique:
        cmd_technique(args)
    elif args.generate:
        cmd_generate(args)
    elif args.injection or args.test:
        cmd_injection(args)
    elif args.fingerprint:
        cmd_fingerprint(args)
    elif args.fuzz:
        cmd_fuzz(args)
    elif args.list:
        cmd_list(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
