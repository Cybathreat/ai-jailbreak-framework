"""
Output Module

Report generation and formatting for security audit results.
Supports JSON, Markdown, CSV, and console output formats.
"""

from typing import List, Dict, Optional, Any
from datetime import datetime, timezone
import json
import hashlib


def generate_report(results: Dict[str, any], 
                    format: str = "markdown",
                    include_metadata: bool = True) -> str:
    """
    Generate formatted report from audit results.
    
    Args:
        results: Audit results dictionary
        format: Output format (markdown, json, text)
        include_metadata: Include timestamp, version, etc.
    
    Returns:
        Formatted report string
    """
    if format == "json":
        return _generate_json_report(results, include_metadata)
    elif format == "markdown":
        return _generate_markdown_report(results, include_metadata)
    elif format == "text":
        return _generate_text_report(results, include_metadata)
    else:
        raise ValueError(f"Unknown format: {format}")


def _generate_json_report(results: Dict[str, any], 
                          include_metadata: bool) -> str:
    """Generate JSON-formatted report."""
    report = {"results": results}
    
    if include_metadata:
        report["metadata"] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": "AI Jailbreak Framework",
            "version": "0.1.0",
            "author": "Cybathreat (Ahmed Chiboub)"
        }
    
    return json.dumps(report, indent=2, default=str)


def _generate_markdown_report(results: Dict[str, any], 
                              include_metadata: bool) -> str:
    """Generate Markdown-formatted report."""
    lines = []
    
    lines.append("# AI Jailbreak Framework - Security Audit Report")
    lines.append("")
    
    if include_metadata:
        lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("**Tool:** AI Jailbreak Framework v0.1.0")
        lines.append("**Author:** Cybathreat (Ahmed Chiboub)")
        lines.append("")
    
    lines.append("---")
    lines.append("")
    
    # Techniques section
    if "techniques" in results:
        tech = results["techniques"]
        lines.append("## Jailbreak Techniques")
        lines.append("")
        lines.append(f"- **Total templates:** {tech.get('total_templates', 0)}")
        lines.append(f"- **Average effectiveness:** {tech.get('avg_effectiveness', 0):.2f}")
        lines.append(f"- **Average detection evasion:** {tech.get('avg_evasion', 0):.2f}")
        lines.append("")
        lines.append("### By Type")
        lines.append("")
        for tech_type, count in tech.get("by_type", {}).items():
            lines.append(f"- {tech_type}: {count}")
        lines.append("")
    
    # Injections section
    if "injections" in results:
        inj = results["injections"]
        lines.append("## Prompt Injection Tests")
        lines.append("")
        lines.append(f"- **Total tests:** {inj.get('total_tests', 0)}")
        lines.append("")
        lines.append("### By Risk Level")
        lines.append("")
        for risk, count in inj.get("by_risk", {}).items():
            lines.append(f"- {risk}: {count}")
        lines.append("")
    
    # Bypass section
    if "bypass" in results:
        bypass = results["bypass"]
        lines.append("## Safety Bypass Techniques")
        lines.append("")
        lines.append(f"- **Total techniques:** {bypass.get('total_techniques', 0)}")
        lines.append("")
        lines.append("### By Category")
        lines.append("")
        for cat, count in bypass.get("by_category", {}).items():
            lines.append(f"- {cat}: {count}")
        lines.append("")
    
    lines.append("---")
    lines.append("")
    lines.append("*For educational and security research purposes only.*")
    
    return "\n".join(lines)


def _generate_text_report(results: Dict[str, any], 
                          include_metadata: bool) -> str:
    """Generate plain text report."""
    lines = []
    
    lines.append("AI Jailbreak Framework - Security Audit Report")
    lines.append("=" * 60)
    lines.append("")
    
    if include_metadata:
        lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("Tool: AI Jailbreak Framework v0.1.0")
        lines.append("Author: Cybathreat (Ahmed Chiboub)")
        lines.append("")
    
    # Techniques
    if "techniques" in results:
        tech = results["techniques"]
        lines.append("JAILBREAK TECHNIQUES")
        lines.append(f"  Total templates: {tech.get('total_templates', 0)}")
        lines.append(f"  Avg effectiveness: {tech.get('avg_effectiveness', 0):.2f}")
        lines.append(f"  Avg evasion: {tech.get('avg_evasion', 0):.2f}")
        lines.append("")
    
    # Injections
    if "injections" in results:
        inj = results["injections"]
        lines.append("PROMPT INJECTION TESTS")
        lines.append(f"  Total tests: {inj.get('total_tests', 0)}")
        lines.append("")
    
    # Bypass
    if "bypass" in results:
        bypass = results["bypass"]
        lines.append("SAFETY BYPASS TECHNIQUES")
        lines.append(f"  Total techniques: {bypass.get('total_techniques', 0)}")
        lines.append("")
    
    lines.append("=" * 60)
    lines.append("Educational/security research use only.")
    
    return "\n".join(lines)


def format_output(data: Any, format: str = "text") -> str:
    """
    Format arbitrary data for output.
    
    Args:
        data: Data to format
        format: Output format
    
    Returns:
        Formatted string
    """
    if format == "json":
        return json.dumps(data, indent=2, default=str)
    elif format == "text":
        return str(data)
    elif format == "table":
        return _format_as_table(data)
    else:
        return str(data)


def _format_as_table(data: Any) -> str:
    """Format data as ASCII table."""
    if isinstance(data, dict):
        lines = []
        for key, value in data.items():
            lines.append(f"{key}: {value}")
        return "\n".join(lines)
    elif isinstance(data, list):
        if data and isinstance(data[0], dict):
            # Get headers
            headers = list(data[0].keys())
            lines = [" | ".join(headers)]
            lines.append("-" * len(lines[0]))
            for row in data:
                lines.append(" | ".join(str(row.get(h, "")) for h in headers))
            return "\n".join(lines)
        else:
            return "\n".join(str(item) for item in data)
    else:
        return str(data)


def generate_hash(data: str) -> str:
    """Generate SHA-256 hash of data."""
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def export_to_file(content: str, filepath: str, 
                   format: str = "text") -> None:
    """
    Export content to file.
    
    Args:
        content: Content to write
        filepath: Output file path
        format: File format (affects extension)
    """
    extensions = {
        "json": ".json",
        "markdown": ".md",
        "text": ".txt"
    }
    
    ext = extensions.get(format, ".txt")
    if not filepath.endswith(ext):
        filepath = filepath + ext
    
    with open(filepath, "w") as f:
        f.write(content)
    
    print(f"Report exported to: {filepath}")


if __name__ == "__main__":
    # Demo report generation
    sample_results = {
        "techniques": {
            "total_templates": 8,
            "avg_effectiveness": 0.49,
            "avg_evasion": 0.51,
            "by_type": {"dan": 2, "persona": 1, "logical": 1}
        },
        "injections": {
            "total_tests": 8,
            "by_risk": {"critical": 3, "high": 3, "medium": 2}
        },
        "bypass": {
            "total_techniques": 10,
            "by_category": {"content_filter": 2, "contextual": 3}
        }
    }
    
    print("Markdown Report:")
    print("=" * 60)
    print(generate_report(sample_results, format="markdown"))
    
    print("\n\nJSON Report:")
    print("=" * 60)
    print(generate_report(sample_results, format="json"))
