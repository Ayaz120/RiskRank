"""
parsers/manual_parser.py
------------------------
Parses a simple JSON format for manually-recorded findings.
"""

import json


def parse_manual_json(filepath):
    with open(filepath, "r") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Expected a JSON array of finding objects")

    findings = []
    for item in data:
        findings.append({
            "asset": item.get("asset", "unknown"),
            "title": item.get("title", "Untitled finding"),
            "description": item.get("description", ""),
            "asset_criticality": item.get("asset_criticality", "unknown"),
            "raw_data": item,
        })

    return findings


if __name__ == "__main__":
    import sys
    for r in parse_manual_json(sys.argv[1]):
        print(r)
