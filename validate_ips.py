#!/usr/bin/env python3

import json
import os


def load_json_file(file_path: str, default=None):
    """Load a JSON file or return default if file doesn't exist."""
    if default is None:
        default = []

    if not os.path.exists(file_path):
        return default

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"Warning: {file_path} is not valid JSON. Using default value.")
        return default


def save_json_file(file_path: str, data):
    """Save data to a JSON file."""
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def save_as_txt_file(file_path: str, data):
    """Save data to a TXT file."""
    with open(file_path, "w", encoding="utf-8") as f:
        for item in data:
            f.write(f"{item}\n")


def validate_ips(old_file: str, new_file: str, metadata_file: str, output_file: str):
    """
    Validate IPs based on TTL mechanism:
    - New IPs get TTL of 20
    - IPs not in new list have TTL reduced by 1
    - IPs with TTL of 0 are removed
    - Old IPs not in TTL data are added with TTL reduced by 1
    """
    old_ips = load_json_file(old_file, [])
    new_ips = load_json_file(new_file, [])
    ttl_data = load_json_file(metadata_file, {})

    old_ips_set = set(old_ips)
    new_ips_set = set(new_ips)

    for ip in old_ips_set:
        if ip not in ttl_data:
            ttl_data[ip] = 20

    for ip in list(ttl_data.keys()):
        if ip not in new_ips_set:
            ttl_data[ip] -= 1
            if ttl_data[ip] <= 0:
                del ttl_data[ip]
                if ip in old_ips_set:
                    old_ips_set.remove(ip)

    for ip in new_ips_set:
        if ip not in ttl_data:
            ttl_data[ip] = 20
            old_ips_set.add(ip)
        else:
            ttl_data[ip] = 20

    final_ips = list(old_ips_set)

    save_json_file(output_file, final_ips)
    save_as_txt_file(output_file.replace(".json", ".txt"), final_ips)
    save_json_file(metadata_file, ttl_data)
    os.remove(new_file)

    print(f"Processed IPs: {len(final_ips)} IPs in final list")
    print(f"Added: {len(new_ips_set - set(old_ips))} new IPs")
    print(f"Removed: {len(set(old_ips) - old_ips_set)} expired IPs")


if __name__ == "__main__":
    OLD_IPS_FILE = "tunnelbear_ips.json"
    NEW_IPS_FILE = "new_tunnelbear_ips.json"
    METADATA_FILE = "tunnelbear_ips_ttl.json"  # Metadata file for TTL tracking
    OUTPUT_FILE = "tunnelbear_ips.json"

    validate_ips(OLD_IPS_FILE, NEW_IPS_FILE, METADATA_FILE, OUTPUT_FILE)
