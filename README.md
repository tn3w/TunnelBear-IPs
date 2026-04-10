<div align="center">
  
# TunnelBear-IPs

An automatically updated list of IP addresses associated with the popular mobile VPN provider, TunnelBear.

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/tn3w/TunnelBear-IPs/main.yml?label=Build&style=for-the-badge)

### IPInfo Category

[IPBlocklist](https://github.com/tn3w/IPBlocklist) | [IP2X](https://github.com/tn3w/IP2X) | [ProtonVPN-IPs](https://github.com/tn3w/ProtonVPN-IPs) | [TunnelBear-IPs](https://github.com/tn3w/TunnelBear-IPs) | [Windscribe-IPs](https://github.com/tn3w/Windscribe-IPs)

</div>

## Table of Contents

- [Data Files](#data-files)
- [How It Works](#how-it-works)
- [Account Setup](#account-setup)
- [Usage Examples](#usage-examples)
- [License](#license)

## Data Files

| File                      | Raw Link                                                                                               | Purpose                                               |
| ------------------------- | ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------- |
| `tunnelbear_ips.json`     | [Raw](https://raw.githubusercontent.com/tn3w/TunnelBear-IPs/refs/heads/master/tunnelbear_ips.json)     | Unique server IP addresses (JSON array)               |
| `tunnelbear_ips.txt`      | [Raw](https://raw.githubusercontent.com/tn3w/TunnelBear-IPs/refs/heads/master/tunnelbear_ips.txt)      | Unique server IP addresses (plain text, one per line) |
| `tunnelbear_ips_ttl.json` | [Raw](https://raw.githubusercontent.com/tn3w/TunnelBear-IPs/refs/heads/master/tunnelbear_ips_ttl.json) | TTL tracking data for IP expiry                       |

## How It Works

Server IPs are fetched from the TunnelBear/PolarBear API across all supported countries. A TTL mechanism keeps the list accurate over time:

- Newly discovered IPs receive a TTL of **30**
- IPs absent from the latest fetch have their TTL decremented by 1
- IPs that reach TTL **0** are removed from the list

One or more TunnelBear accounts are required to authenticate against the API.

## Account Setup

### Required Repository Secrets

| Secret                 | Purpose                                |
| ---------------------- | -------------------------------------- |
| `tunnelbear_email`     | TunnelBear account email (primary)     |
| `tunnelbear_password`  | TunnelBear account password (primary)  |
| `tunnelbear_email1`    | Additional account email (optional)    |
| `tunnelbear_password1` | Additional account password (optional) |

Additional accounts can be added by incrementing the suffix (`tunnelbear_email2` / `tunnelbear_password2`, etc.). Using multiple accounts reduces the chance of rate-limiting during the full country sweep.

### Quick Setup

1. **Create a TunnelBear account**: Sign up at [tunnelbear.com](https://www.tunnelbear.com) (free accounts work)
2. **Add secrets**: In your repository go to Settings → Secrets and variables → Actions, add the required secrets
3. **Test**: Run the workflow from the Actions tab

## Usage Examples

### Check Server IP

```python
import json

def is_tunnelbear_ip(ip_to_check):
    with open('tunnelbear_ips.json', 'r') as f:
        tunnelbear_ips = set(json.load(f))
    return ip_to_check in tunnelbear_ips

if is_tunnelbear_ip("216.238.101.72"):
    print("TunnelBear server IP detected")
```

### Bulk IP Check

```python
import json
from typing import List, Dict

def check_multiple_ips(ips_to_check: List[str]) -> Dict[str, bool]:
    try:
        with open('tunnelbear_ips.json', 'r') as f:
            tunnelbear_ips = set(json.load(f))
        return {ip: ip in tunnelbear_ips for ip in ips_to_check}
    except Exception as e:
        return {'error': str(e)}

ips = ["216.238.101.72", "192.168.1.1"]
results = check_multiple_ips(ips)
for ip, is_tb in results.items():
    print(f"{ip}: TunnelBear={is_tb}")
```

## License

[Apache-2.0](LICENSE)
