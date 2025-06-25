<div align="center">
  
# TunnelBear-IPs

🔒 An automatically updated list of IP addresses associated with the popular mobile VPN provider, TunnelBear.

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/tn3w/ProtonVPN-IPs/main.yml?label=Build&style=for-the-badge)

### IPInfo Category
[IPSet](https://github.com/tn3w/IPSet) | [ProtonVPN-IPs](https://github.com/tn3w/ProtonVPN-IPs) | [TunnelBear-IPs](https://github.com/tn3w/TunnelBear-IPs)

</div>

## 📊 Data Files

The repository maintains six regularly updated data files:

1. `tunnelbear_ips.json` - A JSON array containing only the unique exit IP addresses used by TunnelBear servers. This is a simplified version of the data focusing only on the IP addresses.

2. `tunnelbear_ips.txt` - A plain text file with one IP address per line, making it easy to use in scripts or other tools that expect a simple list format.

## 🛠️ Usage Examples

### Checking if an IP address is a TunnelBear IP

#### Python Example - Check Exit IP

```python
import json
import netaddr

def is_tunnelbear_exit_ip(ip_to_check, json_path='tunnelbear_ips.json'):
    """Check if an IP address is a TunnelBear exit IP"""
    try:
        # Validate IP address format
        netaddr.IPAddress(ip_to_check)
        
        # Load the TunnelBear IPs list
        with open(json_path, 'r') as f:
            tunnelbear_ips = json.load(f)
            
        # Check if IP is in the list
        return ip_to_check in tunnelbear_ips
    except netaddr.AddrFormatError:
        print(f"Error: {ip_to_check} is not a valid IP address")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

# Usage example
ip = "123.45.67.89"  # Example IP address
if is_tunnelbear_exit_ip(ip):
    print(f"{ip} is a TunnelBear exit IP")
else:
    print(f"{ip} is not a TunnelBear exit IP")
```

## 📜 License
Copyright 2025 TN3W

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.