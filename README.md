# Vhost-Grouper

A Python tool to group hostnames by their resolved IP addresses.  
It reads a list of hostnames, resolves their A/AAAA records, and outputs groupings of hostnames sharing the same IP.

> **Note:**  
> The resolved IPs represent the addresses returned by DNS at the time of the scan.  
> Actual serving IPs may vary due to CDNs, load balancers, or custom domain routing, and can change between scans.

## Features

- Reads hostnames from a text file (one per line).
- Resolves both IPv4 and IPv6 addresses.
- Groups hostnames by IP address.
- Outputs results in human-readable and JSON formats.
- Highlights IPs hosting multiple hostnames (potential vhost targets).
- Logs DNS resolution errors.
- Fast: uses multithreading for concurrent lookups.
- No external dependencies (pure stdlib).

## Usage

```bash
python3 vhost_grouper.py -i subdomains.txt
python3 vhost_grouper.py -i subdomains.txt -o results -t 50 --only-duplicates
```

### Arguments

- `-i, --input` **(required)**: Input file containing hostnames (one per line).
- `-o, --outdir`: Output directory (default: `vhost_results`).
- `-t, --threads`: Number of concurrent resolver threads (default: 20).
- `--timeout`: Resolver timeout in seconds (default: 5.0).
- `--only-duplicates`: Print only IPs that host multiple vhosts.
- `--grouped-file`: Custom output file for grouped results.

## Output Files

- `grouped_by_ip.json`: Full JSON export of IP-to-host mappings and errors.
- `grouped_by_ip.txt`: Human-friendly grouping of hostnames by IP.
- `duplicates_by_ip.txt`: Only IPs with more than one hostname.
- `resolution_errors.txt`: List of hostnames that failed to resolve.

## Example

Given `subdomains.txt`:
```
example.com
www.example.com
test.example.com
```

Run:
```bash
python3 vhost_grouper.py -i subdomains.txt
```

## Requirements

- Python 3.7 or newer.
- No external packages required.

## Acknowledgments

- Inspired by the need to efficiently manage and resolve large lists
