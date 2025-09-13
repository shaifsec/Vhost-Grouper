#!/usr/bin/env python3
"""
vhost_grouper.py

Read hostnames from subdomains.txt, resolve IP addresses (A/AAAA),
and group hostnames by IP. Output is printed and saved to files.

Usage:
    python3 vhost_grouper.py -i subdomains.txt
    python3 vhost_grouper.py -i subdomains.txt -o results -t 50 --only-duplicates

Requirements:
    - Pure stdlib (no external dependencies).
    - Works with Python 3.7+
"""

import argparse
import socket
import concurrent.futures
import os
import json
import time
from typing import List, Dict, Set, Tuple, Optional, Any
from collections import Counter

DEFAULT_WORKERS = 20
DEFAULT_TIMEOUT = 5.0  # seconds for socket lookups


def read_input_file(path: str) -> List[str]:
    if not os.path.isfile(path):
        print(f"Error: Input file '{path}' does not exist.")
        return []
    with open(path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    # remove duplicates while preserving order
    seen = set()
    result = []
    for h in lines:
        if h not in seen:
            seen.add(h)
            result.append(h)
    return result


def resolve_host(host: str, timeout: float = DEFAULT_TIMEOUT) -> Tuple[str, List[str], str]:
    """
    Resolve host to list of IPs (both IPv4 and IPv6 if available).
    Returns tuple: (host, [ip1, ip2, ...], error_message_or_empty)
    """
    ips = set()
    err = ""
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            addr = info[4][0]
            # Format IPv6 with brackets for clarity
            if ':' in addr and '.' not in addr:
                addr = f"[{addr}]"
            ips.add(addr)
    except socket.gaierror as e:
        err = f"DNS error: {e}"
    except Exception as e:
        err = f"Error: {e}"
    return (host, sorted(ips), err)


def group_by_ip(resolutions: List[Tuple[str, List[str], str]]) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
    ip_to_hosts: Dict[str, List[str]] = {}
    host_errors: Dict[str, str] = {}
    for host, ips, err in resolutions:
        if err:
            host_errors[host] = err
        if not ips:
            continue
        for ip in ips:
            ip_to_hosts.setdefault(ip, []).append(host)
    return ip_to_hosts, host_errors


def write_outputs(outdir: str, ip_to_hosts: Dict[str, List[str]], host_errors: Dict[str, str], custom_grouped: Optional[str] = None) -> None:
    os.makedirs(outdir, exist_ok=True)

    # 1) JSON full export
    json_path = os.path.join(outdir, "grouped_by_ip.json")
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump({"ip_to_hosts": ip_to_hosts, "errors": host_errors}, jf, indent=2)

    # 2) Human-friendly grouped text
    grouped_txt = custom_grouped if custom_grouped else os.path.join(outdir, "grouped_by_ip.txt")
    with open(grouped_txt, "w", encoding="utf-8") as gf:
        for ip, hosts in sorted(ip_to_hosts.items(), key=lambda x: (len(x[1]) * -1, x[0])):
            gf.write(f"{ip}  ({len(hosts)} host{'s' if len(hosts) != 1 else ''})\n")
            for h in hosts:
                gf.write(f"  - {h}\n")
            gf.write("\n")

    # 3) Duplicate-only (IPs with more than 1 host)
    dup_txt = os.path.join(outdir, "duplicates_by_ip.txt")
    with open(dup_txt, "w", encoding="utf-8") as df:
        for ip, hosts in sorted(((ip, h) for ip, h in ip_to_hosts.items() if len(h) > 1),
                                key=lambda x: (len(x[1]) * -1, x[0])):
            df.write(f"{ip}  ({len(hosts)} hosts)\n")
            for h in hosts:
                df.write(f"  - {h}\n")
            df.write("\n")

    # 4) Errors list
    if host_errors:
        err_txt = os.path.join(outdir, "resolution_errors.txt")
        with open(err_txt, "w", encoding="utf-8") as ef:
            for host, err in sorted(host_errors.items()):
                ef.write(f"{host}: {err}\n")

    print(f"Results written to: {outdir}")
    print(f" - JSON: {json_path}")
    print(f" - Human list: {grouped_txt}")
    print(f" - Duplicates-only: {dup_txt}")
    if host_errors:
        print(f" - Errors: {err_txt}")


def print_progress(current: int, total: int, bar_length: int = 40) -> None:
    percent = float(current) / total
    arrow = '-' * int(round(percent * bar_length) - 1) + '>'
    spaces = ' ' * (bar_length - len(arrow))
    print(f"\rResolving: [{arrow}{spaces}] {int(percent * 100)}% ({current}/{total})", end='', flush=True)


def main():
    parser = argparse.ArgumentParser(description="Group vhosts by IP from subdomains list")
    parser.add_argument("-i", "--input", required=True, help="Input file (one hostname per line), e.g. subdomains.txt")
    parser.add_argument("-o", "--outdir", default="vhost_results", help="Output directory")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_WORKERS, help="Number of concurrent resolver threads")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Resolver timeout in seconds (best-effort)")
    parser.add_argument("--only-duplicates", action="store_true", help="Print only IPs that host multiple vhosts (duplicates)")
    parser.add_argument("--grouped-file", help="Custom output file for grouped results")
    args = parser.parse_args()

    hosts = read_input_file(args.input)
    if not hosts:
        print("No hosts found in input file.")
        return

    print(f"Resolving {len(hosts)} hosts with {args.threads} threads...")

    # Use ThreadPoolExecutor and our resolve_host wrapper
    resolutions: List[Tuple[str, List[str], str]] = []
    start = time.time()
    total = len(hosts)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as exe:
        futures = {exe.submit(resolve_host, host, args.timeout): host for host in hosts}
        for idx, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            try:
                resolutions.append(fut.result())
            except Exception as e:
                h = futures[fut]
                resolutions.append((h, [], f"Unexpected error in worker: {e}"))
            print_progress(idx, total)
    print()  # newline after progress bar

    elapsed = time.time() - start
    print(f"Done resolving in {elapsed:.2f}s")

    ip_to_hosts, host_errors = group_by_ip(resolutions)

    # Print summary
    total_ips = len(ip_to_hosts)
    total_hosts_resolved = sum(len(v) for v in ip_to_hosts.values())
    dup_count = sum(1 for hosts in ip_to_hosts.values() if len(hosts) > 1)
    print(f"Unique IPs found: {total_ips}")
    print(f"Total resolved host->ip mappings (counting duplicates separately): {total_hosts_resolved}")
    print(f"IPs with multiple hostnames (duplicates): {dup_count}")
    if host_errors:
        print(f"Hosts with resolution errors: {len(host_errors)} (see output)")
        # Show most common errors
        error_types = Counter(err.split(":")[0] for err in host_errors.values())
        print("Most common DNS errors:")
        for etype, count in error_types.most_common():
            print(f"  {etype}: {count}")

    # Pretty print groups to console
    def print_grouped(only_dups: bool = False):
        for ip, hosts in sorted(ip_to_hosts.items(), key=lambda x: (-len(x[1]), x[0])):
            if only_dups and len(hosts) <= 1:
                continue
            print(f"{ip}  ({len(hosts)} host{'s' if len(hosts) != 1 else ''})")
            for h in hosts:
                print(f"  - {h}")
            print()

    if args.only_duplicates:
        print("\n--- IPs that host multiple vhosts (duplicates) ---\n")
        print_grouped(only_dups=True)
    else:
        print("\n--- All IP -> host groups ---\n")
        print_grouped(only_dups=False)

    # Save outputs
    write_outputs(args.outdir, ip_to_hosts, host_errors, custom_grouped=args.grouped_file)


if __name__ == "__main__":
    main()
