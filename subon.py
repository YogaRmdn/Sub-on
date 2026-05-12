#!/usr/bin/env python3
"""
Sub-on - Professional Subdomain Active Checker
Powerful wrapper around projectdiscovery/httpx
github.com/Yogarmdn
"""

import argparse
import csv
import json
import logging
import subprocess as sub
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from colorama import Fore, Style, init

init(autoreset=True)

log = logging.getLogger("subon")

BANNER = f"""
{Fore.RED} _____     _       _____
|   __|_ _| |_ ___|     |___
|__   | | | . |___|  |  |   |
|_____|___|___|   |_____|_|_|
{Fore.YELLOW}github.com/Yogarmdn{Style.RESET_ALL}
"""

STATUS_COLORS = {2: Fore.GREEN, 3: Fore.CYAN, 4: Fore.YELLOW, 5: Fore.RED}


def colorize_status(code: int) -> str:
    color = STATUS_COLORS.get(code // 100, Fore.WHITE)
    return f"{color}{code}{Style.RESET_ALL}"


class SubdomainChecker:
    def __init__(
        self,
        target: str,
        output: Optional[str] = None,
        threads: int = 50,
        status_code: bool = False,
        title: bool = False,
        tech_detect: bool = False,
        content_type: bool = False,
        response_time: bool = False,
        method: str = "GET",
        timeout: int = 5,
        max_redirects: int = 5,
        follow_redirects: bool = False,
        output_format: str = "txt",
        silent: bool = False,
        verbose: bool = False,
        retries: int = 2,
        json_output: bool = False,
        filter_codes: Optional[str] = None,
        probe_all: bool = False,
        store_resp: bool = False,
        extract_title: bool = False,
    ):
        self.target = target
        self.output = output
        self.threads = threads
        self.show_status = status_code
        self.show_title = title
        self.show_tech = tech_detect
        self.show_content_type = content_type
        self.show_response_time = response_time
        self.method = method
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.follow_redirects = follow_redirects
        self.output_format = output_format
        self.silent = silent
        self.verbose = verbose
        self.retries = retries
        self.json_output = json_output
        self.filter_codes = filter_codes
        self.probe_all = probe_all
        self.store_resp = store_resp
        self.extract_title = extract_title

        self.results: List[Dict[str, Any]] = []
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None

    def _build_httpx_cmd(self) -> List[str]:
        cmd = ["httpx", "-l", self.target, "-silent"]

        opts = {
            "-sc": self.show_status,
            "-title": self.show_title,
            "-tech-detect": self.show_tech,
            "-content-type": self.show_content_type,
            "-response-time": self.show_response_time,
            "-follow-redirects": self.follow_redirects,
            "-probe-all-ips": self.probe_all,
            "-store-response": self.store_resp,
            "-extract-title": self.extract_title,
        }
        for flag, enabled in opts.items():
            if enabled:
                cmd.append(flag)

        if self.filter_codes:
            cmd.extend(["-mc", self.filter_codes])

        cmd.extend(["-x", self.method])
        cmd.extend(["-timeout", str(self.timeout)])
        cmd.extend(["-max-redirects", str(self.max_redirects)])
        cmd.extend(["-retries", str(self.retries)])

        if self.json_output:
            cmd.append("-json")

        return cmd

    def run(self) -> None:
        self.start_time = time.time()

        if not self.silent:
            print(BANNER)

        cmd = self._build_httpx_cmd()

        if self.verbose:
            logging.basicConfig(
                level=logging.INFO,
                format=f"{Fore.CYAN}[%(asctime)s]{Style.RESET_ALL} %(message)s",
                datefmt="%H:%M:%S",
            )
            log.info(f"Running: {' '.join(cmd)}")

        try:
            result = sub.run(cmd, capture_output=True, text=True, timeout=600)
        except sub.TimeoutExpired:
            log.error("httpx timed out (600s limit)")
            sys.exit(1)
        except FileNotFoundError:
            log.error(
                "httpx not found! Install from https://github.com/projectdiscovery/httpx"
            )
            sys.exit(1)
        except Exception as e:
            log.error(f"Error running httpx: {e}")
            sys.exit(1)

        if result.returncode != 0 and result.stderr and not self.silent:
            log.warning(f"httpx stderr: {result.stderr.strip()}")

        stdout = result.stdout.strip()
        if not stdout:
            if not self.silent:
                log.warning("No active subdomains found")
            self.end_time = time.time()
            self._show_summary()
            return

        self._parse_results(stdout)

        if not self.silent:
            self._display_results()

        self.end_time = time.time()
        self._show_summary()
        self._save_output()

    def _parse_results(self, data: str) -> None:
        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            if self.json_output:
                try:
                    self.results.append(json.loads(line))
                except json.JSONDecodeError:
                    if not self.silent:
                        log.warning(f"Skipping invalid JSON line: {line[:60]}")
            else:
                self.results.append({"url": line})

    def _display_results(self) -> None:
        for i, entry in enumerate(self.results, start=1):
            parts = []

            if "url" in entry:
                parts.append(f"{Fore.GREEN}[{i}]{Style.RESET_ALL} {entry['url']}")
            elif "raw" in entry:
                parts.append(f"{Fore.GREEN}[{i}]{Style.RESET_ALL} {entry['raw']}")

            if self.show_status and "status_code" in entry:
                parts.append(colorize_status(entry["status_code"]))

            if self.show_response_time and "response_time" in entry:
                rt = entry.get("response_time", "")
                parts.append(f"{Fore.MAGENTA}[{rt}ms]{Style.RESET_ALL}")

            if self.show_title and "title" in entry:
                title = entry.get("title", "")
                if title:
                    parts.append(f"{Fore.BLUE}[{title}]{Style.RESET_ALL}")

            if self.show_tech and "technologies" in entry:
                techs = entry.get("technologies", [])
                if techs:
                    parts.append(
                        f"{Fore.YELLOW}[{', '.join(techs)}]{Style.RESET_ALL}"
                    )

            if self.show_content_type and "content_type" in entry:
                ct = entry.get("content_type", "")
                if ct:
                    parts.append(f"{Fore.CYAN}[{ct}]{Style.RESET_ALL}")

            print(" ".join(parts))

    def _show_summary(self) -> None:
        if self.silent:
            return
        elapsed = (self.end_time - self.start_time) if self.end_time else 0
        print(f"\n{Fore.GREEN}{'=' * 50}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Total active subdomains: {len(self.results)}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Time elapsed: {elapsed:.2f}s{Style.RESET_ALL}")
        if self.output:
            print(f"{Fore.GREEN}[+] Output saved: {self.output}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'=' * 50}{Style.RESET_ALL}")

    def _save_output(self) -> None:
        if not self.output:
            return

        ext = Path(self.output).suffix.lower()
        if ext == ".csv" or self.output_format == "csv":
            self._save_csv()
        elif ext == ".json" or self.output_format == "json":
            self._save_json()
        else:
            self._save_txt()

    def _save_txt(self) -> None:
        with open(self.output, "w") as f:
            for entry in self.results:
                f.write(entry.get("url", entry.get("raw", "")) + "\n")

    def _save_csv(self) -> None:
        if not self.results:
            return
        fieldnames = set()
        for r in self.results:
            fieldnames.update(
                k for k, v in r.items() if not isinstance(v, (dict, list))
            )
        with open(self.output, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
            writer.writeheader()
            for r in self.results:
                flat = {k: v for k, v in r.items() if not isinstance(v, (dict, list))}
                writer.writerow(flat)

    def _save_json(self) -> None:
        with open(self.output, "w") as f:
            json.dump(self.results, f, indent=2)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sub-on - Professional Subdomain Active Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  subon.py -t targets.txt
  subon.py -t targets.txt -sc -title -tech
  subon.py -t targets.txt -sc -title -o results.json
  subon.py -t targets.txt -mc 200,302 -sc -title
  subon.py -t targets.txt -follow -X HEAD -timeout 10
        """,
    )

    in_out = parser.add_argument_group("Input / Output")
    in_out.add_argument("-t", "--target", required=True, help="Target file containing subdomains")
    in_out.add_argument("-o", "--output", help="Output file path")

    info = parser.add_argument_group("Information")
    info.add_argument("-sc", "--status-code", action="store_true", help="Show HTTP status code")
    info.add_argument("-title", "--title", action="store_true", help="Show page title")
    info.add_argument("-tech", "--tech-detect", action="store_true", help="Detect web technologies")
    info.add_argument("-ct", "--content-type", action="store_true", help="Show content type")
    info.add_argument("-rt", "--response-time", action="store_true", help="Show response time")
    info.add_argument("-et", "--extract-title", action="store_true", help="Extract page title")

    req = parser.add_argument_group("Request")
    req.add_argument("-X", "--method", default="GET", help="HTTP method (default: GET)")
    req.add_argument("-follow", "--follow-redirects", action="store_true", help="Follow redirects")
    req.add_argument("-timeout", type=int, default=5, help="Timeout in seconds (default: 5)")
    req.add_argument("-maxr", "--max-redirects", type=int, default=5, help="Max redirects (default: 5)")
    req.add_argument("-retries", type=int, default=2, help="Retries on failure (default: 2)")
    req.add_argument("-mc", "--filter-codes", help="Match status codes (e.g. 200,302)")

    probe = parser.add_argument_group("Probe")
    probe.add_argument("-probe-all", "--probe-all-ips", action="store_true", help="Probe all IPs")
    probe.add_argument("-store", "--store-response", action="store_true", help="Store HTTP responses")

    output_group = parser.add_argument_group("Output Format")
    output_group.add_argument("-f", "--format", choices=["txt", "json", "csv"], help="Output format")
    output_group.add_argument("-json", "--json-output", action="store_true", help="Use JSON output from httpx")

    misc = parser.add_argument_group("Misc")
    misc.add_argument("-s", "--silent", action="store_true", help="Silent mode (no banner/output)")
    misc.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    target_path = Path(args.target)
    if not target_path.exists():
        log.error(f"Target file not found: {args.target}")
        sys.exit(1)

    output = args.output
    if output:
        out_path = Path(output)
        if out_path.exists() and not args.silent:
            log.warning(f"Output file exists, will be overwritten: {output}")

    checker = SubdomainChecker(
        target=args.target,
        output=output,
        status_code=args.status_code,
        title=args.title,
        tech_detect=args.tech_detect,
        content_type=args.content_type,
        response_time=args.response_time,
        method=args.method,
        timeout=args.timeout,
        max_redirects=args.max_redirects,
        follow_redirects=args.follow_redirects,
        output_format=args.format or "txt",
        silent=args.silent,
        verbose=args.verbose,
        retries=args.retries,
        json_output=args.json_output,
        filter_codes=args.filter_codes,
        probe_all=args.probe_all_ips,
        store_resp=args.store_response,
        extract_title=args.extract_title,
    )

    checker.run()


if __name__ == "__main__":
    main()
