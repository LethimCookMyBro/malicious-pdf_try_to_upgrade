#!/usr/bin/python
# -*- coding: UTF-8 -*-
##
## Generate malicious PDF/SVG test files with phone-home functionality
## Used for penetration testing and/or red-teaming etc.
##
## Usage: python3 malicious-pdf.py <callback-url>
##
## Output will be written to the output/ directory as test1.pdf, test2.pdf, etc.
##
## Based on https://github.com/modzero/mod0BurpUploadScanner/ and https://github.com/deepzec/Bad-Pdf
##
## Jonas Lejon, 2023-2026 <jonas.github@triop.se>
## https://github.com/jonaslejon/malicious-pdf

import argparse
import sys
from pathlib import Path

from malicious_pdf import __version__
from malicious_pdf.catalog import FILE_EXTENSIONS, selected_test_cases
from malicious_pdf.credit import inject_credit
from malicious_pdf.obfuscation import obfuscate_pdf
from malicious_pdf.utils import validate_url_or_ip_validators


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Generate malicious PDF/SVG test files with phone-home functionality "
            "for penetration testing. Covers URI actions, JavaScript execution, "
            "form submission, annotation injection, widget-based XSS, content "
            "extraction, XXE, CSP bypass, and more. Use with Burp Collaborator "
            "or Interact.sh to detect callbacks."
        )
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("host", help="Callback URL or IP address (e.g. https://burp-collaborator-url)")
    parser.add_argument("--output-dir", default="output", help="Directory to save generated files (default: output/)")
    parser.add_argument("--no-credit", action="store_true", help="Do not embed credit/attribution metadata in generated PDFs")
    parser.add_argument(
        "--obfuscate",
        type=int,
        choices=range(0, 10),
        default=0,
        metavar="LEVEL",
        help=(
            "Obfuscation level 0-9: 0=none (default), 1=name/string encoding, "
            "2=+JS/XSS obfuscation, 3=+stream compression, 4=+JS payload staging, "
            "5=+unescape encoding, 6=+fake file header, 7=+anti-emulation checks, "
            "8=+best-effort empty-password encryption, 9=+best-effort object streams"
        ),
    )
    parser.add_argument(
        "--profile",
        choices=["all", "acrobat", "browser", "server-side", "ntlm", "stealth"],
        default="all",
        help="Generate a specific subset of test cases",
    )
    parser.add_argument(
        "--include-eicar",
        action="store_true",
        help="Include test11.pdf with the EICAR antivirus test string. This intentionally triggers antivirus products.",
    )
    parser.add_argument("--list-tests", action="store_true", help="List selected test files without writing payload files")
    return parser.parse_args()


def remove_stale_eicar(output_dir):
    try:
        (output_dir / "test11.pdf").unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


def main():
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not validate_url_or_ip_validators(args.host):
        print("Error: Invalid URL or IP address. Input must have a scheme (e.g. https://) or be a valid IP address.")
        sys.exit(1)

    test_cases = selected_test_cases(args.host, profile=args.profile, include_eicar=args.include_eicar)
    if not args.include_eicar:
        remove_stale_eicar(output_dir)

    obfuscate_level = args.obfuscate
    if args.profile == "stealth" and obfuscate_level < 3:
        obfuscate_level = 3
        if not args.list_tests:
            print("[+] Stealth profile: auto-setting obfuscation level 3")

    if args.list_tests:
        for test_case in test_cases:
            print(test_case.filename)
        return

    print("[+] Creating PDF files..")
    if args.profile != "all":
        print(f"[+] Profile '{args.profile}': generating {len(test_cases)} test(s)")

    for test_case in test_cases:
        filename = output_dir / test_case.filename
        if test_case.description:
            print(f"    [*] {test_case.filename} - {test_case.description}")
        else:
            print(f"    [*] {test_case.filename}")
        if test_case.content is None:
            test_case.generator(filename)
        else:
            test_case.generator(filename, test_case.content)

    if not args.no_credit:
        inject_credit(output_dir, FILE_EXTENSIONS)

    if obfuscate_level > 0:
        print(f"[+] Applying obfuscation level {obfuscate_level}...")
        for filepath in output_dir.iterdir():
            if filepath.suffix == ".pdf":
                obfuscate_pdf(filepath, obfuscate_level)

    print("[-] Done!")


if __name__ == "__main__":
    if sys.version_info[0] < 3:
        raise SystemExit("Use Python 3 (or higher) only")
    main()
