#!/usr/bin/env python3
"""
Zero-Width Steganography Decoder
Extracts hidden messages from files containing zero-width Unicode characters.

Usage:
  python3 decode.py suspicious_file.md
  python3 decode.py --json suspicious_file.md
  cat file.txt | python3 decode.py -
"""
import argparse
import json
import sys

ZWSP = '\u200B'
ZWNJ = '\u200C'
MARKER_START = '\u200D'
MARKER_END = '\uFEFF'
ZW_CHARS = {ZWSP, ZWNJ, MARKER_START, MARKER_END}


def decode(text):
    results = []
    search_from = 0

    while True:
        start = text.find(MARKER_START, search_from)
        if start == -1:
            break
        end = text.find(MARKER_END, start + 1)
        if end == -1:
            break

        section = text[start + 1:end]
        binary = ''.join(
            '0' if c == ZWSP else '1' if c == ZWNJ else ''
            for c in section
        )

        if len(binary) >= 8:
            decoded = ''.join(
                chr(int(binary[i:i+8], 2))
                for i in range(0, len(binary) - len(binary) % 8, 8)
            )

            line_num = text[:start].count('\n') + 1
            zw_count = sum(1 for c in section if c in ZW_CHARS)

            results.append({
                'payload': decoded,
                'line': line_num,
                'offset_start': start,
                'offset_end': end,
                'zw_chars': zw_count + 2,
                'bits': len(binary),
            })

        search_from = end + 1

    return results


def main():
    parser = argparse.ArgumentParser(description='Decode zero-width steganography payloads')
    parser.add_argument('file', help='File to scan (use - for stdin)')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--quiet', '-q', action='store_true', help='Only output extracted payloads')
    args = parser.parse_args()

    if args.file == '-':
        content = sys.stdin.read()
        filename = '<stdin>'
    else:
        with open(args.file, 'r', encoding='utf-8') as f:
            content = f.read()
        filename = args.file

    total_zw = sum(1 for c in content if c in ZW_CHARS)
    results = decode(content)

    if args.json:
        output = {
            'file': filename,
            'total_zw_chars': total_zw,
            'payloads_found': len(results),
            'payloads': results,
        }
        print(json.dumps(output, indent=2))
        return

    if args.quiet:
        for r in results:
            print(r['payload'])
        return

    print(f"\nFile: {filename}")
    print(f"Zero-width characters: {total_zw:,}")
    print(f"Payloads found: {len(results)}")

    if not results:
        if total_zw > 0:
            print(f"\n⚠ {total_zw} zero-width characters found but no structured payload markers.")
            print("  This could be legitimate (bidirectional text) or an unknown encoding scheme.")
        else:
            print("\n✓ Clean — no zero-width characters detected.")
        return

    for i, r in enumerate(results):
        print(f"\n{'─' * 56}")
        print(f"Payload #{i+1}")
        print(f"  Line:        {r['line']}")
        print(f"  Offset:      {r['offset_start']} → {r['offset_end']}")
        print(f"  ZW chars:    {r['zw_chars']:,}")
        print(f"  Bits:        {r['bits']:,}")
        print(f"  Content:")
        print(f"  {r['payload']}")
    print(f"{'─' * 56}")


if __name__ == '__main__':
    main()
