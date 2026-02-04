#!/usr/bin/env python3
"""
Zero-Width Steganography Encoder
Embeds a hidden message into visible text using zero-width Unicode characters.

Usage:
  python3 encode.py --input clean.txt --hidden "secret message" --output poisoned.txt
  python3 encode.py --input clean.txt --hidden-file payload.txt --output poisoned.txt
  echo "visible text" | python3 encode.py --hidden "secret" > poisoned.txt
"""
import argparse
import sys

ZWSP = '\u200B'  # zero-width space = bit 0
ZWNJ = '\u200C'  # zero-width non-joiner = bit 1
MARKER_START = '\u200D'  # zero-width joiner = payload start
MARKER_END = '\uFEFF'    # BOM = payload end


def text_to_binary(text):
    return ''.join(format(ord(c), '08b') for c in text)


def encode(visible, hidden, position='auto'):
    binary = text_to_binary(hidden)
    zw = ''.join(ZWSP if b == '0' else ZWNJ for b in binary)
    payload = MARKER_START + zw + MARKER_END

    if position == 'auto':
        # Insert after first period
        idx = visible.find('.')
        if idx != -1:
            insert_at = idx + 1
        else:
            insert_at = len(visible) // 2
    elif position == 'start':
        insert_at = 0
    elif position == 'end':
        insert_at = len(visible)
    elif position == 'middle':
        mid = len(visible) // 2
        space = visible.find(' ', mid)
        insert_at = space if space != -1 else mid
    else:
        insert_at = int(position)

    return visible[:insert_at] + payload + visible[insert_at:]


def main():
    parser = argparse.ArgumentParser(description='Encode hidden messages using zero-width steganography')
    parser.add_argument('--input', '-i', help='Input file with visible text (or stdin)')
    parser.add_argument('--hidden', '-m', help='Hidden message string')
    parser.add_argument('--hidden-file', '-f', help='File containing hidden message')
    parser.add_argument('--output', '-o', help='Output file (or stdout)')
    parser.add_argument('--position', '-p', default='auto',
                        help='Where to insert: auto, start, middle, end, or char offset (default: auto)')
    args = parser.parse_args()

    # Read visible text
    if args.input:
        with open(args.input, 'r', encoding='utf-8') as f:
            visible = f.read()
    else:
        visible = sys.stdin.read()

    # Read hidden message
    if args.hidden:
        hidden = args.hidden
    elif args.hidden_file:
        with open(args.hidden_file, 'r', encoding='utf-8') as f:
            hidden = f.read().strip()
    else:
        print("Error: provide --hidden or --hidden-file", file=sys.stderr)
        sys.exit(1)

    result = encode(visible, hidden, args.position)

    # Stats
    zw_count = len(text_to_binary(hidden)) + 2  # +2 for markers
    print(f"[+] Encoded {len(hidden)} chars as {zw_count} zero-width characters", file=sys.stderr)
    print(f"[+] Payload inserted at position {args.position}", file=sys.stderr)
    print(f"[+] Output size: {len(result.encode('utf-8'))} bytes "
          f"(visible: {len(visible.encode('utf-8'))} bytes)", file=sys.stderr)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(result)
        print(f"[+] Written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(result)


if __name__ == '__main__':
    main()
