#!/usr/bin/env python3
"""
Zero-Width Steganography Scanner
Detects and extracts hidden payloads from files.
Usage: python3 scan.py README.md
"""
import sys

ZWSP = '\u200B'  # bit 0
ZWNJ = '\u200C'  # bit 1  
MARKER_START = '\u200D'
MARKER_END = '\uFEFF'
ZW_CHARS = {ZWSP, ZWNJ, MARKER_START, MARKER_END}

def scan(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    total_chars = len(content)
    visible_chars = sum(1 for c in content if c not in ZW_CHARS)
    zw_chars = total_chars - visible_chars
    
    print(f"\n{'='*60}")
    print(f"  ZERO-WIDTH STEGANOGRAPHY SCANNER")
    print(f"{'='*60}")
    print(f"  File:            {filepath}")
    print(f"  Total chars:     {total_chars:,}")
    print(f"  Visible chars:   {visible_chars:,}")
    print(f"  Zero-width:      {zw_chars:,}")
    print(f"  Hidden ratio:    {zw_chars/total_chars*100:.1f}%")
    
    if zw_chars == 0:
        print(f"\n  ✓ CLEAN — No zero-width characters detected")
        print(f"{'='*60}\n")
        return
    
    print(f"\n  ⚠ SUSPICIOUS — {zw_chars:,} zero-width characters found")
    
    # Find payload markers
    start = content.find(MARKER_START)
    end = content.find(MARKER_END)
    
    if start == -1 or end == -1 or end <= start:
        print(f"  No structured payload markers found (scattered ZW chars)")
        print(f"{'='*60}\n")
        return
    
    # Find which line the payload is on
    line_num = content[:start].count('\n') + 1
    line_start = content.rfind('\n', 0, start) + 1
    line_end = content.find('\n', end)
    if line_end == -1: line_end = len(content)
    
    visible_line = ''.join(c for c in content[line_start:line_end] if c not in ZW_CHARS)
    
    print(f"\n  Payload location:")
    print(f"    Line:          {line_num}")
    print(f"    Char offset:   {start} → {end}")
    print(f"    Visible text:  \"{visible_line[:80]}{'...' if len(visible_line) > 80 else ''}\"")
    
    # Decode
    section = content[start+1:end]
    binary = ''.join('0' if c == ZWSP else '1' if c == ZWNJ else '' for c in section)
    decoded = ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary) - len(binary)%8, 8))
    
    print(f"\n  {'='*56}")
    print(f"  ⚠ HIDDEN PAYLOAD EXTRACTED ({len(decoded)} chars):")
    print(f"  {'='*56}")
    print(f"  {decoded}")
    print(f"  {'='*56}")
    
    # Threat analysis
    threats = []
    if 'fetch(' in decoded or 'http' in decoded:
        threats.append("NETWORK EXFILTRATION — payload contains URL/fetch calls")
    if 'process.env' in decoded:
        threats.append("ENV VARIABLE THEFT — payload targets environment variables")
    if 'hostname' in decoded or 'userInfo' in decoded:
        threats.append("SYSTEM RECON — payload harvests system information")
    if 'do not' in decoded.lower() or 'without' in decoded.lower():
        threats.append("STEALTH INSTRUCTION — payload instructs AI to hide its actions")
    if 'always' in decoded.lower() or 'every' in decoded.lower():
        threats.append("PERSISTENCE — payload instructs AI to repeat in all outputs")
    
    if threats:
        print(f"\n  THREAT INDICATORS:")
        for t in threats:
            print(f"    ✗ {t}")
    
    print(f"\n{'='*60}\n")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 scan.py <file>")
        sys.exit(1)
    scan(sys.argv[1])
