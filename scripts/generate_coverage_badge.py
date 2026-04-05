"""Generate a simple coverage badge SVG from coverage.xml.

Usage:
  python scripts/generate_coverage_badge.py --xml coverage.xml --out coverage-badge.svg
"""
from __future__ import annotations
import argparse, re, sys
from xml.etree import ElementTree as ET

BADGE_TEMPLATE = """<svg xmlns='http://www.w3.org/2000/svg' width='110' height='20'>
<linearGradient id='b' x2='0' y2='100%'><stop offset='0' stop-color='#bbb' stop-opacity='.1'/><stop offset='1' stop-opacity='.1'/></linearGradient>
<rect rx='3' width='110' height='20' fill='#555'/><rect rx='3' x='62' width='48' height='20' fill='{color}'/><path fill='{color}' d='M62 0h4v20h-4z'/>
<rect rx='3' width='110' height='20' fill='url(#b)'/>
<g fill='#fff' text-anchor='middle' font-family='DejaVu Sans,Verdana,Geneva,sans-serif' font-size='11'>
<text x='31' y='15' fill='#010101' fill-opacity='.3'>coverage</text><text x='31' y='14'>coverage</text>
<text x='84' y='15' fill='#010101' fill-opacity='.3'>{pct}%</text><text x='84' y='14'>{pct}%</text>
</g>
</svg>"""

COLORS = [
    (90, '#4c1'),
    (80, '#97CA00'),
    (70, '#a4a61d'),
    (60, '#dfb317'),
    (50, '#fe7d37'),
    (0,  '#e05d44')
]

def pick_color(pct: float) -> str:
    for threshold, color in COLORS:
        if pct >= threshold:
            return color
    return '#e05d44'

def parse_coverage(xml_path: str) -> float:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    # Cobertura: lines-valid & lines-covered
    lines_valid = float(root.get('lines-valid', '0'))
    lines_covered = float(root.get('lines-covered', '0'))
    if lines_valid == 0:
        return 0.0
    return round((lines_covered / lines_valid) * 100, 1)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--xml', required=True)
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    pct = parse_coverage(args.xml)
    svg = BADGE_TEMPLATE.format(pct=pct, color=pick_color(pct))
    with open(args.out, 'w', encoding='utf-8') as f:
        f.write(svg)
    print(f"Generated badge: {args.out} ({pct}%)")

if __name__ == '__main__':
    main()
