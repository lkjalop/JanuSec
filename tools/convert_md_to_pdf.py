#!/usr/bin/env python3
"""Convert a Markdown file to PDF for distribution.

This script attempts to use WeasyPrint (recommended) to convert Markdown->HTML->PDF.
If WeasyPrint isn't available, it falls back to a minimal ReportLab-based renderer for plain text.

Usage:
  python tools/convert_md_to_pdf.py whitepapers/technical_deep_dive.md whitepapers/technical_deep_dive.pdf
"""
import sys
import os


def convert_with_weasy(md_path, pdf_path):
    try:
        import markdown
        from weasyprint import HTML
    except Exception as e:
        print('WeasyPrint not available:', e)
        return False

    with open(md_path, 'r', encoding='utf-8') as f:
        md = f.read()
    html = markdown.markdown(md, extensions=['fenced_code', 'tables'])
    HTML(string=html).write_pdf(pdf_path)
    return True


def convert_with_reportlab(md_path, pdf_path):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except Exception as e:
        print('ReportLab not available:', e)
        return False

    with open(md_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4
    y = height - 40
    for line in lines:
        text = line.rstrip('\n')
        if y < 60:
            c.showPage()
            y = height - 40
        c.drawString(40, y, text[:100])
        y -= 12
    c.save()
    return True


def main():
    if len(sys.argv) < 3:
        print('Usage: convert_md_to_pdf.py input.md output.pdf')
        sys.exit(2)
    md_path = sys.argv[1]
    pdf_path = sys.argv[2]
    if not os.path.exists(md_path):
        print('Input file not found:', md_path)
        sys.exit(2)

    if convert_with_weasy(md_path, pdf_path):
        print('Converted with WeasyPrint ->', pdf_path)
        return
    if convert_with_reportlab(md_path, pdf_path):
        print('Converted with ReportLab fallback ->', pdf_path)
        return

    print('No supported PDF converter available. Install WeasyPrint or ReportLab.')


if __name__ == '__main__':
    main()
