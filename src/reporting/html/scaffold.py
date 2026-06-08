from __future__ import annotations

from html import escape


def wrap_page(title_esc: str, body: str, accent: str) -> str:
    css = (
        'body{background:#0c1520;color:#e0e0e0;font-family:Segoe UI,Arial,sans-serif;'
        'padding:24px;max-width:1200px;margin:0 auto}'
        'h2,h3,h4{color:#e6eef8}table{width:100%;border-collapse:collapse;table-layout:fixed}'
        'th{text-align:left;padding:5px 8px;border-bottom:1px solid #243144;color:#9bb;font-size:11px;text-transform:uppercase}'
        'td{padding:5px 8px;border-bottom:1px solid #0e1722;overflow-wrap:break-word}'
        'a{color:#5b9bd5}pre{overflow-x:auto;background:#0a1018;padding:10px;border-radius:6px}'
        'details>summary{cursor:pointer;padding:8px 12px;font-size:12px;font-weight:600}'
        f'details{{border:1px solid {accent}44;border-radius:6px;margin-top:14px}}'
        '.pill{display:inline-block;padding:2px 9px;border-radius:12px;font-size:11px;margin:2px}'
        '.section{margin-top:18px;padding:16px;background:#0e1828;border-left:4px solid '
        + accent + ';border-radius:6px}'
        '.warn{padding:12px 16px;border-radius:6px;margin-bottom:14px}'
        '.stat-bar{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}'
        '.stat{padding:10px 16px;border-radius:6px;background:#0d1620;flex:1;min-width:90px;text-align:center}'
        '.stat .n{font-size:24px;font-weight:700}'
        '.stat .l{font-size:11px;color:#9bb}'
    )
    return (
        f'<!doctype html><html><head><meta charset="utf-8"><title>{title_esc}</title>'
        f'<style>{css}</style></head><body>{body}</body></html>'
    )


def page_header(label: str, verdict: str, confidence: str, company: str,
                session: str, generated_at: str, accent: str) -> str:
    conf_part = f' — {escape(confidence)}%' if confidence else ''
    co_part = f'<strong style="color:#e6eef8">{escape(company)}</strong> &nbsp;·&nbsp; ' if company else ''
    return (
        f'<div style="border-bottom:3px solid {accent};padding-bottom:12px;margin-bottom:18px">'
        f'<h2 style="margin:0;color:{accent};letter-spacing:.03em">{escape(label)}{conf_part}</h2>'
        f'<div style="font-size:13px;font-weight:700;color:#e74c3c;margin-top:6px">'
        f'{escape(verdict)}</div>'
        f'<div style="color:#9bb;font-size:11px;margin-top:4px">'
        f'{co_part}Session: <code>{escape(str(session))}</code>'
        f' &nbsp;·&nbsp; Generated: {generated_at}</div>'
        f'</div>'
    )


def stat_bar(items: list) -> str:
    parts = ['<div class="stat-bar">']
    for n, lbl, clr in items:
        parts.append(f'<div class="stat"><div class="n" style="color:{clr}">{escape(str(n))}</div>'
                     f'<div class="l">{escape(lbl)}</div></div>')
    parts.append('</div>')
    return '\n'.join(parts)


def collapsible(summary_label: str, body_html: str, accent: str) -> str:
    return (f'<details style="border:1px solid {accent}44;border-radius:6px;margin-top:14px">'
            f'<summary style="padding:8px 12px;color:{accent};font-weight:600;font-size:12px">'
            f'{escape(summary_label)}</summary>'
            f'<div style="padding:12px">{body_html}</div></details>')


def table(headers: list, rows_html: list, style: str = '') -> str:
    ths = ''.join(f'<th>{escape(h)}</th>' for h in headers)
    return (f'<table style="{style}"><thead><tr>{ths}</tr></thead>'
            f'<tbody>{"".join(rows_html)}</tbody></table>')


def td(val, mono: bool = False, clr: str = '', align: str = 'left') -> str:
    s = f'text-align:{align};'
    if clr:
        s += f'color:{clr};'
    if mono:
        s += 'font-family:monospace;font-size:11px;'
    return f'<td style="{s}">{escape(str(val))}</td>'


__all__ = ["wrap_page", "page_header", "stat_bar", "collapsible", "table", "td"]
