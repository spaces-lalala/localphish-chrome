"""Render a Markdown report to PDF.

pandoc converts md -> standalone HTML (GFM tables, TOC-friendly anchors),
then Playwright Chromium prints it to PDF. Chromium handles 繁中 fonts and
wide tables far better than LaTeX-based pandoc PDF output, and we already
ship Playwright for Tier B/C.

Usage:
    cd eval
    uv run python build_report_pdf.py ../docs/Group107_final_report.md
    # writes ../docs/Group107_final_report.pdf next to the source file
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

CSS = """
@page { size: A4; margin: 18mm 16mm; }
html { -webkit-print-color-adjust: exact; }
body {
  font-family: "Noto Sans TC", "Microsoft JhengHei", "Segoe UI", sans-serif;
  font-size: 10.5pt; line-height: 1.55; color: #1a1a1a;
  max-width: 100%; margin: 0;
}
h1 { font-size: 17pt; border-bottom: 2px solid #333; padding-bottom: 4px; }
h2 { font-size: 14pt; border-bottom: 1px solid #999; padding-bottom: 3px;
     margin-top: 1.6em; }
h3 { font-size: 12pt; margin-top: 1.3em; }
h2, h3 { page-break-after: avoid; }
code, pre {
  font-family: "Cascadia Mono", Consolas, "Courier New", monospace;
  font-size: 8.8pt;
}
code { background: #f2f2f2; padding: 0 3px; border-radius: 3px; }
pre {
  background: #f7f7f7; border: 1px solid #ddd; border-radius: 4px;
  padding: 8px 10px; overflow-x: hidden;
  white-space: pre-wrap; word-break: break-all;
}
pre code { background: none; padding: 0; }
table {
  border-collapse: collapse; width: 100%; margin: 0.8em 0;
  font-size: 9pt; page-break-inside: avoid;
}
th, td {
  border: 1px solid #bbb; padding: 4px 7px; text-align: left;
  word-break: break-word;
}
th { background: #efefef; }
blockquote {
  border-left: 4px solid #c9a227; background: #fdf8e8;
  margin: 0.8em 0; padding: 6px 12px; color: #444;
}
a { color: #0a58a3; text-decoration: none; word-break: break-all; }
hr { border: none; border-top: 1px solid #ccc; margin: 1.5em 0; }
img { max-width: 100%; }
"""


def md_to_html(md_path: Path) -> str:
    result = subprocess.run(
        [
            "pandoc",
            str(md_path),
            "--from", "gfm+tex_math_dollars",
            "--to", "html5",
            "--standalone",
            "--metadata", f"title={md_path.stem}",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    html = result.stdout
    # Drop pandoc's auto title header; the report has its own H1.
    html = html.replace('<h1 class="title">' + md_path.stem + "</h1>", "")
    return html.replace("</head>", f"<style>{CSS}</style></head>", 1)


def html_to_pdf(html: str, pdf_path: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        html_file = Path(tmp) / "report.html"
        html_file.write_text(html, encoding="utf-8")
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(html_file.as_uri(), wait_until="networkidle")
            page.pdf(
                path=str(pdf_path),
                format="A4",
                print_background=True,
                margin={"top": "0", "bottom": "0", "left": "0", "right": "0"},
            )
            browser.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("markdown", type=Path, help="source .md file")
    parser.add_argument(
        "-o", "--output", type=Path, default=None,
        help="output .pdf path (default: alongside the source)",
    )
    args = parser.parse_args()

    md_path: Path = args.markdown.resolve()
    if not md_path.is_file():
        print(f"not a file: {md_path}", file=sys.stderr)
        return 1
    pdf_path = args.output or md_path.with_suffix(".pdf")

    html = md_to_html(md_path)
    html_to_pdf(html, pdf_path)
    size_kb = pdf_path.stat().st_size // 1024
    print(f"wrote {pdf_path} ({size_kb} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
