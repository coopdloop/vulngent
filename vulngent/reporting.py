"""Render the markdown status report (see agents/tools.py::generate_status_report)
into other output formats for sharing with stakeholders who don't want a terminal
dump: PDF and DOCX today, plain markdown/text passthrough otherwise."""

from __future__ import annotations

SUPPORTED_FORMATS = ("md", "markdown", "txt", "pdf", "docx")

_ASCII_REPLACEMENTS = {
    "\u2014": "-",  # em dash
    "\u2013": "-",  # en dash
    "\u2018": "'",
    "\u2019": "'",
    "\u201c": '"',
    "\u201d": '"',
}


def _pdf_safe(text: str) -> str:
    for src, dst in _ASCII_REPLACEMENTS.items():
        text = text.replace(src, dst)
    return text


def render_report(markdown_text: str, fmt: str) -> str | bytes:
    """Render `markdown_text` (as produced by generate_status_report) into `fmt`.
    Returns str for md/markdown/txt, bytes for pdf/docx."""
    fmt = fmt.lower()
    if fmt in ("md", "markdown", "txt"):
        return markdown_text
    if fmt == "pdf":
        return _to_pdf(markdown_text)
    if fmt == "docx":
        return _to_docx(markdown_text)
    raise ValueError(f"Unsupported report format '{fmt}'. Must be one of {SUPPORTED_FORMATS}.")


def _to_pdf(markdown_text: str) -> bytes:
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    def _line(text: str, size: int, bold: bool = False) -> None:
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "B" if bold else "", size)
        pdf.multi_cell(0, 6 + (size > 11) * 2, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    for raw_line in markdown_text.splitlines():
        line = _pdf_safe(raw_line)
        if line.startswith("## "):
            pdf.ln(3)
            _line(line[3:], 14, bold=True)
        elif line.startswith("# "):
            _line(line[2:], 18, bold=True)
        elif line.startswith("- "):
            _line(f"  - {line[2:]}", 11)
        elif line.strip() == "":
            pdf.ln(2)
        else:
            _line(line, 11)

    return bytes(pdf.output())


def _to_docx(markdown_text: str) -> bytes:
    import io

    from docx import Document

    doc = Document()
    for line in markdown_text.splitlines():
        if line.startswith("## "):
            doc.add_heading(line[3:], level=2)
        elif line.startswith("# "):
            doc.add_heading(line[2:], level=1)
        elif line.startswith("- "):
            doc.add_paragraph(line[2:], style="List Bullet")
        elif line.strip() == "":
            continue
        else:
            doc.add_paragraph(line)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()
