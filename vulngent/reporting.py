"""Render a ReportData snapshot (see report_data.py) into shareable formats: a
branded, minimalist PDF built for stakeholders/leadership, a DOCX for teams that
edit reports before circulating them, and plain markdown/text passthrough for
piping/diffing. Whitelabeling (company name, logo, accent color, footer) comes
from Settings (REPORT_* env vars) via ReportData.branding.
"""

from __future__ import annotations

from vulngent.report_data import ReportData

SUPPORTED_FORMATS = ("md", "markdown", "txt", "pdf", "docx")

SEVERITY_COLORS = {
    "critical": "#DC2626",
    "high": "#EA580C",
    "medium": "#D97706",
    "low": "#65A30D",
    "info": "#64748B",
}
INK = "#111827"
MUTED = "#6B7280"
HAIRLINE = "#E5E7EB"
PANEL_BG = "#F8FAFC"

_ASCII_TRANSLIT = {
    "\u2014": "-",  # em dash
    "\u2013": "-",  # en dash
    "\u2018": "'",
    "\u2019": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u2022": "-",  # bullet
    "\u00a0": " ",  # nbsp
    "\u2026": "...",
}


def _pdf_safe(text: str) -> str:
    """Core PDF fonts (Helvetica) are latin-1 only, but branding fields (company
    name, footer, custom titles) and scanner-sourced vuln titles/descriptions are
    arbitrary Unicode. Transliterate common punctuation, then hard-fallback any
    remaining unsupported character rather than crashing the export."""
    for src, dst in _ASCII_TRANSLIT.items():
        text = text.replace(src, dst)
    try:
        text.encode("latin-1")
    except UnicodeEncodeError:
        text = text.encode("latin-1", errors="replace").decode("latin-1")
    return text


def render_markdown(data: ReportData) -> str:
    lines = [f"# {data.branding.title}", ""]
    lines.append(f"Prepared for {data.branding.company_name} · Generated {data.generated_at:%Y-%m-%d %H:%M UTC}")
    lines.append("")
    lines.append(f"Open: {data.open_count}  In progress: {data.in_progress_count}")
    lines.append("")
    lines.append("## By severity")
    for sev, count in data.by_severity.items():
        lines.append(f"- {sev}: {count}")
    lines.append("")
    lines.append("## Top priority")
    for v in data.top_vulns:
        lines.append(f"- #{v.id} [{v.severity}] {v.external_id} — {v.title} (score={v.priority_score})")
    lines.append("")
    lines.append(f"## Commitments due within 7 days")
    for c in data.commitments_due:
        lines.append(f"- vuln #{c.vulnerability_id} ({c.vulnerability_external_id}): {c.description} (due {c.due_date})")
    return "\n".join(lines)


def render_report(data: ReportData, fmt: str) -> str | bytes:
    """Render `data` into `fmt`. Returns str for md/markdown/txt, bytes for pdf/docx."""
    fmt = fmt.lower()
    if fmt in ("md", "markdown", "txt"):
        return render_markdown(data)
    if fmt == "pdf":
        return _to_pdf(data)
    if fmt == "docx":
        return _to_docx(data)
    raise ValueError(f"Unsupported report format '{fmt}'. Must be one of {SUPPORTED_FORMATS}.")


# --- PDF ---------------------------------------------------------------------------


class _ReportPDF:
    """fpdf2-backed renderer. Kept as a plain helper class (not a subclass of FPDF)
    so layout logic stays readable and testable independent of fpdf2 internals."""

    MARGIN = 18

    def __init__(self, data: ReportData):
        from fpdf import FPDF
        from fpdf.enums import XPos, YPos

        self.data = data
        self.b = data.branding
        self.XPos = XPos
        self.YPos = YPos

        pdf = FPDF(format="A4")
        pdf.set_margins(self.MARGIN, self.MARGIN, self.MARGIN)
        pdf.set_auto_page_break(auto=True, margin=24)
        pdf.alias_nb_pages()
        pdf.set_creator("vulngent")
        pdf.set_title(_pdf_safe(self.b.title))
        self.pdf = pdf
        self._page_w = pdf.w
        self._content_w = pdf.w - 2 * self.MARGIN

        pdf.header = self._header  # type: ignore[method-assign]
        pdf.footer = self._footer  # type: ignore[method-assign]

    # -- chrome ---------------------------------------------------------------

    def _header(self) -> None:
        pdf = self.pdf
        if pdf.page_no() == 1:
            return  # cover page draws its own masthead
        pdf.set_xy(self.MARGIN, 10)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(self.b.accent_color)
        pdf.cell(0, 5, _pdf_safe(self.b.company_name.upper()), new_x=self.XPos.RIGHT, new_y=self.YPos.TOP)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(MUTED)
        pdf.set_x(-self.MARGIN - 60)
        pdf.cell(60, 5, _pdf_safe(self.b.title), align="R", new_x=self.XPos.LMARGIN, new_y=self.YPos.NEXT)
        pdf.set_draw_color(HAIRLINE)
        pdf.set_line_width(0.25)
        pdf.line(self.MARGIN, 16, self._page_w - self.MARGIN, 16)
        pdf.set_y(22)

    def _footer(self) -> None:
        pdf = self.pdf
        pdf.set_draw_color(HAIRLINE)
        pdf.set_line_width(0.25)
        pdf.line(self.MARGIN, pdf.h - 16, self._page_w - self.MARGIN, pdf.h - 16)
        pdf.set_y(-13)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(MUTED)
        pdf.cell(self._content_w / 2, 5, _pdf_safe(self.b.footer_text))
        pdf.set_x(self.MARGIN + self._content_w / 2)
        pdf.cell(self._content_w / 2, 5, f"Page {pdf.page_no()} of {{nb}}", align="R")

    def _reset_x(self) -> None:
        self.pdf.set_x(self.MARGIN)

    def _heading(self, text: str, *, gap_before: float = 8) -> None:
        pdf = self.pdf
        pdf.ln(gap_before)
        self._reset_x()
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(self.b.primary_color)
        pdf.cell(0, 7, _pdf_safe(text), new_x=self.XPos.LMARGIN, new_y=self.YPos.NEXT)
        pdf.set_draw_color(self.b.accent_color)
        pdf.set_line_width(0.6)
        pdf.line(self.MARGIN, pdf.y, self.MARGIN + 10, pdf.y)
        pdf.ln(4)

    # -- cover ------------------------------------------------------------------

    def _cover_page(self) -> None:
        pdf = self.pdf
        pdf.add_page()

        if self.b.logo_path:
            try:
                pdf.image(self.b.logo_path, x=self.MARGIN, y=20, h=14)
            except Exception:
                pass

        pdf.set_xy(self.MARGIN, 55)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(self.b.accent_color)
        pdf.cell(0, 6, _pdf_safe(self.b.company_name.upper()), new_x=self.XPos.LMARGIN, new_y=self.YPos.NEXT)

        pdf.set_xy(self.MARGIN, 64)
        pdf.set_font("Helvetica", "B", 28)
        pdf.set_text_color(self.b.primary_color)
        pdf.multi_cell(self._content_w, 11, _pdf_safe(self.b.title))

        pdf.set_x(self.MARGIN)
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(MUTED)
        pdf.cell(
            0,
            6,
            f"Generated {self.data.generated_at:%Y-%m-%d %H:%M UTC}",
            new_x=self.XPos.LMARGIN,
            new_y=self.YPos.NEXT,
        )

        self._kpi_cards(y=100)
        self._severity_bars(y=140)

    def _kpi_cards(self, *, y: float) -> None:
        pdf = self.pdf
        cards = [
            (str(self.data.open_count), "Open", INK),
            (str(self.data.in_progress_count), "In Progress", self.b.accent_color),
            (str(self.data.by_severity.get("critical", 0)), "Critical", SEVERITY_COLORS["critical"]),
            (str(self.data.by_severity.get("high", 0)), "High", SEVERITY_COLORS["high"]),
        ]
        gap = 6
        card_w = (self._content_w - gap * (len(cards) - 1)) / len(cards)
        card_h = 28
        for i, (num, label, color) in enumerate(cards):
            x = self.MARGIN + i * (card_w + gap)
            pdf.set_draw_color(HAIRLINE)
            pdf.set_fill_color(PANEL_BG)
            pdf.rect(x, y, card_w, card_h, style="FD", round_corners=True, corner_radius=2)
            pdf.set_xy(x, y + 5)
            pdf.set_font("Helvetica", "B", 20)
            pdf.set_text_color(color)
            pdf.cell(card_w, 10, num, align="C", new_x=self.XPos.LEFT, new_y=self.YPos.TOP)
            pdf.set_xy(x, y + 17)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(MUTED)
            pdf.cell(card_w, 5, label, align="C")

    def _severity_bars(self, *, y: float) -> None:
        pdf = self.pdf
        total = sum(self.data.by_severity.values()) or 1
        pdf.set_xy(self.MARGIN, y)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(MUTED)
        pdf.cell(0, 5, "OPEN + IN-PROGRESS BY SEVERITY", new_x=self.XPos.LMARGIN, new_y=self.YPos.NEXT)
        row_y = y + 9
        label_w = 24
        bar_x = self.MARGIN + label_w
        bar_w = self._content_w - label_w - 14
        for sev in ("critical", "high", "medium", "low", "info"):
            count = self.data.by_severity.get(sev, 0)
            if count == 0 and sev not in self.data.by_severity:
                continue
            pdf.set_xy(self.MARGIN, row_y)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(INK)
            pdf.cell(label_w, 6, sev.capitalize())
            pdf.set_draw_color(HAIRLINE)
            pdf.set_fill_color(PANEL_BG)
            pdf.rect(bar_x, row_y, bar_w, 5, style="F")
            frac_w = max(bar_w * (count / total), 1.2) if count else 0
            if frac_w:
                pdf.set_fill_color(SEVERITY_COLORS[sev])
                pdf.rect(bar_x, row_y, frac_w, 5, style="F")
            pdf.set_xy(bar_x + bar_w + 3, row_y - 0.5)
            pdf.set_text_color(MUTED)
            pdf.cell(11, 6, str(count))
            row_y += 8

    # -- findings table -----------------------------------------------------

    def _findings_table(self) -> None:
        pdf = self.pdf
        data = self.data.top_vulns
        self._heading(f"Top Priority Findings ({len(data)})")
        if not data:
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(MUTED)
            pdf.multi_cell(0, 6, "No open or in-progress vulnerabilities.")
            return

        from fpdf.fonts import FontFace

        header_style = FontFace(color="#FFFFFF", fill_color=self.b.primary_color, emphasis="B")
        pdf.set_font("Helvetica", "", 9)
        with pdf.table(
            col_widths=(15, 27, 20, 88, 15, 15),
            text_align=("LEFT", "LEFT", "CENTER", "LEFT", "CENTER", "CENTER"),
            borders_layout="HORIZONTAL_LINES",
            cell_fill_mode="ROWS",
            cell_fill_color=PANEL_BG,
            headings_style=header_style,
            line_height=5,
            padding=(1.6, 2, 1.6, 2),
        ) as table:
            row = table.row()
            for h in ("ID", "CVE / Finding", "Severity", "Title", "CVSS", "Score"):
                row.cell(h)
            for v in data:
                row = table.row()
                row.cell(f"#{v.id}")
                row.cell(_pdf_safe(v.external_id))
                sev_style = FontFace(
                    color="#FFFFFF", fill_color=SEVERITY_COLORS.get(v.severity, MUTED), emphasis="B"
                )
                row.cell(v.severity.upper(), style=sev_style, align="C")
                row.cell(_pdf_safe(v.title))
                row.cell(f"{v.cvss_score:.1f}" if v.cvss_score is not None else "-")
                row.cell(f"{v.priority_score:.1f}" if v.priority_score is not None else "-")

    def _commitments_section(self) -> None:
        commitments = self.data.commitments_due
        self._heading("Commitments Due Soon")
        pdf = self.pdf
        if not commitments:
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(MUTED)
            pdf.multi_cell(0, 6, "No commitments due in the reporting window.")
            return
        pdf.set_font("Helvetica", "", 9)
        with pdf.table(
            col_widths=(20, 105, 25, 25),
            text_align="LEFT",
            borders_layout="HORIZONTAL_LINES",
            cell_fill_mode="ROWS",
            cell_fill_color=PANEL_BG,
            line_height=5,
            padding=(1.6, 2, 1.6, 2),
        ) as table:
            row = table.row()
            for h in ("Vuln", "Commitment", "Due", "Status"):
                row.cell(h)
            for c in commitments:
                row = table.row()
                row.cell(_pdf_safe(f"#{c.vulnerability_id} {c.vulnerability_external_id}"))
                row.cell(_pdf_safe(c.description))
                row.cell(str(c.due_date))
                row.cell(c.status.upper())

    def render(self) -> bytes:
        self._cover_page()
        self.pdf.add_page()
        self._findings_table()
        self._commitments_section()
        return bytes(self.pdf.output())


def _to_pdf(data: ReportData) -> bytes:
    return _ReportPDF(data).render()


# --- DOCX ---------------------------------------------------------------------------


def _to_docx(data: ReportData) -> bytes:
    import io

    from docx import Document
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml.ns import qn
    from docx.shared import Pt, RGBColor

    b = data.branding

    def _rgb(hexcolor: str) -> RGBColor:
        h = hexcolor.lstrip("#")
        return RGBColor(int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))

    def _shade_cell(cell, hexcolor: str) -> None:
        shd = cell._tc.get_or_add_tcPr().makeelement(qn("w:shd"), {qn("w:fill"): hexcolor.lstrip("#")})
        cell._tc.get_or_add_tcPr().append(shd)

    doc = Document()
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(10.5)

    if b.logo_path:
        try:
            doc.add_picture(b.logo_path, height=Pt(36))
        except Exception:
            pass

    eyebrow = doc.add_paragraph()
    run = eyebrow.add_run(b.company_name.upper())
    run.bold = True
    run.font.size = Pt(10)
    run.font.color.rgb = _rgb(b.accent_color)

    title = doc.add_paragraph()
    run = title.add_run(b.title)
    run.bold = True
    run.font.size = Pt(24)
    run.font.color.rgb = _rgb(b.primary_color)

    meta = doc.add_paragraph()
    run = meta.add_run(f"Generated {data.generated_at:%Y-%m-%d %H:%M UTC}")
    run.font.size = Pt(10)
    run.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)

    doc.add_paragraph()

    kpi_table = doc.add_table(rows=2, cols=4)
    kpi_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    kpis = [
        (str(data.open_count), "Open"),
        (str(data.in_progress_count), "In Progress"),
        (str(data.by_severity.get("critical", 0)), "Critical"),
        (str(data.by_severity.get("high", 0)), "High"),
    ]
    for col, (num, label) in enumerate(kpis):
        num_cell = kpi_table.cell(0, col)
        num_cell.text = ""
        p = num_cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(num)
        run.bold = True
        run.font.size = Pt(20)
        run.font.color.rgb = _rgb(b.primary_color)
        _shade_cell(num_cell, "F8FAFC")

        label_cell = kpi_table.cell(1, col)
        label_cell.text = ""
        p = label_cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(label)
        run.font.size = Pt(9)
        run.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)
        _shade_cell(label_cell, "F8FAFC")

    doc.add_paragraph()
    doc.add_heading("By Severity", level=2)
    for sev, count in data.by_severity.items():
        doc.add_paragraph(f"{sev.capitalize()}: {count}", style="List Bullet")

    doc.add_heading(f"Top Priority Findings ({len(data.top_vulns)})", level=2)
    if not data.top_vulns:
        doc.add_paragraph("No open or in-progress vulnerabilities.")
    else:
        table = doc.add_table(rows=1, cols=6)
        table.style = "Light Grid Accent 1"
        hdr = table.rows[0].cells
        for i, h in enumerate(("ID", "CVE / Finding", "Severity", "Title", "CVSS", "Score")):
            hdr[i].text = h
        for v in data.top_vulns:
            cells = table.add_row().cells
            cells[0].text = f"#{v.id}"
            cells[1].text = v.external_id
            cells[2].text = v.severity.upper()
            cells[3].text = v.title
            cells[4].text = f"{v.cvss_score:.1f}" if v.cvss_score is not None else "-"
            cells[5].text = f"{v.priority_score:.1f}" if v.priority_score is not None else "-"

    doc.add_heading("Commitments Due Soon", level=2)
    if not data.commitments_due:
        doc.add_paragraph("No commitments due in the reporting window.")
    else:
        table = doc.add_table(rows=1, cols=4)
        table.style = "Light Grid Accent 1"
        hdr = table.rows[0].cells
        for i, h in enumerate(("Vuln", "Commitment", "Due", "Status")):
            hdr[i].text = h
        for c in data.commitments_due:
            cells = table.add_row().cells
            cells[0].text = f"#{c.vulnerability_id} {c.vulnerability_external_id}"
            cells[1].text = c.description
            cells[2].text = str(c.due_date)
            cells[3].text = c.status.upper()

    footer_p = doc.add_paragraph()
    run = footer_p.add_run(b.footer_text)
    run.italic = True
    run.font.size = Pt(8)
    run.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()
