# -*- coding: utf-8 -*-
"""Build a single Chinese PDF manual from the JPSSL wiki Markdown files."""

from __future__ import annotations

import re
import textwrap
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

from markdown_it import MarkdownIt
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    PageBreak,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "侏罗纪网络安全加密套件（JPSSL）使用说明.pdf"
TITLE = "侏罗纪网络安全加密套件（JPSSL）使用说明"
SUBTITLE = "JPSSL Wiki 合并版 · C++20 高性能跨平台密码学库"
VERSION = "1.1.10"
COPYRIGHT_OWNER = "侏罗纪（海城）计算机软件科技有限公司"
GITHUB_URL = "https://github.com/DaChengTechnology/JPSSL"
GITEE_URL = "https://gitee.com/dachtech_admin/JPSSL"

PAGE_ORDER = [
    "Home.md",
    "Beginner-Guide.md",
    "Getting-Started.md",
    "Build-Options.md",
    "Platform-Builds.md",
    "Command-Line-Tools.md",
    "Algorithm-Support.md",
    "API-Symmetric.md",
    "API-Hash-MAC-KDF.md",
    "API-Asymmetric.md",
    "API-X509.md",
    "API-TLS.md",
    "API-TLS-Socket.md",
    "Certificate-Transparency.md",
    "MUSA-GPU.md",
    "Benchmarks.md",
    "Testing.md",
    "ECDSA-SIMD-Feasibility.md",
]

FONT_REGULAR = "MSYaHei"
FONT_BOLD = "MSYaHei-Bold"


def register_fonts() -> None:
    pdfmetrics.registerFont(TTFont(FONT_REGULAR, r"C:\Windows\Fonts\msyh.ttc"))
    pdfmetrics.registerFont(TTFont(FONT_BOLD, r"C:\Windows\Fonts\msyhbd.ttc"))
    pdfmetrics.registerFontFamily(
        FONT_REGULAR,
        normal=FONT_REGULAR,
        bold=FONT_BOLD,
        italic=FONT_REGULAR,
        boldItalic=FONT_BOLD,
    )


def build_styles() -> dict[str, ParagraphStyle]:
    base = dict(fontName=FONT_REGULAR, textColor=colors.HexColor("#1f2937"), wordWrap="CJK")

    def make_style(name: str, **kwargs) -> ParagraphStyle:
        merged = base.copy()
        merged.update(kwargs)
        return ParagraphStyle(name, **merged)

    return {
        "CoverTitle": make_style(
            "CoverTitle", fontSize=24, leading=32, alignment=1, textColor=colors.HexColor("#111827"), spaceAfter=10 * mm
        ),
        "CoverSubtitle": make_style(
            "CoverSubtitle", fontSize=12, leading=18, alignment=1, textColor=colors.HexColor("#4b5563"), spaceAfter=6 * mm
        ),
        "TOCTitle": make_style(
            "TOCTitle", fontSize=20, leading=28, spaceAfter=8 * mm, textColor=colors.HexColor("#111827")
        ),
        "H1": make_style(
            "H1", fontName=FONT_BOLD, fontSize=18, leading=24, spaceBefore=0, spaceAfter=6 * mm, textColor=colors.HexColor("#0f172a"), keepWithNext=True
        ),
        "H2": make_style(
            "H2", fontName=FONT_BOLD, fontSize=14, leading=20, spaceBefore=5 * mm, spaceAfter=2.5 * mm, textColor=colors.HexColor("#111827"), keepWithNext=True
        ),
        "H3": make_style(
            "H3", fontName=FONT_BOLD, fontSize=11.5, leading=16, spaceBefore=3.5 * mm, spaceAfter=2 * mm, textColor=colors.HexColor("#1f2937"), keepWithNext=True
        ),
        "H4": make_style(
            "H4", fontName=FONT_BOLD, fontSize=10.5, leading=15, spaceBefore=3 * mm, spaceAfter=1.5 * mm, textColor=colors.HexColor("#374151"), keepWithNext=True
        ),
        "Body": make_style(
            "Body", fontSize=10, leading=16, spaceAfter=2.2 * mm, alignment=0
        ),
        "List": make_style(
            "List", fontSize=10, leading=16, leftIndent=6 * mm, firstLineIndent=0, spaceAfter=1.2 * mm
        ),
        "Quote": make_style(
            "Quote", fontSize=9.5, leading=15, leftIndent=6 * mm, rightIndent=4 * mm, textColor=colors.HexColor("#4b5563"), backColor=colors.HexColor("#f8fafc"), borderColor=colors.HexColor("#cbd5e1"), borderWidth=0.6, borderPadding=5, spaceBefore=2 * mm, spaceAfter=3 * mm
        ),
        "Code": make_style(
            "Code", fontSize=8, leading=10.5, textColor=colors.HexColor("#111827"), backColor=colors.HexColor("#f6f8fa"), borderColor=colors.HexColor("#d0d7de"), borderWidth=0.5, borderPadding=5, leftIndent=0, rightIndent=0, spaceBefore=2 * mm, spaceAfter=3 * mm
        ),
        "TableCell": make_style(
            "TableCell", fontSize=8.5, leading=12, spaceAfter=0
        ),
        "TableHeader": make_style(
            "TableHeader", fontName=FONT_BOLD, fontSize=8.5, leading=12, textColor=colors.HexColor("#0f172a"), spaceAfter=0
        ),
    }


class ManualDocTemplate(BaseDocTemplate):
    def __init__(self, filename: str, **kwargs):
        super().__init__(filename, **kwargs)
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="normal")
        self.addPageTemplates([PageTemplate(id="normal", frames=[frame], onPage=self._draw_footer)])

    def _draw_footer(self, canvas, doc):
        canvas.saveState()
        if doc.page > 1:
            canvas.setFont(FONT_REGULAR, 8)
            canvas.setFillColor(colors.HexColor("#6b7280"))
            canvas.drawString(doc.leftMargin, 11 * mm, TITLE)
            canvas.drawRightString(A4[0] - doc.rightMargin, 11 * mm, f"第 {doc.page} 页")
            canvas.setStrokeColor(colors.HexColor("#d1d5db"))
            canvas.setLineWidth(0.5)
            canvas.line(doc.leftMargin, 14 * mm, A4[0] - doc.rightMargin, 14 * mm)
        canvas.restoreState()

    def afterFlowable(self, flowable):
        if not isinstance(flowable, Paragraph):
            return
        style_name = flowable.style.name
        level_map = {"H1": 0, "H2": 1, "H3": 2}
        if style_name not in level_map:
            return
        level = level_map[style_name]
        text = flowable.getPlainText()
        key = f"heading-{self.seq.nextf('heading')}"
        self.canv.bookmarkPage(key)
        try:
            self.canv.addOutlineEntry(text, key, level=level, closed=False)
        except Exception:
            pass
        self.notify("TOCEntry", (level, text, self.page, key))


def render_inline(inline_token) -> str:
    parts: list[str] = []
    external_link_stack: list[bool] = []
    for token in inline_token.children or []:
        ttype = token.type
        if ttype == "text":
            parts.append(escape(token.content))
        elif ttype == "code_inline":
            parts.append(f'<font name="{FONT_REGULAR}" color="#b91c1c">{escape(token.content)}</font>')
        elif ttype == "strong_open":
            parts.append("<b>")
        elif ttype == "strong_close":
            parts.append("</b>")
        elif ttype == "em_open":
            parts.append("<i>")
        elif ttype == "em_close":
            parts.append("</i>")
        elif ttype == "s_open":
            parts.append("<strike>")
        elif ttype == "s_close":
            parts.append("</strike>")
        elif ttype == "link_open":
            href = (token.attrs or {}).get("href", "")
            is_external = href.startswith(("http://", "https://", "mailto:"))
            external_link_stack.append(is_external)
            if is_external:
                parts.append(f'<link href={quoteattr(href)}><font color="#0563c1"><u>')
        elif ttype == "link_close":
            is_external = external_link_stack.pop() if external_link_stack else False
            if is_external:
                parts.append("</u></font></link>")
        elif ttype in ("softbreak", "hardbreak"):
            parts.append("<br/>")
        elif ttype == "image":
            alt = token.content or ""
            parts.append(escape(alt))
        elif ttype in ("html_inline", "html_block"):
            parts.append(escape(token.content))
        else:
            if token.content:
                parts.append(escape(token.content))
    return "".join(parts)


def wrap_code_line(line: str, width: int = 96) -> list[str]:
    if len(line) <= width:
        return [line]
    stripped = line.lstrip()
    indent = line[: len(line) - len(stripped)]
    wrapped = textwrap.wrap(
        line,
        width=width,
        subsequent_indent=indent + "    ",
        break_long_words=True,
        break_on_hyphens=False,
        replace_whitespace=False,
        drop_whitespace=False,
    )
    return wrapped or [line]


def add_code_block(story: list, content: str, styles: dict[str, ParagraphStyle]) -> None:
    lines: list[str] = []
    for line in content.rstrip("\n").splitlines() or [""]:
        lines.extend(wrap_code_line(line))
    code_text = "\n".join(lines)
    story.append(Preformatted(code_text, styles["Code"], maxLineLength=110))


def parse_list(tokens, i: int, ordered: bool, level: int, story: list, styles: dict[str, ParagraphStyle]) -> int:
    close_type = "ordered_list_close" if ordered else "bullet_list_close"
    item_no = 0
    i += 1
    while i < len(tokens) and tokens[i].type != close_type:
        token = tokens[i]
        if token.type == "list_item_open":
            item_no += 1
            i += 1
            chunks: list[str] = []
            while i < len(tokens) and tokens[i].type != "list_item_close":
                inner = tokens[i]
                if inner.type == "paragraph_open":
                    chunks.append(render_inline(tokens[i + 1]))
                    i += 3
                elif inner.type == "fence":
                    # Rare inside lists; keep code as an indented pre block.
                    code_lines = []
                    for line in inner.content.rstrip("\n").splitlines():
                        code_lines.extend(wrap_code_line(line, width=88))
                    chunks.append("<br/>".join(escape(line).replace(" ", "&nbsp;") for line in code_lines))
                    i += 1
                elif inner.type in ("bullet_list_open", "ordered_list_open"):
                    i = parse_list(tokens, i, inner.type == "ordered_list_open", level + 1, story, styles)
                else:
                    i += 1
            bullet = f"{item_no}." if ordered else "•"
            text = "<br/>".join(chunk for chunk in chunks if chunk)
            item_style = ParagraphStyle(
                f"ListLevel{level}",
                parent=styles["List"],
                leftIndent=(6 + level * 5) * mm,
                bulletIndent=(level * 5) * mm,
            )
            story.append(Paragraph(text, item_style, bulletText=bullet))
        else:
            i += 1
    return i + 1


def parse_table(tokens, i: int, story: list, styles: dict[str, ParagraphStyle], available_width: float) -> int:
    header_rows: list[list[str]] = []
    body_rows: list[list[str]] = []
    in_header = False
    current_row: list[str] | None = None
    i += 1
    while i < len(tokens) and tokens[i].type != "table_close":
        token = tokens[i]
        if token.type == "thead_open":
            in_header = True
        elif token.type == "thead_close":
            in_header = False
        elif token.type == "tr_open":
            current_row = []
        elif token.type in ("th_open", "td_open"):
            cell_html = render_inline(tokens[i + 1]) if i + 1 < len(tokens) else ""
            if current_row is not None:
                current_row.append(cell_html)
            i += 2  # skip inline and close token
        elif token.type == "tr_close":
            if current_row is not None:
                if in_header:
                    header_rows.append(current_row)
                else:
                    body_rows.append(current_row)
            current_row = None
        i += 1

    rows = header_rows + body_rows
    if not rows:
        return i + 1
    ncols = max(len(row) for row in rows)
    for row in rows:
        row.extend([""] * (ncols - len(row)))
    col_width = available_width / max(ncols, 1)
    table_data = []
    for r, row in enumerate(rows):
        style = styles["TableHeader"] if r < len(header_rows) else styles["TableCell"]
        table_data.append([Paragraph(cell, style) for cell in row])
    table = Table(table_data, colWidths=[col_width] * ncols, repeatRows=1 if header_rows else 0, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#c8d0dc")),
                ("BACKGROUND", (0, 0), (-1, max(len(header_rows) - 1, 0)), colors.HexColor("#e8eef7")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(Spacer(1, 1.5 * mm))
    story.append(table)
    story.append(Spacer(1, 2.5 * mm))
    return i + 1


def parse_blockquote(tokens, i: int, story: list, styles: dict[str, ParagraphStyle]) -> int:
    i += 1
    chunks: list[str] = []
    while i < len(tokens) and tokens[i].type != "blockquote_close":
        if tokens[i].type == "paragraph_open":
            chunks.append(render_inline(tokens[i + 1]))
            i += 3
        else:
            i += 1
    text = "<br/>".join(chunk for chunk in chunks if chunk)
    if text:
        story.append(Paragraph(text, styles["Quote"]))
    return i + 1


def parse_markdown(text: str, story: list, styles: dict[str, ParagraphStyle], available_width: float) -> None:
    md = MarkdownIt("default")
    tokens = md.parse(text.replace("\r\n", "\n").replace("\r", "\n"))
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.type == "heading_open":
            level = int(token.tag[1]) if token.tag and len(token.tag) > 1 else 2
            inline = tokens[i + 1]
            content = render_inline(inline)
            style = styles["H1"] if level == 1 else styles["H2"] if level == 2 else styles["H3"] if level == 3 else styles["H4"]
            story.append(Paragraph(content, style))
            i += 3
        elif token.type == "paragraph_open":
            content = render_inline(tokens[i + 1])
            if content.strip():
                story.append(Paragraph(content, styles["Body"]))
            i += 3
        elif token.type == "bullet_list_open":
            i = parse_list(tokens, i, ordered=False, level=0, story=story, styles=styles)
        elif token.type == "ordered_list_open":
            i = parse_list(tokens, i, ordered=True, level=0, story=story, styles=styles)
        elif token.type == "fence":
            add_code_block(story, token.content, styles)
            i += 1
        elif token.type == "table_open":
            i = parse_table(tokens, i, story, styles, available_width)
        elif token.type == "blockquote_open":
            i = parse_blockquote(tokens, i, story, styles)
        elif token.type == "hr":
            story.append(Spacer(1, 2 * mm))
            story.append(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#d1d5db")))
            story.append(Spacer(1, 3 * mm))
            i += 1
        else:
            i += 1


def clean_internal_links(markdown_text: str) -> str:
    # Convert wiki page links like [文字](Getting-Started) to plain text; keep external URLs.
    def repl(match: re.Match) -> str:
        label, href = match.group(1), match.group(2)
        if href.startswith(("http://", "https://", "mailto:", "#")):
            return match.group(0)
        return label

    return re.sub(r"\[([^\]]+)\]\(([^)]+)\)", repl, markdown_text)


def build_pdf() -> Path:
    register_fonts()
    styles = build_styles()
    doc = ManualDocTemplate(
        str(OUTPUT),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=16 * mm,
        topMargin=20 * mm,
        bottomMargin=18 * mm,
        title=f"{TITLE} v{VERSION}",
        author=COPYRIGHT_OWNER,
        subject=f"JPSSL 使用说明 v{VERSION}",
        creator=COPYRIGHT_OWNER,
    )
    available_width = doc.width
    story: list = []

    # Cover
    story.append(Spacer(1, 42 * mm))
    story.append(Paragraph(escape(TITLE), styles["CoverTitle"]))
    story.append(Paragraph(escape(SUBTITLE), styles["CoverSubtitle"]))
    story.append(Paragraph(escape(f"著作权人：{COPYRIGHT_OWNER}"), styles["CoverSubtitle"]))
    story.append(Paragraph(escape(f"版本号：{VERSION}"), styles["CoverSubtitle"]))
    story.append(
        Paragraph(
            "开源地址："
            f'<link href={quoteattr(GITHUB_URL)}><font color="#0563c1"><u>{escape(GITHUB_URL)}</u></font></link>'
            "<br/>"
            f'<link href={quoteattr(GITEE_URL)}><font color="#0563c1"><u>{escape(GITEE_URL)}</u></font></link>',
            styles["CoverSubtitle"],
        )
    )
    story.append(Paragraph(escape(f"生成日期：{datetime.now():%Y年%m月%d日}"), styles["CoverSubtitle"]))
    story.append(PageBreak())

    # TOC
    story.append(Paragraph("目录", styles["TOCTitle"]))
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle("TOCLevel1", fontName=FONT_BOLD, fontSize=11, leading=16, leftIndent=0, firstLineIndent=0, spaceBefore=3, wordWrap="CJK"),
        ParagraphStyle("TOCLevel2", fontName=FONT_REGULAR, fontSize=9.5, leading=14, leftIndent=6 * mm, firstLineIndent=0, spaceBefore=1, wordWrap="CJK"),
        ParagraphStyle("TOCLevel3", fontName=FONT_REGULAR, fontSize=9, leading=13, leftIndent=12 * mm, firstLineIndent=0, spaceBefore=0.5, textColor=colors.HexColor("#4b5563"), wordWrap="CJK"),
    ]
    story.append(toc)

    for index, filename in enumerate(PAGE_ORDER):
        path = ROOT / filename
        if not path.exists():
            continue
        story.append(PageBreak())
        text = path.read_text(encoding="utf-8")
        text = clean_internal_links(text)
        parse_markdown(text, story, styles, available_width)

    doc.multiBuild(story)
    return OUTPUT


if __name__ == "__main__":
    output = build_pdf()
    print(output)
