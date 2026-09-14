"""Offline publication rendering that never silently discards report lines."""
from pathlib import Path
import re

from fpdf import FPDF


class _ReportPDF(FPDF):
    # Report text is untrusted. Keep destinations readable, but never create
    # active PDF links (including javascript:, file:, or relative app routes).
    MARKDOWN_LINK_REGEX = re.compile(r"(?!)")


_INLINE = re.compile(r"`[^`\n]+`|\*\*[^*\n]+\*\*|\[[^\[\]\n]+\]\([^()\n]+\)")


def _literal_inline(text: str) -> str:
    # Enable only the small subset below; preserve every other FPDF marker.
    text = text.replace("\\", "\\\\")
    for marker in ("**", "__", "~~", "--"):
        text = text.replace(marker, "\\" + marker)
    return text


def _inline(text: str) -> str:
    """Balanced bold and simple links; code spans remain literal, without HTML."""
    pieces = []
    end = 0
    for match in _INLINE.finditer(text):
        pieces.append(_literal_inline(text[end:match.start()]))
        token = match[0]
        if token.startswith("**"):
            pieces.append("**" + _literal_inline(token[2:-2]) + "**")
        elif token.startswith("["):
            label, destination = token[1:-1].split("](", 1)
            pieces.append(_literal_inline(f"{label} ({destination})"))
        else:
            pieces.append(_literal_inline(token))
        end = match.end()
    pieces.append(_literal_inline(text[end:]))
    result = "".join(pieces)
    # FPDF preserves a final escape run literally rather than unescaping it.
    trailing = len(result) - len(result.rstrip("\\"))
    return result[:-trailing] + "\\" * (trailing // 2) if trailing else result


def render_report_pdf(markdown: str, *, report_id: int, created: str) -> bytes:
    fonts = Path(__file__).parent / "assets" / "fonts"
    pdf = _ReportPDF()
    pdf.set_auto_page_break(auto=True, margin=16)
    for family, style, filename in (
        ("Lotus", "", "DejaVuSans.ttf"),
        ("Lotus", "B", "DejaVuSans-Bold.ttf"),
        ("LotusMono", "", "DejaVuSansMono.ttf"),
    ):
        pdf.add_font(family, style, str(fonts / filename))
    pdf.add_page()
    pdf.set_title(f"Lotus report #{report_id}")
    pdf.set_font("Lotus", "B", 18)
    pdf.multi_cell(0, 11, "Lotus Security Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Lotus", size=9)
    pdf.multi_cell(0, 6, f"Report #{report_id} | Generated: {created}", new_x="LMARGIN", new_y="NEXT")
    # The bundled fonts cover common scripts, not every Unicode character.
    # Preserve unsupported/control characters explicitly, never as empty glyphs.
    escaped = False

    def supported(text, *, inline=False):
        nonlocal escaped
        cmap = pdf.current_font.cmap
        if inline:
            # Bold fragments use a different bundled font. A character that is
            # unavailable there must remain explicit rather than disappearing.
            cmap = cmap.keys() & pdf.fonts["lotusB"].cmap.keys()
        result = []
        for char in text.expandtabs(4):
            if ord(char) in cmap and ord(char) >= 32:
                result.append(char)
            else:
                escaped = True
                result.append(f"[U+{ord(char):04X}]")
        return "".join(result)

    pdf.ln(5)
    code = False
    first_content = True
    for raw in markdown.splitlines():
        # The export already supplies this exact title. Other headings and later
        # repeated titles remain report content and must still be printed.
        if first_content and raw.strip():
            first_content = False
            if raw.strip() == "# Lotus Security Report":
                continue
        if raw.lstrip().startswith("```"):
            code = not code
            pdf.ln(2)
            continue
        heading = None if code else re.match(r"^(#{1,6})\s+(.*)$", raw)
        if heading:
            size = {1:16, 2:13, 3:11}.get(len(heading[1]), 10)
            pdf.set_font("Lotus", "B", size)
            text = heading[2]
        else:
            pdf.set_font("LotusMono" if code or raw.startswith("|") else "Lotus", size=8 if code or raw.startswith("|") else 9)
            text = raw
        if not text:
            pdf.ln(2)
            continue
        inline = not code and not raw.startswith("|") and not heading
        plain = supported(text, inline=inline)
        pdf.multi_cell(0, 5 if not heading else 8, _inline(plain) if inline else plain,
                       new_x="LMARGIN", new_y="NEXT",
                       wrapmode="CHAR" if code or raw.startswith("|") else "WORD", align="L",
                       markdown=inline, print_sh=True)
    if escaped:
        pdf.ln(4)
        pdf.set_font("Lotus", size=8)
        pdf.multi_cell(0, 5, "Export note: characters unavailable in the bundled fonts are preserved as [U+XXXX] Unicode code points. Download Markdown for the original text.",
                       new_x="LMARGIN", new_y="NEXT")
    return bytes(pdf.output())
