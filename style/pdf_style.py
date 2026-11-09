from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle
VERDICT_COLORS={
    "MALWARE": colors.red,
    "BENIGN": colors.green,
    "INCONCLUSIVE": colors.gray
}

def styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontSize=20, spaceAfter=2, alignment=0),
        "sub": ParagraphStyle("s", parent=base["Normal"], fontSize=9, textColor=colors.grey),
        "h": ParagraphStyle("h", parent=base["Heading2"], fontSize=13, spaceBefore=14, spaceAfter=6,
                            textColor=colors.HexColor("#263238")),
        "body": ParagraphStyle("b", parent=base["Normal"], fontSize=9.5, leading=13),
        "cell": ParagraphStyle("c", parent=base["Normal"], fontSize=8.5, leading=11, wordWrap="CJK"),
        "cellb": ParagraphStyle("cb", parent=base["Normal"], fontSize=8.5, leading=11,
                                fontName="Helvetica-Bold"),
        "head": ParagraphStyle("hd", parent=base["Normal"], fontSize=8.5, leading=11,
                               fontName="Helvetica-Bold", textColor=colors.white),
        "muted": ParagraphStyle("m", parent=base["Normal"], fontSize=9, textColor=colors.grey),
        "banner_l": ParagraphStyle("bl", parent=base["Normal"], leading=32),
        "banner_r": ParagraphStyle("br", parent=base["Normal"], leading=24),
        "note": ParagraphStyle("n", parent=base["Normal"], fontSize=8, leading=11, textColor=colors.grey),
    }

def table(data: list[list], col_widths: list[float], header: bool = True) -> Table:
    t = Table(data, colWidths=col_widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CFD8DC")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474F"))]
        style += [("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F7F8")])]
    else:
        style += [("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ECEFF1"))]
    t.setStyle(TableStyle(style))
    return t