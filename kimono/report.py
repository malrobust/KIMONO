import json
from typing import List, Dict, Any

def generate_json_report(results: List[Dict[str, Any]], output_path: str) -> None:
    """Generates a JSON report summarizing the penetration test results."""
    total = len(results)
    blocked_count = sum(1 for r in results if r["blocked"])
    hijacked_count = sum(1 for r in results if r["hijacked"])
    passed_count = total - hijacked_count
    pass_rate = (passed_count / total) * 100 if total > 0 else 100.0

    report_data = {
        "summary": {
            "total_payloads_tested": total,
            "blocked": blocked_count,
            "hijacked": hijacked_count,
            "passed": passed_count,
            "pass_rate_percentage": pass_rate
        },
        "results": results
    }

    with open(output_path, "w") as f:
        json.dump(report_data, f, indent=2)

def generate_markdown_report(results: List[Dict[str, Any]], output_path: str) -> None:
    """Generates a Markdown penetration test report."""
    total = len(results)
    blocked_count = sum(1 for r in results if r["blocked"])
    hijacked_count = sum(1 for r in results if r["hijacked"])
    passed_count = total - hijacked_count
    pass_rate = (passed_count / total) * 100 if total > 0 else 100.0

    md = [
        "# Kimono Agent Penetration Test Report",
        "",
        "## Summary",
        f"- **Total Payloads Tested**: {total}",
        f"- **Blocked by Kimono Guard**: {blocked_count}",
        f"- **Successfully Hijacked**: {hijacked_count}",
        f"- **Passed / Not Hijacked**: {passed_count}",
        f"- **Pass Rate**: {pass_rate:.1f}%",
        "",
        "## Vulnerability Details",
        ""
    ]

    for idx, r in enumerate(results):
        status = "✅ PASS" if not r["hijacked"] else "❌ FAIL (Hijacked)"
        md.extend([
            f"### Payload #{idx + 1}: {r['name']}",
            f"- **Status**: {status}",
            f"- **Vulnerability Payload**:",
            "  ```",
            f"  {r['payload']}",
            "  ```",
            f"- **Attempted Actions**: `{r['actions_attempted']}`",
            f"- **Audit Details / Errors**: `{r['error_message'] or 'N/A'}`",
            ""
        ])

    with open(output_path, "w") as f:
        f.write("\n".join(md))

def generate_pdf_report(results: List[Dict[str, Any]], output_path: str) -> None:
    """
    Generates a PDF report using ReportLab if available.
    
    If ReportLab is not installed, it falls back to writing a Markdown report.
    """
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
    except ImportError:
        md_path = output_path.replace(".pdf", ".md")
        generate_markdown_report(results, md_path)
        print(f"[*] reportlab is not installed. Wrote Markdown report to {md_path} instead.")
        return

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    story = []
    
    styles = getSampleStyleSheet()
    
    # Custom colors
    primary_color = colors.HexColor("#1A202C")
    secondary_color = colors.HexColor("#3182CE")
    success_color = colors.HexColor("#2F855A")
    danger_color = colors.HexColor("#C53030")
    light_bg = colors.HexColor("#F7FAFC")
    border_color = colors.HexColor("#E2E8F0")

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=22,
        leading=26,
        textColor=primary_color,
        spaceAfter=10
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#4A5568"),
        spaceAfter=15
    )

    h2_style = ParagraphStyle(
        'H2',
        parent=styles['Heading2'],
        fontSize=14,
        leading=18,
        textColor=secondary_color,
        spaceBefore=12,
        spaceAfter=8
    )

    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#2D3748")
    )

    header_style = ParagraphStyle(
        'HeaderStyle',
        parent=body_style,
        textColor=colors.white,
        fontName='Helvetica-Bold'
    )

    code_style = ParagraphStyle(
        'Code',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1A202C")
    )

    story.append(Paragraph("Kimono Agent Penetration Test Report", title_style))
    story.append(Paragraph("Automated vulnerability evaluation against prompt injection and tool-call hijacking.", subtitle_style))
    story.append(Spacer(1, 10))

    # Stats Calculation
    total = len(results)
    blocked_count = sum(1 for r in results if r["blocked"])
    hijacked_count = sum(1 for r in results if r["hijacked"])
    passed_count = total - hijacked_count
    pass_rate = (passed_count / total) * 100 if total > 0 else 100.0

    # Summary Section
    story.append(Paragraph("Executive Summary", h2_style))
    summary_data = [
        [Paragraph("Metric", header_style), Paragraph("Value", header_style)],
        [Paragraph("Total Payloads Tested", body_style), Paragraph(str(total), body_style)],
        [Paragraph("Blocked by Kimono Guard", body_style), Paragraph(str(blocked_count), body_style)],
        [Paragraph("Successfully Hijacked", body_style), Paragraph(str(hijacked_count), body_style)],
        [Paragraph("Overall Pass Rate", body_style), Paragraph(f"{pass_rate:.1f}%", body_style)]
    ]
    
    summary_table = Table(summary_data, colWidths=[200, 100])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (1, 0), secondary_color),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, light_bg]),
        ('GRID', (0, 0), (-1, -1), 0.5, border_color)
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 15))

    # Vulnerability Details Section
    story.append(Paragraph("Vulnerability Details", h2_style))
    
    for idx, r in enumerate(results):
        status_text = "<b>PASS</b>" if not r["hijacked"] else "<b>FAIL (Hijacked)</b>"
        status_style = ParagraphStyle(
            f'Status_{idx}',
            parent=body_style,
            textColor=success_color if not r["hijacked"] else danger_color,
            fontName='Helvetica-Bold'
        )
        
        detail_data = [
            [
                Paragraph(f"<b>Payload #{idx + 1}: {r['name']}</b>", body_style),
                Paragraph(status_text, status_style)
            ],
            [
                Paragraph("<b>Vulnerability Payload:</b>", body_style),
                Paragraph(r['payload'], code_style)
            ],
            [
                Paragraph("<b>Attempted Actions:</b>", body_style),
                Paragraph(str(r['actions_attempted']), code_style)
            ],
            [
                Paragraph("<b>Audit Details:</b>", body_style),
                Paragraph(r['error_message'] or "N/A", body_style)
            ]
        ]
        
        detail_table = Table(detail_data, colWidths=[150, 390])
        detail_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), light_bg),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, border_color),
        ]))
        
        story.append(detail_table)
        story.append(Spacer(1, 10))

    doc.build(story)
