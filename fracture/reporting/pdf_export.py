from pathlib import Path


def _meta_summary(meta: dict) -> str:
    if not isinstance(meta, dict) or not meta:
        return "none"

    best = str(meta.get("best_classification", "")).strip()
    if best:
        return best

    pairs = []
    for key, value in meta.items():
        pairs.append(f"{key}={value}")
        if len(pairs) >= 3:
            break
    return ", ".join(pairs) if pairs else "meta present"


def _build_lines(report) -> list[str]:
    report_data = report.to_dict() if hasattr(report, "to_dict") else dict(report)
    findings = report_data.get("findings_summary", {}) or {}
    results = report_data.get("results", {}) or {}

    lines = [
        "FRACTURE Security Assessment Report",
        "",
        "Executive Summary",
        f"Target: {report_data.get('target_url', 'unknown')}",
        f"Detected model: {report_data.get('detected_model', 'unknown')}",
        f"Risk level: {report_data.get('risk_level', 'unknown')}",
        f"Modules run: {report_data.get('modules_run', 0)}",
        f"Modules succeeded: {report_data.get('modules_succeeded', 0)}",
        f"Average confidence: {report_data.get('avg_asr', 0.0):.0%}",
        (
            "Methodology note: FRACTURE report assessments are automated heuristic "
            "signals. Use them for triage and manually validate externally significant findings."
        ),
        "",
        "Findings Summary",
        f"Confirmed: {findings.get('confirmed', 0)}",
        f"Probable: {findings.get('probable', 0)}",
        f"Possible: {findings.get('possible', 0)}",
        f"Negative: {findings.get('negative', 0)}",
    ]
    for summary_line in list(findings.get("executive_summary", []) or [])[:3]:
        lines.append(f"Executive signal: {summary_line}")
    top_signals = list(findings.get("top_signals", []) or [])
    if top_signals:
        lines.append(f"Top signals: {', '.join(top_signals[:4])}")
    lines.extend(["", "Module Results"])

    for module_name, result in results.items():
        lines.extend(
            [
                module_name,
                f"  Assessment: {result.get('assessment', 'unknown')}",
                f"  Module assessment: {result.get('module_assessment', 'unknown')}",
                f"  Confidence: {float(result.get('confidence', 0.0) or 0.0):.0%}",
                f"  Signal: {_meta_summary(result.get('evidence_meta', {}))}",
            ]
        )
        key_signals = list(result.get("key_signals", []) or [])
        if key_signals:
            lines.append(f"  Key signals: {', '.join(key_signals[:3])}")
        assessment_basis = list(result.get("assessment_basis", []) or [])
        if assessment_basis:
            lines.append(f"  Assessment basis: {', '.join(assessment_basis[:3])}")
        rationale = str(result.get("report_rationale", "") or "").strip()
        if rationale:
            lines.append(f"  Rationale: {rationale}")
        notes = str(result.get("notes", "") or "").strip()
        if notes:
            lines.append(f"  Notes: {notes}")
        lines.append("")

    return lines


def _wrap_line(text: str, width: int = 92) -> list[str]:
    text = str(text or "")
    if not text:
        return [""]

    words = text.split()
    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        candidate = f"{current} {word}"
        if len(candidate) <= width:
            current = candidate
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


def _escape_pdf_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def export_report_pdf(report, output_path: str) -> None:
    raw_lines = _build_lines(report)
    lines: list[str] = []
    for line in raw_lines:
        lines.extend(_wrap_line(line))

    lines_per_page = 44
    pages = [
        lines[index:index + lines_per_page]
        for index in range(0, len(lines), lines_per_page)
    ] or [["FRACTURE Security Assessment Report"]]

    objects: list[bytes] = []

    def add_object(payload: str) -> int:
        objects.append(payload.encode("latin-1", errors="replace"))
        return len(objects)

    font_obj = add_object("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    page_ids: list[int] = []
    content_ids: list[int] = []

    page_width = 612
    page_height = 792
    top_y = 760
    line_step = 16

    for page_lines in pages:
        commands = ["BT", "/F1 11 Tf", f"72 {top_y} Td"]
        first_line = True
        for line in page_lines:
            escaped = _escape_pdf_text(line)
            if first_line:
                commands.append(f"({escaped}) Tj")
                first_line = False
            else:
                commands.append(f"0 -{line_step} Td")
                commands.append(f"({escaped}) Tj")
        commands.append("ET")
        stream = "\n".join(commands)
        content_obj = add_object(
            f"<< /Length {len(stream.encode('latin-1', errors='replace'))} >>\nstream\n{stream}\nendstream"
        )
        content_ids.append(content_obj)
        page_ids.append(0)

    kids_refs = " ".join(f"{index + 3} 0 R" for index in range(len(pages)))
    pages_obj = add_object(
        f"<< /Type /Pages /Kids [{kids_refs}] /Count {len(pages)} >>"
    )

    for idx, content_obj in enumerate(content_ids):
        page_obj = (
            f"<< /Type /Page /Parent {pages_obj} 0 R /MediaBox [0 0 {page_width} {page_height}] "
            f"/Resources << /Font << /F1 {font_obj} 0 R >> >> /Contents {content_obj} 0 R >>"
        )
        page_ids[idx] = add_object(page_obj)

    catalog_obj = add_object(f"<< /Type /Catalog /Pages {pages_obj} 0 R >>")

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for obj_id, payload in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{obj_id} 0 obj\n".encode("latin-1"))
        output.extend(payload)
        output.extend(b"\nendobj\n")

    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))
    output.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_obj} 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("latin-1")
    )

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(output)
