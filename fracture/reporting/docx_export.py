from datetime import UTC, datetime
from pathlib import Path
from xml.sax.saxutils import escape
from zipfile import ZIP_DEFLATED, ZipFile


def _paragraph(text: str, bold: bool = False) -> str:
    text = escape(str(text or ""))
    if bold:
        return (
            "<w:p><w:r><w:rPr><w:b/></w:rPr>"
            f"<w:t xml:space=\"preserve\">{text}</w:t></w:r></w:p>"
        )
    return f"<w:p><w:r><w:t xml:space=\"preserve\">{text}</w:t></w:r></w:p>"


def _meta_summary(meta: dict) -> str:
    if not isinstance(meta, dict) or not meta:
        return "none"

    best = str(meta.get("best_classification", "")).strip()
    if best:
        return best

    pairs = []
    for key, value in meta.items():
        key_name = str(key or "")
        if any(token in key_name.lower() for token in ["cookie", "authorization", "token", "secret"]):
            value = "<redacted>"
        pairs.append(f"{key}={value}")
        if len(pairs) >= 3:
            break
    return ", ".join(pairs) if pairs else "meta present"


def export_report_docx(report, output_path: str) -> None:
    report_data = report.to_dict() if hasattr(report, "to_dict") else dict(report)
    findings = report_data.get("findings_summary", {}) or {}
    results = report_data.get("results", {}) or {}
    now = datetime.now(UTC).isoformat()

    body = []
    body.append(_paragraph("FRACTURE Security Assessment Report", bold=True))
    body.append(_paragraph(""))
    body.append(_paragraph("Executive Summary", bold=True))
    body.append(_paragraph(f"Target: {report_data.get('target_url', 'unknown')}"))
    body.append(_paragraph(f"Detected model: {report_data.get('detected_model', 'unknown')}"))
    body.append(_paragraph(f"Risk level: {report_data.get('risk_level', 'unknown')}"))
    body.append(_paragraph(f"Modules run: {report_data.get('modules_run', 0)}"))
    body.append(_paragraph(f"Modules succeeded: {report_data.get('modules_succeeded', 0)}"))
    body.append(_paragraph(f"Average confidence: {report_data.get('avg_asr', 0.0):.0%}"))
    body.append(
        _paragraph(
            "Methodology note: FRACTURE report assessments are automated heuristic signals. "
            "Use them for triage and manually validate externally significant findings."
        )
    )
    body.append(_paragraph(""))
    body.append(_paragraph("Findings Summary", bold=True))
    body.append(_paragraph(f"Confirmed: {findings.get('confirmed', 0)}"))
    body.append(_paragraph(f"Probable: {findings.get('probable', 0)}"))
    body.append(_paragraph(f"Possible: {findings.get('possible', 0)}"))
    body.append(_paragraph(f"Negative: {findings.get('negative', 0)}"))
    for summary_line in list(findings.get("executive_summary", []) or [])[:3]:
        body.append(_paragraph(f"Executive signal: {summary_line}"))
    top_signals = list(findings.get("top_signals", []) or [])
    if top_signals:
        body.append(_paragraph(f"Top signals: {', '.join(top_signals[:4])}"))
    body.append(_paragraph(""))
    body.append(_paragraph("Module Results", bold=True))

    for module_name, result in results.items():
        body.append(_paragraph(module_name, bold=True))
        body.append(_paragraph(f"Assessment: {result.get('assessment', 'unknown')}"))
        module_assessment = str(result.get("module_assessment", "") or "").strip()
        if module_assessment:
            body.append(_paragraph(f"Module assessment: {module_assessment}"))
        body.append(_paragraph(f"Confidence: {float(result.get('confidence', 0.0) or 0.0):.0%}"))
        body.append(_paragraph(f"Signal: {_meta_summary(result.get('evidence_meta', {}))}"))
        key_signals = list(result.get("key_signals", []) or [])
        if key_signals:
            body.append(_paragraph(f"Key signals: {', '.join(key_signals[:3])}"))
        assessment_basis = list(result.get("assessment_basis", []) or [])
        if assessment_basis:
            body.append(_paragraph(f"Assessment basis: {', '.join(assessment_basis[:3])}"))
        rationale = str(result.get("report_rationale", "") or "").strip()
        if rationale:
            body.append(_paragraph(f"Rationale: {rationale}"))
        notes = str(result.get("notes", "") or "").strip()
        if notes:
            body.append(_paragraph(f"Notes: {notes}"))
        body.append(_paragraph(""))

    document_xml = (
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        "<w:document "
        "xmlns:wpc=\"http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas\" "
        "xmlns:mc=\"http://schemas.openxmlformats.org/markup-compatibility/2006\" "
        "xmlns:o=\"urn:schemas-microsoft-com:office:office\" "
        "xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" "
        "xmlns:m=\"http://schemas.openxmlformats.org/officeDocument/2006/math\" "
        "xmlns:v=\"urn:schemas-microsoft-com:vml\" "
        "xmlns:wp14=\"http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing\" "
        "xmlns:wp=\"http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing\" "
        "xmlns:w10=\"urn:schemas-microsoft-com:office:word\" "
        "xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\" "
        "xmlns:w14=\"http://schemas.microsoft.com/office/word/2010/wordml\" "
        "xmlns:wpg=\"http://schemas.microsoft.com/office/word/2010/wordprocessingGroup\" "
        "xmlns:wpi=\"http://schemas.microsoft.com/office/word/2010/wordprocessingInk\" "
        "xmlns:wne=\"http://schemas.microsoft.com/office/word/2006/wordml\" "
        "xmlns:wps=\"http://schemas.microsoft.com/office/word/2010/wordprocessingShape\" "
        "mc:Ignorable=\"w14 wp14\">"
        "<w:body>"
        + "".join(body)
        + (
            "<w:sectPr>"
            "<w:pgSz w:w=\"12240\" w:h=\"15840\"/>"
            "<w:pgMar w:top=\"1440\" w:right=\"1440\" w:bottom=\"1440\" w:left=\"1440\" "
            "w:header=\"720\" w:footer=\"720\" w:gutter=\"0\"/>"
            "</w:sectPr>"
            "</w:body></w:document>"
        )
    )

    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"""

    root_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>"""

    document_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>"""

    core_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/"
 xmlns:dcterms="http://purl.org/dc/terms/"
 xmlns:dcmitype="http://purl.org/dc/dcmitype/"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>FRACTURE Security Assessment Report</dc:title>
  <dc:creator>FRACTURE</dc:creator>
  <cp:lastModifiedBy>FRACTURE</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">{escape(now)}</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">{escape(now)}</dcterms:modified>
</cp:coreProperties>"""

    app_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
 xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>FRACTURE</Application>
</Properties>"""

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", root_rels)
        archive.writestr("word/document.xml", document_xml)
        archive.writestr("word/_rels/document.xml.rels", document_rels)
        archive.writestr("docProps/core.xml", core_xml)
        archive.writestr("docProps/app.xml", app_xml)
