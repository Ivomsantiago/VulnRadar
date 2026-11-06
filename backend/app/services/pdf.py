"""Small paginated PDF writer for local technical reports (no browser/service dependency)."""

import textwrap


def report_pdf(title, lines):
    wrapped = []
    for line in lines:
        wrapped.extend(textwrap.wrap(str(line), width=92, replace_whitespace=False) or [""])
    chunks = [wrapped[index : index + 48] for index in range(0, len(wrapped), 48)] or [[]]
    objects = [
        b"",
        b"",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
    ]

    def literal(text):
        return str(text).encode("cp1252", errors="replace").replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)").replace(b"\r", b" ").replace(b"\n", b" ")

    pages = []
    for index, chunk in enumerate(chunks):
        page_id, stream_id = len(objects) + 1, len(objects) + 2
        pages.append(page_id)
        stream = b"BT /F2 16 Tf 42 800 Td (" + literal(title) + b") Tj ET\nBT /F1 9 Tf 42 772 Td 14 TL\n"
        for line in chunk:
            stream += b"(" + literal(line) + b") Tj T*\n"
        stream += b"ET\nBT /F1 8 Tf 42 28 Td (" + literal(f"VulnRadar | Página {index + 1}/{len(chunks)} | Dados das fontes e análises registradas") + b") Tj ET"
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {stream_id} 0 R >>".encode())
        objects.append(f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream")
    objects[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects[1] = f"<< /Type /Pages /Kids [{' '.join(f'{page} 0 R' for page in pages)}] /Count {len(pages)} >>".encode()
    output, offsets = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"), [0]
    for index, body in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode() + body + b"\nendobj\n")
    position = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{position}\n%%EOF\n".encode())
    return bytes(output)
