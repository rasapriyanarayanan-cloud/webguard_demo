import io
from flask import Flask, render_template, request, jsonify, send_file
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from scanner import scan

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.post("/api/scan")
def api_scan():
    d = request.get_json(force=True)
    if not d.get("consent"):
        return jsonify(error="Please confirm you own or have permission to test this site."), 400
    try:
        return jsonify(scan(d.get("url", ""), d.get("mode", "public")))
    except ValueError as e:
        return jsonify(error=str(e)), 400
    except Exception as e:
        return jsonify(error=f"Scan failed: {type(e).__name__}"), 502

@app.post("/api/report")
def api_report():
    r = request.get_json(force=True)
    ss, buf = getSampleStyleSheet(), io.BytesIO()
    el = [Paragraph("WebGuard Security Report", ss["Title"]),
          Paragraph(f"Target: {r['url']}<br/>Scanned: {r['scanned_at']}<br/>Score: {r['score']}/100 ({r['risk']})", ss["Normal"]),
          Spacer(1, 12)]
    rows = [["Check", "Status", "Details"]] + [[Paragraph(f["title"], ss["Normal"]), f["status"].upper(), Paragraph(f["detail"], ss["Normal"])] for f in r["findings"]]
    t = Table(rows, colWidths=[150, 60, 280])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1d4ed8")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                           ("GRID", (0, 0), (-1, -1), .4, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    el += [t, Spacer(1, 14), Paragraph("Recommended Fixes (nginx examples)", ss["Heading2"])]
    for f in r["findings"]:
        if f["status"] in ("review", "info"):
            el += [Paragraph(f"<b>{f['title']}</b>: {f['fix']['problem']} {f['fix']['solution']}", ss["Normal"]),
                   Paragraph(f"<font name='Courier' size=8>{f['fix']['snippet']}</font>", ss["Normal"]), Spacer(1, 6)]
    el.append(Paragraph("Note: basic header assessment only; not a full penetration test.", ss["Italic"]))
    SimpleDocTemplate(buf, pagesize=A4).build(el); buf.seek(0)
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name="webguard_report.pdf")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
