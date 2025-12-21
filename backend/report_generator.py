from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.colors import red, green, orange, black
from io import BytesIO
from datetime import datetime


def create_pdf_report(url, prediction, confidence, vt_score, risk_score, severity):
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)

    c.setFont("Helvetica-Bold", 20)
    c.drawString(50, 800, "Cyber Threat Analysis Report")

    c.setFont("Helvetica", 12)
    c.drawString(50, 770, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    c.drawString(50, 750, f"URL: {url}")

    c.drawString(50, 720, f"Prediction: {prediction}")
    c.drawString(50, 700, f"Confidence: {confidence:.2f}%")
    c.drawString(50, 680, f"Risk Score: {risk_score} ({severity})")

    c.save()
    buffer.seek(0)
    return buffer
