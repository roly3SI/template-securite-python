import json
from fpdf import FPDF


class Report:
    def __init__(self, result: dict) -> None:
        self.result = result

    def generate_pdf(self, out_pdf: str) -> None:
        """Rapport PDF lisible (fpdf2)."""
        pdf = FPDF()
        pdf.add_page()

        pdf.set_font("helvetica", style="B", size=16)
        pdf.cell(0, 10, f"Rapport Triage SOC : {self.result.get('sha256', 'Inconnu')}", ln=True, align="C")
        pdf.ln(10)

        pdf.set_font("helvetica", size=12)
        pdf.cell(0, 8, f"Score de dangerosité : {self.result.get('score', 0)} / 10", ln=True)
        pdf.cell(0, 8, f"Famille suspectée : {self.result.get('family_guess', 'Inconnue')}", ln=True)
        pdf.cell(0, 8, f"Type de fichier : {self.result.get('file_type', '')}", ln=True)
        pdf.cell(0, 8, f"Entropie de Shannon : {self.result.get('entropy', 0.0)}", ln=True)
        pdf.ln(5)

        pdf.set_font("helvetica", style="B", size=14)
        pdf.cell(0, 10, "Analyse détaillée (LLM) :", ln=True)
        pdf.set_font("helvetica", size=12)
        pdf.multi_cell(0, 8, txt=str(self.result.get("llm_summary", "")))

        pdf.output(out_pdf)

    def generate_json(self, out_json: str) -> None:
        """Fichier JSON lisible."""
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(self.result, f, indent=2, ensure_ascii=False)
