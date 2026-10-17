from tp1.utils.capture import Capture
import pygal
from fpdf import FPDF

class Report:
    def __init__(self, capture: Capture, filename: str, summary: dict):
        self.capture = capture
        self.filename = filename
        self.title = "Rapport d'Analyse"
        self.summary = summary
        self.array = ""
        self.graph_file = "graph.svg"

    def concat_report(self) -> str:
        return self.title + "\n" + self.array

    def save(self, filename: str) -> None:
        doc = FPDF()
        doc.add_page()

        doc.set_font("helvetica", style="B", size=16)
        doc.cell(w=0, h=10, txt=self.title, align="C", ln=1)
        doc.ln(10)

        #Contenu principal
        doc.set_font("helvetica", size=12)
        doc.multi_cell(w=0, h=8, txt=self.array)
        doc.ln(8)

        doc.set_font("helvetica", style="B", size=14)
        doc.cell(w=0, h=10, txt="Statistiques des protocoles :", ln=1)

        doc.set_font("helvetica", size=12)

        #Recupération et affichage des stats
        stats = self.summary.get("protocols", {})
        for p, count in stats.items():
            doc.cell(w=0, h=8, txt=f"- {p} : {count} paquets", ln=1)

        doc.ln(5)
        doc.set_text_color(100, 100, 100)
        doc.set_font("helvetica", style="I", size=10)

        info_graph = "Le graphique SVG est dans " + self.graph_file
        doc.cell(w=0, h=8, txt=info_graph, ln=1)

        doc.output(filename)

    def generate(self, param: str) -> None:
        if param == "graph":
            #Création du graphique
            bar_chart = pygal.Bar()
            bar_chart.title = "Volume par protocole"

            protocols = self.summary.get("protocols", {})
            for proto, count in protocols.items():
                bar_chart.add(proto, count)

            bar_chart.render_to_file(self.graph_file)

        elif param == "array":
            #Formatage du texte
            attacks = self.summary.get("attacks", [])
            flag = self.summary.get("flag", "Non trouvé")

            content = f"Flag trouvé : {flag}\n\n"
            content += "Alertes détectées :\n"

            if not attacks:
                content += "Aucune attaque.\n"
            else:
                for atk in attacks:
                    content += f"- {atk['type']} ciblant/depuis {atk['attacker']}\n"

            self.array = content