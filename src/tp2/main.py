import argparse
import os
from tp2.utils.report import Report
from tp2.utils.triage import Triage


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", required=True, help="Dossier contenant les samples")
    ap.add_argument("--rules", required=True, help="Dossier contenant les règles YARA")
    ap.add_argument("--out", required=True, help="Dossier pour les résultats")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    for filename in os.listdir(args.samples):
        filepath = os.path.join(args.samples, filename)

    if os.path.isfile(filepath):
        triage = Triage(filepath, backend="openrouter")
        triage.scanner.rules_path = args.rules
        result = triage.run()
        out_name = result.get("sha256", filename)
        report = Report(result)
        report.generate_json(os.path.join(args.out, f"{out_name}.triage.json"))

        try:
            report.generate_pdf(os.path.join(args.out, f"{out_name}.pdf"))
        except NotImplementedError:
            pass


if __name__ == "__main__":
    main()
