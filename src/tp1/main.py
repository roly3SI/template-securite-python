import argparse
from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report

def parse_args():
    #On gère les arguments de la command line
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", required=True, type=str)
    parser.add_argument("--out", default="report.json", type=str)
    return parser.parse_args()

def main():
    logger.info("Starting TP1")
    args = parse_args()

    #Lecture et analyse du fichier pcap
    capture = Capture()
    capture.read_pcap(args.pcap)
    capture.analyse()
    summary = capture.get_summary()

    filename = "report.pdf"
    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")
    report.save(filename)


if __name__ == "__main__":
    main()