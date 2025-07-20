from modules.pcap_parser import process_pcap
from modules.live_capture import capture_live
from modules.alert_generator import generate_alerts
from modules.ioc_extractor import extract_iocs
from modules.utils import log_event

def run_analysis(input_source, config_path):
    log_event(f"Starting analysis: {input_source}")
    if input_source == "live":
        packets = capture_live()
    else:
        packets = process_pcap(input_source)

    extract_iocs(packets)
    generate_alerts(packets)
    log_event("Analysis completed.")
