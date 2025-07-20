import pyshark

def capture_live(interface="eth0"):
    cap = pyshark.LiveCapture(interface=interface)
    cap.sniff(timeout=10)
    return cap
