from scapy.all import sniff, Dot11Deauth
import yaml
from database import insert_log
import logging

try:
    with open("config.yaml") as f:
        config = yaml.safe_load(f)
    interface = config.get('interface')
    log_level = getattr(logging, config.get('log_level', 'INFO').upper(), logging.INFO)
except Exception as e:
    logging.basicConfig(level=logging.INFO)
    logging.error(f"Failed to load config.yaml: {e}")
    exit(1)

logging.basicConfig(level=log_level)

if not interface:
    logging.error("No interface specified in config.yaml.")
    exit(1)

def handle_packet(pkt):
    if pkt.haslayer(Dot11Deauth):
        mac = getattr(pkt, 'addr2', "Unknown")
        signal = getattr(pkt, 'dBm_AntSignal', "?")
        # Extract channel from Dot11Elt with ID 3 (DS Parameter Set)
        channel_val = "Unknown"
        elt = pkt.getlayer('Dot11Elt')
        while elt is not None:
            if hasattr(elt, 'ID') and elt.ID == 3:
                try:
                    channel_val = str(elt.info[0])
                except Exception:
                    channel_val = "Unknown"
                break
            elt = elt.payload.getlayer('Dot11Elt')
        msg = "DeAuthentication"
        insert_log(mac, signal, channel_val, msg)
        logging.info(f"DeAuth detected: MAC={mac}, Signal={signal}, Channel={channel_val}")

logging.info(f"[*] Starting Wi-Fi sniffing on interface: {interface}")
try:
    sniff(prn=handle_packet, iface=interface, store=0)
except KeyboardInterrupt:
    logging.info("[*] Sniffing stopped by user.")
except Exception as e:
    logging.error(f"Error during sniffing: {e}")
