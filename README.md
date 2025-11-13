# Masscan Inventar Scanner

**Version:** 3.1.0  
**Autor:** heckpiet  
**Lizenz:** MIT

Ein schneller, parallelisierter Inventarscanner auf Basis von `masscan`.  
Der Scanner liest Zielnetze aus einer Textdatei, führt parallele Scans aus, parst Masscan-Ergebnisse und erzeugt eine vollständige Inventarübersicht.

Ideal zur schnellen Erkennung von:
- aktiven Hosts  
- offenen Ports  
- einfachen Gerätetyp-Indikatoren  
- Netzstrukturoberblicken in großen Umgebungen  

---

## ✨ Features

- Liest Zielnetze und Hosts aus einer Textdatei  
- Unterstützt IPv4 und IPv6  
- IPv6-Netze werden automatisch gesplittet (z. B. /32 → /48), um Masscan-Limits zu umgehen  
- Masscan läuft parallel für maximale Geschwindigkeit  
- Ergebnisse je Ziel:
  - JSON-Rohdaten  
  - CSV  
  - JSON (parsed)  
  - menschlich lesbare Zusammenfassung  
- Gesamtinventar für **alle** gefundenen Hosts:
  - `inventory_hosts.csv`
  - `inventory_hosts.json`
  - `inventory_hosts_report.txt` (menschenlesbarer Textreport)
- Ein sauber strukturierter Output-Ordner:

---

Masscan_Inventar_Scanner_YYYYMMDD_HHMMSS/
├── logs/
│ ├── masscan.log
│ └── errors.log
├── output/
│ ├── <target>_masscan_output.json
│ ├── <target>_parsed.csv
│ ├── <target>_parsed.json
│ ├── <target>_summary.txt
│ ├── inventory_hosts.csv
│ ├── inventory_hosts.json
│ └── inventory_hosts_report.txt
└── html/ (Reserviert für spätere Web-Infos)


---

## 📦 Installation

### Debian / Ubuntu Beispiel:

```bash
sudo apt update
sudo apt install -y masscan python3 python3-pip

Python-Pakete:
pip3 install -r requirements.txt


(Aktuell minimale Dependencies)

Python-Pakete:
pip3 install -r requirements.txt


(Aktuell minimale Dependencies)

📝 targets.txt Beispiel
# IPv4 / IPv6 Netze oder einzelne Hosts
10.140.104.1/24
192.168.100.10
2001:db8::/32

🚀 Nutzung

Einfachster Lauf:

sudo python3 masscan_inventar_scanner.py -f targets.txt


mit eigenen Ports:

sudo python3 masscan_inventar_scanner.py -f targets.txt -p 22,80,443


mit erhöhter Geschwindigkeit und mehr Parallelität:

sudo python3 masscan_inventar_scanner.py -f targets.txt -r 5000 --concurrency 10


Ausgabeverzeichnis anpassen:

sudo python3 masscan_inventar_scanner.py -f targets.txt --outdir /tmp/inventar

⚠️ Hinweis zu Berechtigungen

Masscan benötigt für Raw-Sockets üblicherweise Root-Rechte:

sudo masscan ...


oder sicherer:

sudo setcap cap_net_raw,cap_net_admin+ep $(which masscan)
