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

