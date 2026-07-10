NETZWERK-SCANNER – EINFACHER START

WINDOWS
1. Alle Dateien in denselben Ordner entpacken.
2. Doppelklick auf: Netzwerkscanner-starten-Windows.cmd
3. Falls Windows nach Rechten fragt, bestaetigen.
4. Nach dem Scan oeffnet sich der HTML-Bericht automatisch.

LINUX
1. Alle Dateien in denselben Ordner entpacken.
2. Terminal im Ordner oeffnen.
3. Einmal ausfuehren:
   chmod +x netzwerkscanner-starten-linux.sh
4. Danach starten mit:
   ./netzwerkscanner-starten-linux.sh

Der einfache Modus:
- erkennt das lokale Netzwerk automatisch
- nimmt erreichbare und zuletzt bekannte Offline-Geraete auf
- liest ARP/Neighbor, DHCP-Leases und hosts-Datei
- erstellt CSV und HTML
- oeffnet den HTML-Bericht automatisch
- installiert kein Excel-Modul
- zeigt nach Abschluss kein kompliziertes Menue
