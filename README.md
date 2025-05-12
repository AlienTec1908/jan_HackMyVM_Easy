Webanwendung (Port 8080):
    Die Parameterverarbeitung für `/redirect` korrigieren, um doppelte Parameter oder unerwartete Eingaben sicher zu handhaben.
    Eine robuste Whitelist für erlaubte Ziel-URLs in `/redirect` implementieren und Zugriffe auf interne Ressourcen oder `file://` blockieren.
    Den Endpunkt `/credz` entfernen oder mit starker Authentifizierung/Autorisierung schützen. Zugangsdaten niemals in Klartext speichern oder über Web-Endpunkte verfügbar machen.
    Fehlende Sicherheitsheader (`X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, etc.) implementieren.
    Gefundene Backup-Dateien aus dem Web-Verzeichnis entfernen und sicherstellen, dass keine Backups in öffentlich zugängliche Bereiche geschrieben werden.
System & SSH:
    Die `sudo`-Regel für den Benutzer `ssh` entfernen oder so einschränken, dass der SSH-Dienst nicht mehr als root neu gestartet werden kann.
    Sicherstellen, dass die SSH-Konfigurationsdatei `/etc/ssh/sshd_config` nur für `root` schreibbar ist.
    SSH-Zugriff generell härten: Starke Passwörter oder (besser) Key-basierte Authentifizierung erzwingen. `Fail2ban` oder ähnliche Tools zur Abwehr von Brute-Force-Angriffen einsetzen.
    Die Verwendung der SSH-Banner-Funktion überdenken und deaktivieren, wenn sie nicht zwingend benötigt wird.
Allgemeine Sicherheitspraktiken:
    Regelmäßige Sicherheitsüberprüfungen und Penetrationstests durchführen.
    System und alle Komponenten aktuell halten (Patches).
    Logging und Monitoring von System- und Anwendungsereignissen implementieren.
