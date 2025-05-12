# jan (HackMyVM) - Penetration Test Bericht

![jan.png](jan.png)

**Datum des Berichts:** 30. Januar 2025  
**VM:** jan  
**Plattform:** HackMyVM [https://hackmyvm.eu/machines/machine.php?vm=jan](https://hackmyvm.eu/machines/machine.php?vm=jan)  
**Autor der VM:** DarkSpirit  
**Original Writeup:** [https://alientec1908.github.io/jan_HackMyVM_Easy/](https://alientec1908.github.io/jan_HackMyVM_Easy/)

---

## Disclaimer

**Wichtiger Hinweis:** Dieser Bericht und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die hier beschriebenen Techniken und Werkzeuge dürfen nur in legalen und autorisierten Umgebungen (z.B. auf eigenen Systemen oder mit ausdrücklicher Genehmigung des Eigentümers) angewendet werden. Jegliche illegale Nutzung der hier bereitgestellten Informationen ist strengstens untersagt. Der Autor übernimmt keine Haftung für Schäden, die durch Missbrauch dieser Informationen entstehen. Handeln Sie stets verantwortungsbewusst und ethisch.

---

## Inhaltsverzeichnis

1.  [Zusammenfassung](#zusammenfassung)
2.  [Verwendete Tools](#verwendete-tools)
3.  [Phase 1: Reconnaissance & Scans](#phase-1-reconnaissance--scans)
4.  [Phase 2: Web Enumeration & Initial Access (SSRF & Credential Disclosure)](#phase-2-web-enumeration--initial-access-ssrf--credential-disclosure)
5.  [Phase 3: Privilege Escalation (Sudo & SSH Banner Abuse)](#phase-3-privilege-escalation-sudo--ssh-banner-abuse)
6.  [Proof of Concept (Root Access via SSH Banner)](#proof-of-concept-root-access-via-ssh-banner)
7.  [Flags](#flags)
8.  [Empfohlene Maßnahmen (Mitigation)](#empfohlene-maßnahmen-mitigation)

---

## Zusammenfassung

Dieser Bericht dokumentiert die Kompromittierung der virtuellen Maschine "jan" von HackMyVM (Schwierigkeitsgrad: Easy). Die initiale Erkundung offenbarte offene SSH- (Port 22) und HTTP-Proxy-Dienste (Port 8080). Die Web-Enumeration führte zur Entdeckung der Pfade `/redirect` und `/credz`. Der `/redirect`-Endpunkt war anfällig für eine Schwachstelle in der Parameterverarbeitung, die es erlaubte, durch Übergabe zweier `url`-Parameter (z.B. `?url=ben&url=/credz`) auf den internen `/credz`-Endpunkt zuzugreifen. Dieser enthielt die Klartext-Zugangsdaten `ssh:EazyLOL`. Damit war ein SSH-Login als Benutzer `ssh` möglich.

Die Privilegieneskalation zu Root-Rechten erfolgte durch Ausnutzung einer unsicheren `sudo`-Konfiguration. Der Benutzer `ssh` durfte den SSH-Dienst (`/sbin/service sshd restart`) als `root` ohne Passwort neustarten. Da der Benutzer `ssh` (impliziert durch den Erfolg des Angriffs) Schreibrechte auf die SSH-Konfigurationsdatei `/etc/ssh/sshd_config` hatte, konnte die `Banner`-Direktive so manipuliert werden, dass sie auf `/root/root.txt` zeigte. Nach einem Neustart des SSH-Dienstes wurde der Inhalt der Root-Flag-Datei beim nächsten SSH-Login-Versuch als Banner angezeigt.

---

## Verwendete Tools

*   `nmap`
*   `curl`
*   `nikto`
*   `dirb`
*   `hydra`
*   `wfuzz`
*   `ssh`
*   `proxychains` (versucht, nicht erfolgreich für Exploit)
*   `ffuf`
*   `bettercap` (versucht, nicht erfolgreich für Exploit)
*   `python3`
*   `vi`, `nano` (impliziert)
*   `grep`, `find`, `cat`, `echo`, `ls`, `id`, `service`
*   `sudo`
*   `john` (versucht, nicht erfolgreich für Exploit)

---

## Phase 1: Reconnaissance & Scans

1.  **Netzwerk-Scan und Host-Konfiguration:**
    *   Eine variable IP-Adresse wurde während des Tests verwendet (zuletzt `192.168.2.170`). Die MAC-Adresse deutete auf VirtualBox hin.
    *   Der Hostname `jan.hmv` wurde der lokalen `/etc/hosts`-Datei hinzugefügt.

2.  **Port-Scan (Nmap auf `192.168.2.166` initial, dann `192.168.2.170`):**
    *   Ein umfassender `nmap`-Scan offenbarte:
        *   **Port 22 (SSH):** OpenSSH 9.9
        *   **Port 8080 (HTTP-Proxy):** Dienst nicht eindeutig erkannt, Nmap meldete "Welcome to our Public Server. Maybe Internal." bei GET-Anfragen.
    *   `nikto` auf Port 8080 fand fehlende Sicherheitsheader und potenziell interessante Backup-Dateien (wurden nicht weiter verfolgt).
    *   `dirb` auf Port 8080 fand `/redirect` und `/robots.txt`.

---

## Phase 2: Web Enumeration & Initial Access (SSRF & Credential Disclosure)

1.  **Analyse von `robots.txt` und Web-Pfaden:**
    *   `/robots.txt` enthielt `/redirect` und `/credz`.
    *   Direkter Aufruf von `http://[IP]:8080/credz` ergab "Only accessible internally.".
    *   Direkter Aufruf von `http://[IP]:8080/redirect` ergab "Parameter 'url' needed.".

2.  **SSRF-Versuche und Parameter-Schwachstelle:**
    *   Diverse SSRF-Versuche über `/redirect?url=[ZIEL]` auf interne und externe Ziele scheiterten zunächst.
    *   Der Durchbruch gelang durch Übergabe zweier `url`-Parameter an `/redirect`:
        ```bash
        curl -X GET "http://192.168.2.170:8080/redirect?url=ben&url=/credz"
        # Ausgabe: ssh/EazyLOL
        ```
    *   Dies umging die Zugriffsbeschränkung auf `/credz` und enthüllte die Zugangsdaten:
        *   Benutzer: `ssh`
        *   Passwort: `EazyLOL`

3.  **SSH-Login als `ssh`:**
    *   `ssh ssh@192.168.2.170` mit dem Passwort `EazyLOL` war erfolgreich.
    *   Initialer Zugriff als `ssh` auf dem System `jan` wurde erlangt.
    *   Die User-Flag `HMVSSWYMCNFIBDAFMTHFK` wurde in `/home/ssh/user.txt` gefunden.

---

## Phase 3: Privilege Escalation (Sudo & SSH Banner Abuse)

1.  **Sudo-Rechte-Prüfung für `ssh`:**
    *   `jan:~$ sudo -l` zeigte:
        ```
        User ssh may run the following commands on jan:
            (root) NOPASSWD: /sbin/service sshd restart
        ```
    *   Der Benutzer `ssh` durfte den SSH-Dienst (`sshd`) als `root` ohne Passwort neu starten.

2.  **Manipulation der SSH-Konfiguration (`/etc/ssh/sshd_config`):**
    *   Die Datei `/etc/ssh/sshd_config` wurde bearbeitet (impliziert, dass `ssh` Schreibrechte hatte oder `nano` über eine andere Lücke mit Root-Rechten ausgeführt werden konnte, was im Log nicht klar wird).
    *   Die `Banner`-Direktive wurde auf `/root/root.txt` gesetzt:
        ```ini
        # In /etc/ssh/sshd_config:
        Banner /root/root.txt
        ```
    *   Versuche, `/root/.ssh/id_rsa` oder `/etc/shadow` über den Banner auszulesen, wurden ebenfalls dokumentiert, wobei `/etc/shadow` erfolgreich war, aber für den finalen Flag-Zugriff nicht benötigt wurde.

3.  **Neustart des SSH-Dienstes:**
    *   Der SSH-Dienst wurde mit den `sudo`-Rechten neu gestartet:
        ```bash
        sudo /sbin/service sshd restart
        ```
    *   Die aktuelle SSH-Verbindung wurde dabei getrennt.

4.  **Auslesen der Root-Flag über SSH-Banner:**
    *   Beim erneuten Verbindungsversuch per SSH (`ssh ssh@192.168.2.170`) wurde der Inhalt von `/root/root.txt` als Banner vor der Passwortabfrage angezeigt.
    *   Die Root-Flag `HMV2PRMTERWTFUDNGMBG` wurde erfolgreich ausgelesen.

---

## Proof of Concept (Root Access via SSH Banner)

**Kurzbeschreibung:** Die Privilegieneskalation nutzte eine `sudo`-Regel, die dem Benutzer `ssh` erlaubte, den SSH-Dienst als `root` ohne Passwort neu zu starten. In Kombination mit der (implizierten) Fähigkeit, die SSH-Konfigurationsdatei `/etc/ssh/sshd_config` zu bearbeiten, wurde die `Banner`-Direktive auf `/root/root.txt` gesetzt. Nach dem Neustart des SSH-Dienstes wurde der Inhalt dieser Datei jedem sich verbindenden Benutzer vor der Authentifizierung angezeigt.

**Schritte (als `ssh`):**
1.  Bearbeite die SSH-Konfigurationsdatei `/etc/ssh/sshd_config`:
    ```bash
    # nano /etc/ssh/sshd_config 
    # Ändere oder füge hinzu:
    # Banner /root/root.txt
    ```
    Speichere die Datei.
2.  Starte den SSH-Dienst neu mit `sudo`:
    ```bash
    sudo /sbin/service sshd restart
    ```
    (Die aktuelle SSH-Verbindung wird getrennt).
3.  Versuche, dich erneut per SSH zu verbinden (von der Angreifer-Maschine):
    ```bash
    ssh ssh@192.168.2.170
    ```
**Ergebnis:** Der Inhalt von `/root/root.txt` (die Root-Flagge) wird als SSH-Banner angezeigt, bevor eine Passwortabfrage erfolgt.

---

## Flags

*   **User Flag (`/home/ssh/user.txt`):**
    ```
    HMVSSWYMCNFIBDAFMTHFK
    ```
*   **Root Flag (ausgelesen via SSH-Banner, Inhalt von `/root/root.txt`):**
    ```
    HMV2PRMTERWTFUDNGMBG
    ```

---

## Empfohlene Maßnahmen (Mitigation)

*   **Webanwendungssicherheit (Proxy/Redirect):**
    *   **DRINGEND:** Korrigieren Sie die unsichere Parameterverarbeitung im `/redirect`-Endpunkt. Stellen Sie sicher, dass doppelte Parameter korrekt behandelt werden und nicht zur Umgehung von Sicherheitsprüfungen führen.
    *   Implementieren Sie eine strikte Whitelist für erlaubte Ziel-URLs im `/redirect`-Endpunkt, um SSRF-Angriffe zu verhindern. Blockieren Sie Zugriffe auf interne Ressourcen und das `file://`-Protokoll.
*   **Credential Management:**
    *   **Entfernen Sie den `/credz`-Endpunkt oder sichern Sie ihn mit starker Authentifizierung und Autorisierung.** Speichern Sie Zugangsdaten niemals im Klartext oder an leicht zugänglichen Stellen.
    *   Erzwingen Sie starke, einzigartige Passwörter für alle Benutzerkonten.
*   **Sudo-Konfiguration:**
    *   **DRINGEND:** Überprüfen und härten Sie die `sudo`-Regeln. Entfernen Sie die Berechtigung für den Benutzer `ssh` (oder andere unprivilegierte Benutzer), den SSH-Dienst (`/sbin/service sshd restart`) als `root` neu zu starten. Solche Rechte sollten nur absolut notwendigen Administratoren vorbehalten sein.
*   **SSH-Konfigurationssicherheit:**
    *   Stellen Sie sicher, dass die SSH-Konfigurationsdatei `/etc/ssh/sshd_config` nur für den `root`-Benutzer schreibbar ist.
    *   Überdenken Sie die Verwendung der `Banner`-Funktion kritisch. Wenn sie verwendet wird, stellen Sie sicher, dass die referenzierte Datei keine sensiblen Informationen enthält und nicht von unprivilegierten Benutzern manipuliert werden kann.
*   **Allgemeine Webserver-Sicherheit:**
    *   Implementieren Sie fehlende Sicherheitsheader (`X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`).
    *   Entfernen Sie potenziell sensible Backup-Dateien aus dem Web-Root.
*   **Netzwerksicherheit:**
    *   Verwenden Sie feste IP-Adressen für Server, um Verwirrung und Tracking-Probleme zu vermeiden.
*   **Systemhärtung:**
    *   Überwachen Sie SSH-Logins und Systemlogs auf verdächtige Aktivitäten.
    *   Führen Sie regelmäßige Sicherheitsaudits und Schwachstellenscans durch.

---

**Ben C. - Cyber Security Reports**
