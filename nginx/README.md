# NGINX Installer - Modular Version

Een vereenvoudigde en modulaire versie van de NGINX installer die het originele script opsplitst in kleinere, beheerbare componenten.

## Structuur

```
nginx-installer/
├── nginx_installer.sh          # Hoofdscript (vereenvoudigd)
├── config/
│   └── versions.conf           # Versie configuratie
├── lib/
│   ├── common.sh              # Algemene functies
│   ├── download.sh            # Download en verificatie
│   ├── build.sh               # Build functies
│   ├── install.sh             # Installatie functies
│   └── service.sh             # Service management
└── templates/
    ├── nginx_conf.sh          # NGINX configuratie templates
    └── html_files.sh          # HTML bestanden templates
```

## Voordelen van de modulaire aanpak

1. **Eenvoudiger onderhoud**: Elke functionaliteit zit in een eigen bestand
2. **Betere leesbaarheid**: Kleinere bestanden zijn makkelijker te begrijpen
3. **Herbruikbaarheid**: Modules kunnen apart gebruikt worden
4. **Uitbreidbaarheid**: Nieuwe functies kunnen gemakkelijk toegevoegd worden
5. **Debugging**: Problemen zijn makkelijker te lokaliseren

## Gebruik

Het gebruik blijft hetzelfde als het originele script:

```bash
# Installeren
sudo ./nginx_installer.sh install

# Verwijderen
sudo ./nginx_installer.sh remove

# Verificatie
sudo ./nginx_installer.sh verify
```

## Environment variabelen

Alle originele environment variabelen blijven werken:

```bash
CONFIRM=yes ./nginx_installer.sh install
ENABLE_ZSTD=0 ./nginx_installer.sh install
ENABLE_STREAM=0 ./nginx_installer.sh install
CHECKSUM_POLICY=allow-missing ./nginx_installer.sh install
```

## Aanpassingen maken

### Versies bijwerken
Bewerk `config/versions.conf` om nieuwe versies in te stellen.

### Configuratie aanpassen
Bewerk `templates/nginx_conf.sh` voor NGINX configuratie wijzigingen.

### HTML paginas aanpassen
Bewerk `templates/html_files.sh` voor custom error paginas of index pagina.

### Nieuwe functies toevoegen
Voeg nieuwe functies toe aan de juiste library in `lib/` of maak een nieuwe library.

## Bestanden overzicht

- **nginx_installer.sh**: Hoofdscript met commandline interface
- **config/versions.conf**: Alle versienummers en URLs
- **lib/common.sh**: Logging, error handling, validatie
- **lib/download.sh**: Download en checksum verificatie
- **lib/build.sh**: OpenSSL en NGINX compilatie
- **lib/install.sh**: Installatie en configuratie
- **lib/service.sh**: Systemd service management en verificatie
- **templates/nginx_conf.sh**: NGINX configuratie bestanden
- **templates/html_files.sh**: Default HTML bestanden

Deze modulaire aanpak maakt het script veel eenvoudiger om te onderhouden en uit te breiden, terwijl alle functionaliteit van het originele script behouden blijft.
