import re  # Importation du module des expressions régulières pour la recherche de motifs
import os  # Importation du module OS pour la gestion des fichiers et chemins

ISO_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2})?")
SEVERITY_TOKEN_RE = re.compile(r"<\s*(debug|info|notice|warn|warning|err|error|crit|critical)\s*>", re.IGNORECASE)
ISO_LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2})?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>[^\s:]+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)


def _extract_fields(line: str):
    m = ISO_LINE_RE.match(line)
    if not m:
        return {
            "timestamp": None,
            "host": None,
            "service": None,
            "message": line,
            "token_severity": None,
        }
    msg = (m.group("message") or "").strip()
    tok = SEVERITY_TOKEN_RE.search(msg)
    return {
        "timestamp": m.group("timestamp"),
        "host": m.group("host"),
        "service": m.group("service"),
        "message": msg,
        "token_severity": tok.group(1).lower() if tok else None,
    }

def parse_log_file(filepath):
    """
    Fonction principale pour analyser un fichier de log et classifier ses lignes.
    """
    # Initialisation du dictionnaire qui contiendra les lignes classées par niveau de sévérité
    segments = {
        'ERROR': [],
        'WARNING': [],
        'INFO': [],
        'DEBUG': []
    }
    
    # Définition des motifs (Regex) pour identifier chaque catégorie (Insensible à la casse)
    patterns = {
        'ERROR': re.compile(r'\b(error|err|fail(?:ed|ure)?|critical|severe|panic|fatal|denied)\b', re.IGNORECASE),
        'WARNING': re.compile(r'\b(warning|warn|timeout|retry|degraded)\b', re.IGNORECASE),
        'INFO': re.compile(r'\b(info|notice)\b', re.IGNORECASE),
        'DEBUG': re.compile(r'\bdebug\b', re.IGNORECASE)
    }

    # Vérification de l'existence du fichier avant l'ouverture pour éviter les plantages
    if not os.path.exists(filepath):
        return segments

    # Ouverture du fichier en mode lecture avec gestion des erreurs d'encodage
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()  # Suppression des espaces et sauts de ligne inutiles
            
            if not line:  # Ignorer les lignes vides
                continue
                
            # Guard: ignore malformed lines without obvious timestamp header.
            # Accept both ISO ("2026-04-08T14:56:03...") and classic syslog style.
            has_ts = bool(ISO_TS_RE.search(line) or re.match(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', line))
            if not has_ts:
                continue

            # First, map explicit syslog tokens like "<info>", "<warn>", "<err>".
            fields = _extract_fields(line)
            raw = fields.get("token_severity")
            if raw:
                if raw in ('err', 'error', 'crit', 'critical'):
                    segments['ERROR'].append(line)
                    continue
                if raw in ('warn', 'warning'):
                    segments['WARNING'].append(line)
                    continue
                if raw in ('debug',):
                    segments['DEBUG'].append(line)
                    continue
                segments['INFO'].append(line)
                continue

            found = False
            # Parcours des motifs définis pour classifier la ligne actuelle
            for level, pattern in patterns.items():
                if pattern.search(line):
                    segments[level].append(line)  # Ajout de la ligne au segment correspondant
                    found = True
                    break  # Arrêter la recherche dès qu'un motif est trouvé
            
            # Si aucun motif spécifique n'est trouvé, classer la ligne par défaut dans INFO
            if not found:
                segments['INFO'].append(line)
                
    return segments  # Retourne le dictionnaire final contenant tous les logs triés