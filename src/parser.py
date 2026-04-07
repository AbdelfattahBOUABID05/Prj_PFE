import re  # Importation du module des expressions régulières pour la recherche de motifs
import os  # Importation du module OS pour la gestion des fichiers et chemins

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
        'ERROR': re.compile(r'error|fail|critical|severe', re.IGNORECASE),
        'WARNING': re.compile(r'warning|warn', re.IGNORECASE),
        'INFO': re.compile(r'info', re.IGNORECASE),
        'DEBUG': re.compile(r'debug', re.IGNORECASE)
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