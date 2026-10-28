# Template code Sécurité Python

## Description

Projet contenant les modèles de TP pour le cours de sécurité Python de 4e année de l'ESGI.

## Installation

Faire un fork puis un clone du projet :

```bash
git clone git@github.com:<VotreNom>/template-securite-python.git
```

Installer les dépendances :

```bash
cd template-securite-python
poetry lock
poetry install
```

## Utilisation

Lancer le projet :

```bash
poetry run tp1
```

## TP1 - Analyse réseau

Ce projet est un outil d'analyse de trafic réseau (IDS/IPS) développé en Python avec la bibliothèque Scapy. Il permet de lire une capture réseau (fichier `.pcap`), d'en extraire des statistiques par protocole, et de détecter d'éventuelles attaques.

### Fonctionnalités

* **Statistiques des protocoles :** Comptage des paquets Ethernet, ARP, IP, TCP, UDP, ICMP, DNS et HTTP.

* **Détection d'attaques :**

  * **ARP Spoofing :** Repérage des conflits d'adresses MAC pour une même adresse IP.

  * **Port Scanning :** Détection d'un grand nombre de requêtes SYN vers des ports distincts depuis une même source.

  * **Injection SQL :** Analyse de la charge utile (payload) à la recherche de signatures malveillantes (`UNION SELECT`, `1=1`, etc.).

* **Recherche de drapeau (Flag) :** Extraction automatique du flag (format `ESGI{...}`) si celui-ci est transmis par un attaquant identifié.

* **Génération de rapports :** Export des résultats sous format `report.json` et `report.pdf` (incluant un graphique SVG).

## TP2 - Projet outillé

Ce projet est un outil d'analyse statique automatisée de fichiers suspects. Il permet d'extraire des informations techniques approfondies d'un binaire et de rechercher des signatures malveillantes sans avoir à l'exécuter.

### Fonctionnalités

* **Identification de fichiers :** Utilisation de `python-magic` pour déterminer la véritable nature du fichier (PE, ELF, etc.) indépendamment de son extension.

* **Analyse d'exécutables (LIEF) :** Extraction des métadonnées du binaire, telles que les tables d'import/export et les propriétés des sections, pour repérer des anomalies ou du *packing*.

* **Analyse par signatures (YARA) :** Scan du fichier à l'aide de règles YARA pour détecter des patterns spécifiques ou des correspondances avec des malwares connus.

* **Recherche de drapeau (Flag) :** Extraction automatique du flag (format `ESGI{...}`) dissimulé au sein des structures ou des chaînes de caractères du binaire.

## TP3 - Capture the flag

Ce projet est un script d'exploitation automatisé de bout en bout. Il enchaîne une phase de reconnaissance web avec contournement de protection et une phase d'interaction réseau bas niveau (Sockets TCP) soumise à une contrainte de temps.

### Fonctionnalités

* **Fuzzing Web :** Découverte de ressources cachées (`/internal-panel`) par énumération de répertoires à l'aide d'une wordlist.

* **Contournement de CAPTCHA :** Maintien d'une session HTTP persistante (`requests`) et résolution automatisée de défis visuels via la reconnaissance optique de caractères (OCR avec `pytesseract` et `PIL`).

* **Résilience et Gestion d'erreurs :** Implémentation d'une boucle de rejeu transparente en cas d'erreur d'interprétation de l'OCR.

* **Exploitation de Socket TCP :** Bascule sur un protocole réseau (`pwntools`) pour interagir avec le service interne.

* **Décodage et Chiffrement à la volée :** Interception du flux réseau, décodage Base64, application d'un masque XOR avec la clé secrète, et renvoi instantané de la réponse au serveur pour valider le challenge.

* **Récupération de drapeaux :** Extraction automatique des deux drapeaux (Web et TCP final).

## Installation et Prérequis

Le projet utilise **Poetry** pour la gestion des dépendances.

**Prérequis spécifique au TP3 :** L'outil OCR **Tesseract** doit être installé sur la machine hôte et ajouté à la variable d'environnement `PATH`.

Pour installer l'environnement complet :

```bash
poetry lock
poetry install
```

## Exécution

**Lancer le TP1 :**

```bash
poetry run tp1 --pcap <chemin_vers_le_fichier.pcap> --out report.json
```

**Lancer le TP2 :**

```bash
poetry run tp2 --target <chemin_vers_le_binaire_suspect>
```

**Lancer le TP3 :**

```bash
poetry run tp3 --target http://127.0.0.1:8080
```

## Tests

Ce projet inclut des tests unitaires avec simulation d'environnements (Mocking des requêtes HTTP et de l'OCR pour le TP3).

Pour exécuter les tests :

```bash
poetry run pytest
```