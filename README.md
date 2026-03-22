# Bootability Checker v2.0

**Auteurs** : DZOUAKEU FESSI Emmanuella Cindy · YAKAM TCHAMOU Rick Vadel  
**Examinateur** : M. NGUIMBUS, enseignant de SE  
**Institut** : Institut Universitaire Saint Jean

---

## Présentation

Outil d'analyse bas niveau de la **bootabilité** d'un disque physique.  
Détecte et valide sans aucune écriture sur le disque :

- **MBR** : signature `0x55AA` + présence d'une partition active (flag `0x80`)
- **GPT** : header LBA1, CRC32 ANSI du header et du tableau de partitions
- **Partitions de boot** : ESP (EFI System Partition), `freebsd-boot`, `freebsd-ufs`, `freebsd-zfs`, Linux root, partitions Windows et macOS
- **Disques hybrides** : MBR protectif (`0xEE`) + GPT
- **Secteurs 4Kn natifs** (4096 bytes/secteur)

---

## Deux itérations

| Fichier | Plateforme | Description |
|---------|-----------|-------------|
| `bootability_checker_freebsd.c` | FreeBSD | Natif FreeBSD, utilise `sysctl kern.disks`, `DIOCGSECTORSIZE` |
| `bootability_checker_cross.c`   | Universel | FreeBSD, Linux, Windows, macOS, OpenBSD, NetBSD |

---

## Compilation

### Itération 1 — FreeBSD

```sh
# Avec le Makefile
make -f Makefile_freebsd

# Ou manuellement
cc -std=c99 -Wall -Wextra -o bootability_checker bootability_checker_freebsd.c
```

### Itération 2 — Cross-platform

```sh
# Linux
gcc -std=c99 -Wall -Wextra -o bootability_checker bootability_checker_cross.c

# FreeBSD / OpenBSD / NetBSD
cc -std=c99 -Wall -Wextra -o bootability_checker bootability_checker_cross.c

# macOS
clang -std=c99 -Wall -Wextra -o bootability_checker bootability_checker_cross.c

# Windows (MSVC — invite de commandes développeur)
cl /W4 /O2 /Fe:bootability_checker.exe bootability_checker_cross.c

# Windows (MinGW/MSYS2)
gcc -std=c99 -Wall -Wextra -o bootability_checker.exe bootability_checker_cross.c

# Avec le Makefile universel
make -f Makefile_cross
```

---

## Usage

```sh
# Mode interactif (liste les disques, demande un choix)
sudo ./bootability_checker

# Analyse directe
sudo ./bootability_checker /dev/ada0       # FreeBSD
sudo ./bootability_checker /dev/sda        # Linux
sudo ./bootability_checker /dev/disk0      # macOS
sudo ./bootability_checker /dev/sd0c       # OpenBSD
     ./bootability_checker \\.\PhysicalDrive0  # Windows (Admin)

# Analyser tous les disques détectés
sudo ./bootability_checker --all

# Aide et version
./bootability_checker --help
./bootability_checker --version
```

---

## Codes de retour

| Code | Signification |
|------|--------------|
| `0`  | Au moins un mode bootable détecté |
| `1`  | Disque non bootable |
| `2`  | Erreur d'accès ou argument invalide |

---

## Architecture technique

### Itération 1 (FreeBSD)

```
main()
  ├── interactive_mode()    ← sysctl kern.disks
  ├── all_mode()
  └── analyze_disk()
        ├── detect_sector_size()   ← ioctl DIOCGSECTORSIZE
        ├── detect_disk_size()     ← ioctl DIOCGMEDIASIZE
        ├── read_sector()          ← pread() (offsets LBA absolus)
        ├── analyze_mbr()          ← parse table partitions + flag 0x80
        ├── analyze_gpt()          ← header + CRC32 + scan 128 entrées
        └── compute_verdict()
```

### Itération 2 (Cross-platform)

```
PlatformOps (HAL)
  ├── open_disk / close_disk / read_at
  ├── get_sector_size / get_disk_size
  └── list_disks / is_tty

Moteur d'analyse (100% portable, 0 #ifdef)
  ├── engine_analyze_mbr()
  ├── engine_analyze_gpt()
  └── compute_verdict()
```

La couche HAL (`PlatformOps`) est une struct de pointeurs de fonctions.  
Le moteur d'analyse est **totalement indépendant de l'OS** — une seule base de code.

---

## Détails techniques

### CRC32 GPT
L'implémentation utilise le polynôme ANSI CCITT `0x04C11DB7` (représentation réfléchie : `0xEDB88320`), seed `~0`, XOR final `~0`, conformément à la spécification UEFI 2.11 chapitre 5. Le CRC32c (Castagnoli) matériel est **incompatible** et ne doit pas être utilisé.

### GUIDs de partitions (little-endian sur disque)
| Type | GUID RFC 4122 | Sur disque (hex) |
|------|--------------|-----------------|
| ESP | `C12A7328-F81F-11D2-BA4B-00A0C93EC93B` | `28 73 2A C1 1F F8 D2 11...` |
| freebsd-boot | `83BD6B9D-7F41-11DC-BE0B-001560B84F0F` | `9D 6B BD 83 41 7F DC 11...` |
| freebsd-ufs | `516E7CB6-6ECF-11D6-8FF8-00022D09712B` | `B6 7C 6E 51 CF 6E D6 11...` |
| freebsd-zfs | `516E7CBA-6ECF-11D6-8FF8-00022D09712B` | `BA 7C 6E 51 CF 6E D6 11...` |

### Logique de bootabilité
- **BIOS bootable** : MBR valide + partition active `OR` GPT valide + `freebsd-boot`
- **UEFI bootable** : GPT valide (CRC OK) + partition ESP présente

### Sécurité
- Ouverture en lecture seule (`O_RDONLY` / `GENERIC_READ`)
- `pread()` avec offsets absolus (pas de `read()` séquentiel)
- Validation de toutes les bornes avant accès mémoire
- Aucune écriture effectuée sur le disque

---

## Licence

MIT — Voir fichier `LICENSE`
