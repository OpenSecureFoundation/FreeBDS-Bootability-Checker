/*
 * bootability_checker_freebsd.c
 *
 * Bootability Checker - Iteration 1 : FreeBSD natif
 * Auteurs  : DZOUAKEU FESSI Emmanuella Cindy
 *            YAKAM TCHAMOU Rick Vadel
 * Examinateur : M. NGUIMBUS, enseignant de SE
 * Institut : Institut Universitaire Saint Jean
 *
 * Description :
 *   Outil d'analyse bas niveau de la bootabilité d'un disque physique
 *   sous FreeBSD. Détecte et valide :
 *     - MBR (signature 0x55AA + partition active)
 *     - GPT (header LBA1 + CRC32 ANSI + partition entries)
 *     - ESP / freebsd-boot / freebsd-zfs / freebsd-ufs
 *     - Disques hybrides (protective MBR + GPT)
 *     - Secteurs 4Kn (native 4096-byte sectors)
 *
 * Compilation :
 *   cc -std=c99 -Wall -Wextra -o bootability_checker bootability_checker_freebsd.c
 *
 * Usage :
 *   sudo ./bootability_checker           (menu interactif)
 *   sudo ./bootability_checker /dev/ada0 (analyse directe)
 *   sudo ./bootability_checker --all     (tous les disques détectés)
 *   ./bootability_checker --help
 *   ./bootability_checker --version
 *
 * Licence : MIT
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/disk.h>        /* DIOCGSECTORSIZE, DIOCGMEDIASIZE */
#include <sys/ioctl.h>

/* =========================================================================
 * Constantes
 * ========================================================================= */

#define VERSION_STR        "2.0.0"
#define DEFAULT_SECTOR     512
#define MAX_SECTOR         4096
#define MAX_DISKS          32
#define MAX_DISK_NAME      64
#define MAX_GPT_ENTRIES    128
#define GPT_ENTRY_SIZE     128
#define GPT_ENTRY_ARRAY_SZ (MAX_GPT_ENTRIES * GPT_ENTRY_SIZE)  /* 16384 octets */

/* Offsets MBR */
#define MBR_PART_TABLE_OFF 446
#define MBR_SIGNATURE_OFF  510
#define MBR_PART_ENTRY_SZ  16
#define MBR_NUM_PARTS      4
#define MBR_ACTIVE_FLAG    0x80
#define MBR_TYPE_EFI_GPT   0xEE   /* Protective MBR pour GPT */

/* Offsets GPT Header (dans LBA1) */
#define GPT_SIG_OFF        0      /* "EFI PART" 8 octets */
#define GPT_REV_OFF        8      /* Révision 4 octets  */
#define GPT_HDRSIZE_OFF    12     /* Taille header 4 octets (généralement 92) */
#define GPT_HDRCRC_OFF     16     /* CRC32 du header 4 octets */
#define GPT_MYLBA_OFF      24     /* My LBA 8 octets */
#define GPT_ALTLBA_OFF     32     /* Alternate LBA 8 octets */
#define GPT_FIRSTLBA_OFF   40     /* First usable LBA 8 octets */
#define GPT_LASTLBA_OFF    48     /* Last usable LBA 8 octets */
#define GPT_DISKGUID_OFF   56     /* Disk GUID 16 octets */
#define GPT_PARTLBA_OFF    72     /* Partition entry array LBA 8 octets */
#define GPT_NPARTS_OFF     80     /* Nombre d'entrées 4 octets */
#define GPT_ENTSIZE_OFF    84     /* Taille entrée 4 octets */
#define GPT_PARTCRC_OFF    88     /* CRC32 partition array 4 octets */

/* Offsets d'une entrée GPT (128 octets chacune) */
#define GPT_ENT_TYPE_OFF   0      /* Type GUID 16 octets */
#define GPT_ENT_GUID_OFF   16     /* Unique GUID 16 octets */
#define GPT_ENT_SLBA_OFF   32     /* Start LBA 8 octets */
#define GPT_ENT_ELBA_OFF   40     /* End LBA 8 octets */
#define GPT_ENT_ATTR_OFF   48     /* Attributs 8 octets */
#define GPT_ENT_NAME_OFF   56     /* Nom UTF-16LE 72 octets */

/* =========================================================================
 * GUIDs des types de partitions (stockés en little-endian sur disque)
 * Source : UEFI spec 2.11 + man gpart(8) FreeBSD
 *
 * Note : les 3 premiers groupes sont en little-endian sur disque.
 * Ex : C12A7328-F81F-11D2-BA4B-00A0C93EC93B
 *      → sur disque : 28 73 2A C1  1F F8  D2 11  BA 4B  00 A0 C9 3E C9 3B
 * ========================================================================= */
static const uint8_t GUID_ESP[16] = {
    0x28, 0x73, 0x2A, 0xC1,  0x1F, 0xF8,  0xD2, 0x11,
    0xBA, 0x4B, 0x00, 0xA0,  0xC9, 0x3E,  0xC9, 0x3B
};

/*
 * freebsd-boot : 83BD6B9D-7F41-11DC-BE0B-001560B84F0F
 * → sur disque : 9D 6B BD 83  41 7F  DC 11  BE 0B  00 15 60 B8 4F 0F
 */
static const uint8_t GUID_FREEBSD_BOOT[16] = {
    0x9D, 0x6B, 0xBD, 0x83,  0x41, 0x7F,  0xDC, 0x11,
    0xBE, 0x0B, 0x00, 0x15,  0x60, 0xB8,  0x4F, 0x0F
};

/*
 * freebsd-ufs : 516E7CB6-6ECF-11D6-8FF8-00022D09712B
 * → sur disque : B6 7C 6E 51  CF 6E  D6 11  8F F8  00 02 2D 09 71 2B
 */
static const uint8_t GUID_FREEBSD_UFS[16] = {
    0xB6, 0x7C, 0x6E, 0x51,  0xCF, 0x6E,  0xD6, 0x11,
    0x8F, 0xF8, 0x00, 0x02,  0x2D, 0x09,  0x71, 0x2B
};

/*
 * freebsd-zfs : 516E7CBA-6ECF-11D6-8FF8-00022D09712B
 * → sur disque : BA 7C 6E 51  CF 6E  D6 11  8F F8  00 02 2D 09 71 2B
 */
static const uint8_t GUID_FREEBSD_ZFS[16] = {
    0xBA, 0x7C, 0x6E, 0x51,  0xCF, 0x6E,  0xD6, 0x11,
    0x8F, 0xF8, 0x00, 0x02,  0x2D, 0x09,  0x71, 0x2B
};

/*
 * freebsd-swap : 516E7CB5-6ECF-11D6-8FF8-00022D09712B
 * → sur disque : B5 7C 6E 51  CF 6E  D6 11  8F F8  00 02 2D 09 71 2B
 */
static const uint8_t GUID_FREEBSD_SWAP[16] = {
    0xB5, 0x7C, 0x6E, 0x51,  0xCF, 0x6E,  0xD6, 0x11,
    0x8F, 0xF8, 0x00, 0x02,  0x2D, 0x09,  0x71, 0x2B
};

/* GUID vide (entrée non utilisée) */
static const uint8_t GUID_ZERO[16] = { 0 };

/* =========================================================================
 * Couleurs ANSI — désactivées automatiquement si stdout n'est pas un TTY
 * ========================================================================= */
static int use_color = 0;

#define COL(c)   (use_color ? (c)   : "")
#define RED      "\x1B[31m"
#define GRN      "\x1B[32m"
#define YEL      "\x1B[33m"
#define CYN      "\x1B[36m"
#define BOLD     "\x1B[1m"
#define RESET    "\x1B[0m"

/* =========================================================================
 * Structures de résultat d'analyse
 * ========================================================================= */

typedef struct {
    /* MBR */
    int  mbr_signature_ok;    /* 0x55AA présent */
    int  mbr_active_part;     /* Partition active (flag 0x80) trouvée */
    int  mbr_is_protective;   /* MBR protectif (type 0xEE, indique GPT) */

    /* GPT */
    int  gpt_header_found;    /* Signature "EFI PART" à LBA1 */
    int  gpt_header_crc_ok;   /* CRC32 header validé */
    int  gpt_partcrc_ok;      /* CRC32 partition array validé */
    int  gpt_has_esp;         /* Partition ESP trouvée */
    int  gpt_has_fbsd_boot;   /* Partition freebsd-boot trouvée */
    int  gpt_has_fbsd_ufs;    /* Partition freebsd-ufs trouvée */
    int  gpt_has_fbsd_zfs;    /* Partition freebsd-zfs trouvée */

    /* Disque */
    uint32_t sector_size;     /* Taille de secteur détectée */
    uint64_t disk_size_bytes; /* Taille totale en octets */
    int  is_hybrid;           /* MBR protectif + GPT valide */

    /* Verdict final */
    int  bootable_bios;
    int  bootable_uefi;
} DiskReport;

/* =========================================================================
 * CRC32 ANSI (polynôme 0x04C11DB7, seed ~0, résultat XOR ~0)
 * Algorithme identique à celui de la spécification UEFI pour GPT.
 * NE PAS remplacer par crc32c (Castagnoli) — incompatible GPT.
 * ========================================================================= */
static uint32_t crc32_table[256];
static int      crc32_initialized = 0;

static void crc32_init(void)
{
    uint32_t i, j, crc;
    for (i = 0; i < 256; i++) {
        crc = i;
        for (j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320U; /* poly réfléchi */
            else
                crc >>= 1;
        }
        crc32_table[i] = crc;
    }
    crc32_initialized = 1;
}

static uint32_t crc32_compute(const uint8_t *buf, size_t len)
{
    uint32_t crc = 0xFFFFFFFFU;
    size_t i;
    if (!crc32_initialized) crc32_init();
    for (i = 0; i < len; i++)
        crc = (crc >> 8) ^ crc32_table[(crc ^ buf[i]) & 0xFF];
    return crc ^ 0xFFFFFFFFU;
}

/* =========================================================================
 * Lecture sécurisée d'un secteur via pread (offset absolu, pas séquentiel)
 * Retourne 0 en succès, -1 en erreur.
 * ========================================================================= */
static int read_sector(int fd, uint64_t lba, uint32_t sector_size,
                       uint8_t *buf)
{
    off_t  offset = (off_t)lba * (off_t)sector_size;
    ssize_t n     = pread(fd, buf, sector_size, offset);
    if (n != (ssize_t)sector_size) {
        return -1;
    }
    return 0;
}

/* =========================================================================
 * Helpers de lecture little-endian depuis un buffer brut
 * ========================================================================= */
static inline uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static inline uint64_t read_le64(const uint8_t *p)
{
    return (uint64_t)p[0]
         | ((uint64_t)p[1] << 8)
         | ((uint64_t)p[2] << 16)
         | ((uint64_t)p[3] << 24)
         | ((uint64_t)p[4] << 32)
         | ((uint64_t)p[5] << 40)
         | ((uint64_t)p[6] << 48)
         | ((uint64_t)p[7] << 56);
}

/* =========================================================================
 * Analyse MBR (LBA 0)
 * ========================================================================= */
static void analyze_mbr(const uint8_t *sector0, DiskReport *r)
{
    int i;
    const uint8_t *entry;

    /* Signature 0x55AA aux octets 510-511 */
    r->mbr_signature_ok = (sector0[MBR_SIGNATURE_OFF]     == 0x55 &&
                           sector0[MBR_SIGNATURE_OFF + 1] == 0xAA);

    if (!r->mbr_signature_ok) return;

    /* Parcours des 4 entrées de la table de partitions MBR */
    for (i = 0; i < MBR_NUM_PARTS; i++) {
        entry = sector0 + MBR_PART_TABLE_OFF + (i * MBR_PART_ENTRY_SZ);

        /* Octet 0 : Status / boot indicator */
        if (entry[0] == MBR_ACTIVE_FLAG)
            r->mbr_active_part = 1;

        /* Type 0xEE = protective MBR (indique présence GPT) */
        if (entry[4] == MBR_TYPE_EFI_GPT)
            r->mbr_is_protective = 1;
    }
}

/* =========================================================================
 * Analyse GPT Header (LBA 1) + Partition Entry Array (LBA 2+)
 * ========================================================================= */
static void analyze_gpt(int fd, const uint8_t *sector1,
                        uint32_t sector_size, DiskReport *r)
{
    uint32_t hdr_size, stored_crc, computed_crc;
    uint32_t nparts, entsize;
    uint64_t part_lba;
    uint8_t  hdr_copy[MAX_SECTOR];
    uint8_t *part_array = NULL;
    size_t   array_bytes;
    int      i;

    /* 1. Vérification signature "EFI PART" */
    if (memcmp(sector1 + GPT_SIG_OFF, "EFI PART", 8) != 0)
        return;

    r->gpt_header_found = 1;

    /* 2. Taille du header (offset 12, 4 octets LE) */
    hdr_size = read_le32(sector1 + GPT_HDRSIZE_OFF);
    if (hdr_size < 92 || hdr_size > sector_size) {
        /* Header corrompu ou invalide */
        return;
    }

    /* 3. Validation CRC32 du header GPT
     *    Procédure : copier le header, zéroïser les octets 16-19 (champ CRC),
     *    calculer CRC32 sur hdr_size octets, comparer au champ stocké.
     */
    stored_crc = read_le32(sector1 + GPT_HDRCRC_OFF);
    memcpy(hdr_copy, sector1, hdr_size);
    memset(hdr_copy + GPT_HDRCRC_OFF, 0, 4);
    computed_crc = crc32_compute(hdr_copy, hdr_size);
    r->gpt_header_crc_ok = (computed_crc == stored_crc);

    /* 4. Lecture des paramètres de la partition entry array */
    nparts   = read_le32(sector1 + GPT_NPARTS_OFF);
    entsize  = read_le32(sector1 + GPT_ENTSIZE_OFF);
    part_lba = read_le64(sector1 + GPT_PARTLBA_OFF);

    if (nparts == 0 || entsize < 128 || entsize > 512 ||
        nparts > MAX_GPT_ENTRIES || part_lba < 2) {
        return;
    }

    array_bytes = (size_t)nparts * entsize;
    if (array_bytes > 1024 * 1024) {  /* sanity: max 1 Mo */
        return;
    }

    /* 5. Lecture de la partition entry array */
    part_array = (uint8_t *)malloc(array_bytes);
    if (!part_array) return;

    {
        uint64_t lba = part_lba;
        uint8_t  tmp[MAX_SECTOR];
        size_t   bytes_read = 0;
        size_t   to_copy;

        while (bytes_read < array_bytes) {
            if (read_sector(fd, lba, sector_size, tmp) < 0) {
                free(part_array);
                return;
            }
            to_copy = array_bytes - bytes_read;
            if (to_copy > sector_size) to_copy = sector_size;
            memcpy(part_array + bytes_read, tmp, to_copy);
            bytes_read += to_copy;
            lba++;
        }
    }

    /* 6. Validation CRC32 de la partition entry array */
    {
        uint32_t stored_pcrc  = read_le32(sector1 + GPT_PARTCRC_OFF);
        uint32_t computed_pcrc = crc32_compute(part_array, array_bytes);
        r->gpt_partcrc_ok = (computed_pcrc == stored_pcrc);
    }

    /* 7. Scan des entrées : détection ESP, freebsd-boot, freebsd-zfs, etc. */
    for (i = 0; i < (int)nparts; i++) {
        const uint8_t *ent = part_array + (i * entsize);
        const uint8_t *type_guid = ent + GPT_ENT_TYPE_OFF;

        /* Ignorer les entrées vides (GUID zéro) */
        if (memcmp(type_guid, GUID_ZERO, 16) == 0)
            continue;

        if (memcmp(type_guid, GUID_ESP, 16) == 0)
            r->gpt_has_esp = 1;
        else if (memcmp(type_guid, GUID_FREEBSD_BOOT, 16) == 0)
            r->gpt_has_fbsd_boot = 1;
        else if (memcmp(type_guid, GUID_FREEBSD_UFS, 16) == 0)
            r->gpt_has_fbsd_ufs = 1;
        else if (memcmp(type_guid, GUID_FREEBSD_ZFS, 16) == 0)
            r->gpt_has_fbsd_zfs = 1;
    }

    free(part_array);

    /* Disque hybride si protective MBR + GPT valide */
    r->is_hybrid = r->mbr_is_protective && r->gpt_header_found;
}

/* =========================================================================
 * Détection de la taille de secteur via ioctl (support 4Kn)
 * ========================================================================= */
static uint32_t detect_sector_size(int fd)
{
    u_int sector_size = 0;
    if (ioctl(fd, DIOCGSECTORSIZE, &sector_size) == 0 && sector_size > 0)
        return (uint32_t)sector_size;
    return DEFAULT_SECTOR;  /* fallback */
}

/* =========================================================================
 * Détection de la taille totale du disque
 * ========================================================================= */
static uint64_t detect_disk_size(int fd)
{
    off_t media_size = 0;
    if (ioctl(fd, DIOCGMEDIASIZE, &media_size) == 0 && media_size > 0)
        return (uint64_t)media_size;
    return 0;
}

/* =========================================================================
 * Calcul du verdict final
 * ========================================================================= */
static void compute_verdict(DiskReport *r)
{
    /*
     * BOOTABLE BIOS :
     *   Mode 1 : MBR valide + partition active (boot classique MBR/BIOS)
     *   Mode 2 : GPT valide + freebsd-boot present (gptboot/BIOS/GPT)
     *            → FreeBSD supporte le boot BIOS depuis GPT via pmbr+gptboot
     */
    r->bootable_bios = 0;
    if (r->mbr_signature_ok && r->mbr_active_part && !r->mbr_is_protective)
        r->bootable_bios = 1;
    if (r->gpt_header_found && r->gpt_header_crc_ok && r->gpt_has_fbsd_boot)
        r->bootable_bios = 1;

    /*
     * BOOTABLE UEFI :
     *   GPT valide (header + CRC) + partition ESP présente
     *   (boot1.efi/loader.efi se trouvent dans l'ESP)
     */
    r->bootable_uefi = 0;
    if (r->gpt_header_found && r->gpt_header_crc_ok && r->gpt_has_esp)
        r->bootable_uefi = 1;
}

/* =========================================================================
 * Formatage d'une taille en octets en chaîne lisible
 * ========================================================================= */
static void format_size(uint64_t bytes, char *buf, size_t buflen)
{
    if (bytes == 0) {
        snprintf(buf, buflen, "inconnu");
    } else if (bytes >= (uint64_t)1024 * 1024 * 1024 * 1024) {
        snprintf(buf, buflen, "%.2f To", (double)bytes / (1024.0*1024*1024*1024));
    } else if (bytes >= (uint64_t)1024 * 1024 * 1024) {
        snprintf(buf, buflen, "%.2f Go", (double)bytes / (1024.0*1024*1024));
    } else if (bytes >= (uint64_t)1024 * 1024) {
        snprintf(buf, buflen, "%.2f Mo", (double)bytes / (1024.0*1024));
    } else {
        snprintf(buf, buflen, "%.2f Ko", (double)bytes / 1024.0);
    }
}

/* =========================================================================
 * Affichage du rapport détaillé
 * ========================================================================= */
static void print_report(const char *path, const DiskReport *r)
{
    char size_str[32];
    format_size(r->disk_size_bytes, size_str, sizeof(size_str));

    printf("\n%s%s[ RAPPORT : %s ]%s\n",
           COL(BOLD), COL(CYN), path, COL(RESET));
    printf("%s=================================================%s\n",
           COL(CYN), COL(RESET));

    /* Informations disque */
    printf("  Taille de secteur  : %u octets %s\n",
           r->sector_size,
           r->sector_size == 4096
               ? "(4Kn natif)" : "(512 standard / 512e)");
    printf("  Capacité disque    : %s\n", size_str);

    /* ------------------------------------------------------------------ */
    printf("\n%s--- Analyse MBR (LBA 0) ---%s\n", COL(BOLD), COL(RESET));
    printf("  Signature 0x55AA   : %s%s%s\n",
           r->mbr_signature_ok ? COL(GRN) : COL(RED),
           r->mbr_signature_ok ? "VALIDE" : "ABSENTE",
           COL(RESET));

    if (r->mbr_signature_ok) {
        if (r->mbr_is_protective) {
            printf("  Type MBR           : %sMBR PROTECTIF (0xEE) → disque GPT%s\n",
                   COL(YEL), COL(RESET));
        } else {
            printf("  Partition active   : %s%s%s\n",
                   r->mbr_active_part ? COL(GRN) : COL(RED),
                   r->mbr_active_part ? "OUI (flag 0x80 présent)" : "NON (aucune partition active)",
                   COL(RESET));
        }
    }

    /* ------------------------------------------------------------------ */
    printf("\n%s--- Analyse GPT (LBA 1) ---%s\n", COL(BOLD), COL(RESET));
    printf("  Signature EFI PART : %s%s%s\n",
           r->gpt_header_found ? COL(GRN) : COL(RED),
           r->gpt_header_found ? "TROUVÉE" : "ABSENTE",
           COL(RESET));

    if (r->gpt_header_found) {
        printf("  CRC32 Header       : %s%s%s\n",
               r->gpt_header_crc_ok ? COL(GRN) : COL(RED),
               r->gpt_header_crc_ok ? "VALIDE" : "INVALIDE (header corrompu !)",
               COL(RESET));
        printf("  CRC32 Partitions   : %s%s%s\n",
               r->gpt_partcrc_ok ? COL(GRN) : COL(RED),
               r->gpt_partcrc_ok ? "VALIDE" : "INVALIDE (table corrompue !)",
               COL(RESET));

        printf("\n  %sPartitions détectées :%s\n", COL(BOLD), COL(RESET));
        printf("    ESP (UEFI System)  : %s%s%s\n",
               r->gpt_has_esp ? COL(GRN) : COL(YEL),
               r->gpt_has_esp ? "OUI" : "NON",
               COL(RESET));
        printf("    freebsd-boot       : %s%s%s\n",
               r->gpt_has_fbsd_boot ? COL(GRN) : COL(YEL),
               r->gpt_has_fbsd_boot ? "OUI" : "NON",
               COL(RESET));
        printf("    freebsd-ufs        : %s%s%s\n",
               r->gpt_has_fbsd_ufs ? COL(GRN) : COL(YEL),
               r->gpt_has_fbsd_ufs ? "OUI" : "NON",
               COL(RESET));
        printf("    freebsd-zfs        : %s%s%s\n",
               r->gpt_has_fbsd_zfs ? COL(GRN) : COL(YEL),
               r->gpt_has_fbsd_zfs ? "OUI" : "NON",
               COL(RESET));

        if (r->is_hybrid)
            printf("\n  %sDisque hybride détecté : MBR protectif + GPT valide%s\n",
                   COL(YEL), COL(RESET));
    }

    /* ------------------------------------------------------------------ */
    printf("\n%s=================================================%s\n",
           COL(CYN), COL(RESET));
    printf("%s  VERDICT FINAL%s\n", COL(BOLD), COL(RESET));
    printf("%s=================================================%s\n",
           COL(CYN), COL(RESET));

    if (r->bootable_bios && r->bootable_uefi) {
        printf("  %s%s✓ BOOTABLE — BIOS (Legacy) + UEFI (Dual Mode)%s\n",
               COL(BOLD), COL(GRN), COL(RESET));
    } else if (r->bootable_bios) {
        printf("  %s%s✓ BOOTABLE — BIOS (Legacy / MBR ou GPT+freebsd-boot)%s\n",
               COL(BOLD), COL(GRN), COL(RESET));
    } else if (r->bootable_uefi) {
        printf("  %s%s✓ BOOTABLE — UEFI (GPT + ESP)%s\n",
               COL(BOLD), COL(GRN), COL(RESET));
    } else {
        printf("  %s%s✗ NON BOOTABLE%s\n",
               COL(BOLD), COL(RED), COL(RESET));

        /* Aide diagnostique */
        printf("\n  %sDiagnostic :%s\n", COL(YEL), COL(RESET));
        if (!r->mbr_signature_ok && !r->gpt_header_found)
            printf("    → Ni MBR ni GPT trouvés — disque non partitionné ou corrompu.\n");
        if (r->mbr_signature_ok && !r->mbr_active_part && !r->mbr_is_protective)
            printf("    → MBR présent mais aucune partition marquée active.\n");
        if (r->gpt_header_found && !r->gpt_header_crc_ok)
            printf("    → Header GPT corrompu (CRC invalide).\n");
        if (r->gpt_header_found && r->gpt_header_crc_ok &&
            !r->gpt_has_esp && !r->gpt_has_fbsd_boot)
            printf("    → GPT valide mais pas de partition ESP ni freebsd-boot.\n");
    }

    printf("%s=================================================%s\n\n",
           COL(CYN), COL(RESET));
}

/* =========================================================================
 * Analyse complète d'un disque identifié par son chemin (ex: /dev/ada0)
 * ========================================================================= */
static int analyze_disk(const char *path)
{
    int        fd;
    DiskReport r;
    uint8_t    sector0[MAX_SECTOR];
    uint8_t    sector1[MAX_SECTOR];
    uint32_t   ssize;

    memset(&r, 0, sizeof(r));

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr,
                "%sErreur%s : Impossible d'ouvrir %s : %s\n"
                "  → Relancez avec les droits root (doas ou sudo).\n",
                COL(RED), COL(RESET), path, strerror(errno));
        return -1;
    }

    /* Taille de secteur et capacité */
    ssize = detect_sector_size(fd);
    r.sector_size     = ssize;
    r.disk_size_bytes = detect_disk_size(fd);

    /* Lecture des secteurs 0 et 1 avec pread (offsets absolus) */
    memset(sector0, 0, sizeof(sector0));
    memset(sector1, 0, sizeof(sector1));

    if (read_sector(fd, 0, ssize, sector0) < 0) {
        fprintf(stderr,
                "%sErreur%s : Lecture LBA 0 impossible sur %s : %s\n",
                COL(RED), COL(RESET), path, strerror(errno));
        close(fd);
        return -1;
    }

    if (read_sector(fd, 1, ssize, sector1) < 0) {
        fprintf(stderr,
                "%sErreur%s : Lecture LBA 1 impossible sur %s : %s\n",
                COL(RED), COL(RESET), path, strerror(errno));
        close(fd);
        return -1;
    }

    /* Analyses */
    analyze_mbr(sector0, &r);
    analyze_gpt(fd, sector1, ssize, &r);
    compute_verdict(&r);

    close(fd);

    /* Rapport */
    print_report(path, &r);

    return (r.bootable_bios || r.bootable_uefi) ? 0 : 1;
}

/* =========================================================================
 * Découverte automatique des disques via sysctl kern.disks (FreeBSD)
 * Retourne le nombre de disques trouvés.
 * ========================================================================= */
static int list_disks(char disk_names[MAX_DISKS][MAX_DISK_NAME])
{
    char   raw[4096];
    size_t len = sizeof(raw);
    int    count = 0;
    char  *token;

    memset(raw, 0, sizeof(raw));

    if (sysctlbyname("kern.disks", raw, &len, NULL, 0) < 0) {
        perror("sysctl kern.disks");
        return -1;
    }

    token = strtok(raw, " \t\n");
    while (token != NULL && count < MAX_DISKS) {
        /*
         * Filtrer les périphériques non-disques (cd, fd, ...) :
         * on ne garde que ada, da, nvd, vtblk, mmcsd, md.
         */
        if (strncmp(token, "ada", 3) == 0 ||
            strncmp(token, "da",  2) == 0 ||
            strncmp(token, "nvd", 3) == 0 ||
            strncmp(token, "vtblk", 5) == 0 ||
            strncmp(token, "mmcsd", 5) == 0 ||
            strncmp(token, "md",   2) == 0) {
            snprintf(disk_names[count], MAX_DISK_NAME, "%s", token);
            count++;
        }
        token = strtok(NULL, " \t\n");
    }
    return count;
}

/* =========================================================================
 * En-tête du programme
 * ========================================================================= */
static void print_header(void)
{
    printf("\n%s%s", COL(BOLD), COL(CYN));
    printf("╔═══════════════════════════════════════════════╗\n");
    printf("║    BOOTABILITY CHECKER v%s — FreeBSD       ║\n", VERSION_STR);
    printf("║    Analyseur de bootabilité disque bas niveau ║\n");
    printf("╚═══════════════════════════════════════════════╝\n");
    printf("%s\n", COL(RESET));
}

/* =========================================================================
 * Aide
 * ========================================================================= */
static void print_help(const char *prog)
{
    printf("Usage:\n");
    printf("  %s                    Mode interactif (liste les disques)\n", prog);
    printf("  %s /dev/ada0          Analyse directe d'un disque\n", prog);
    printf("  %s --all              Analyse tous les disques détectés\n", prog);
    printf("  %s --help             Affiche cette aide\n", prog);
    printf("  %s --version          Affiche la version\n", prog);
    printf("\nNotes:\n");
    printf("  - Nécessite les droits root pour accéder aux périphériques bloc.\n");
    printf("  - Lecture seule, aucune écriture effectuée sur le disque.\n");
    printf("  - Supporte les disques 512, 512e, et 4Kn natifs.\n");
    printf("\nCodes de retour:\n");
    printf("  0 : Au moins un mode bootable détecté\n");
    printf("  1 : Non bootable\n");
    printf("  2 : Erreur d'accès ou argument invalide\n");
}

/* =========================================================================
 * Mode interactif : liste les disques et demande un choix
 * ========================================================================= */
static int interactive_mode(void)
{
    char disk_names[MAX_DISKS][MAX_DISK_NAME];
    char path[MAX_DISK_NAME + 6];
    int  count, choice, c;

    count = list_disks(disk_names);
    if (count < 0) {
        fprintf(stderr, "%sErreur%s : Impossible de récupérer la liste des disques.\n",
                COL(RED), COL(RESET));
        return 2;
    }

    if (count == 0) {
        printf("%sAucun disque physique détecté.%s\n", COL(YEL), COL(RESET));
        return 2;
    }

    printf("%sDisques détectés :%s\n", COL(BOLD), COL(RESET));
    for (int i = 0; i < count; i++)
        printf("  [%2d] /dev/%s\n", i + 1, disk_names[i]);

    printf("\nChoisissez un numéro (0 pour quitter) : ");
    fflush(stdout);

    if (scanf("%d", &choice) != 1) {
        /* Nettoyage du buffer stdin en cas d'entrée non numérique */
        while ((c = getchar()) != '\n' && c != EOF) {}
        fprintf(stderr, "%sEntrée invalide.%s\n", COL(RED), COL(RESET));
        return 2;
    }
    /* Nettoyer le '\n' résiduel */
    while ((c = getchar()) != '\n' && c != EOF) {}

    if (choice == 0) return 0;

    if (choice < 1 || choice > count) {
        fprintf(stderr, "%sChoix hors plage [1-%d].%s\n",
                COL(RED), count, COL(RESET));
        return 2;
    }

    snprintf(path, sizeof(path), "/dev/%s", disk_names[choice - 1]);
    return analyze_disk(path) == 0 ? 0 : 1;
}

/* =========================================================================
 * Mode --all : analyse tous les disques détectés
 * ========================================================================= */
static int all_mode(void)
{
    char disk_names[MAX_DISKS][MAX_DISK_NAME];
    char path[MAX_DISK_NAME + 6];
    int  count, i;
    int  any_bootable = 0;

    count = list_disks(disk_names);
    if (count <= 0) {
        printf("%sAucun disque physique détecté.%s\n", COL(YEL), COL(RESET));
        return (count == 0) ? 0 : 2;
    }

    printf("%s%d disque(s) à analyser...%s\n", COL(YEL), count, COL(RESET));

    for (i = 0; i < count; i++) {
        snprintf(path, sizeof(path), "/dev/%s", disk_names[i]);
        if (analyze_disk(path) == 0)
            any_bootable = 1;
    }

    return any_bootable ? 0 : 1;
}

/* =========================================================================
 * Point d'entrée
 * ========================================================================= */
int main(int argc, char *argv[])
{
    /* Détection TTY pour les couleurs ANSI */
    use_color = isatty(STDOUT_FILENO);

    print_header();

    /* ---- Analyse des arguments ---- */

    if (argc == 1) {
        /* Aucun argument : mode interactif */
        return interactive_mode();
    }

    if (argc == 2) {
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            print_help(argv[0]);
            return 0;
        }

        if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0) {
            printf("bootability_checker %s (FreeBSD)\n", VERSION_STR);
            return 0;
        }

        if (strcmp(argv[1], "--all") == 0 || strcmp(argv[1], "-a") == 0) {
            return all_mode();
        }

        /* Sinon : chemin direct (ex: /dev/ada0 ou ada0) */
        if (argv[1][0] != '-') {
            char path[256];
            /* Accepter "ada0" ou "/dev/ada0" */
            if (strncmp(argv[1], "/dev/", 5) == 0) {
                snprintf(path, sizeof(path), "%s", argv[1]);
            } else {
                snprintf(path, sizeof(path), "/dev/%s", argv[1]);
            }
            return analyze_disk(path) == 0 ? 0 : 1;
        }
    }

    fprintf(stderr, "%sArgument invalide : %s%s\n",
            COL(RED), argv[1], COL(RESET));
    fprintf(stderr, "Utilisez --help pour l'aide.\n");
    return 2;
}
