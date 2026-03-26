/* POSIX source for pread, isatty */
#if !defined(_WIN32) && !defined(_WIN64)
#  ifndef _POSIX_C_SOURCE
#    define _POSIX_C_SOURCE 200809L
#  endif
#endif

/*
 * bootability_checker_cross.c
 *
 * Bootability Checker - Iteration 2 : Cross-Platform
 * Auteurs  : DZOUAKEU FESSI Emmanuella Cindy
 *            YAKAM TCHAMOU Rick Vadel
 * Examinateur : M. NGUIMBUS, enseignant de SE
 * Institut : Institut Universitaire Saint Jean
 *
 * Plateformes supportées :
 *   - FreeBSD   (DIOCGSECTORSIZE / kern.disks)
 *   - Linux     (/proc/partitions + BLKSSZGET)
 *   - macOS     (DKIOCGETBLOCKSIZE + diskutil)
 *   - OpenBSD   (DIOCGPDINFO)
 *   - NetBSD    (DIOCGDINFO)
 *   - Windows   (CreateFile + DeviceIoControl)
 *
 * Architecture :
 *   Une couche d'abstraction "platform_*" isole toute la logique
 *   spécifique à l'OS. Le moteur d'analyse MBR/GPT est commun et
 *   partagé entre toutes les plateformes (zéro #ifdef dans le moteur).
 *
 * Compilation :
 *   FreeBSD/OpenBSD/NetBSD :
 *     cc -std=c99 -Wall -Wextra -o bootability_checker bootability_checker_cross.c
 *
 *   Linux :
 *     gcc -std=c99 -Wall -Wextra -o bootability_checker bootability_checker_cross.c
 *
 *   macOS :
 *     clang -std=c99 -Wall -Wextra -o bootability_checker bootability_checker_cross.c
 *
 *   Windows (MSVC) :
 *     cl /W4 /Fe:bootability_checker.exe bootability_checker_cross.c
 *
 *   Windows (MinGW/MSYS2) :
 *     gcc -std=c99 -Wall -Wextra -o bootability_checker.exe bootability_checker_cross.c
 *
 * Usage :
 *   (root requis sur Unix/macOS)
 *   sudo ./bootability_checker                 → interactif
 *   sudo ./bootability_checker /dev/sda        → Linux
 *   sudo ./bootability_checker /dev/ada0       → FreeBSD
 *   sudo ./bootability_checker /dev/disk0      → macOS
 *   ./bootability_checker \\.\PhysicalDrive0   → Windows (Admin)
 *   sudo ./bootability_checker --all
 *
 * Licence : MIT
 */

/* =========================================================================
 * Détection de la plateforme à la compilation
 * ========================================================================= */
#if defined(_WIN32) || defined(_WIN64)
  #define PLATFORM_WINDOWS 1
#elif defined(__linux__)
  #define PLATFORM_LINUX   1
#elif defined(__FreeBSD__)
  #define PLATFORM_FREEBSD 1
#elif defined(__APPLE__) && defined(__MACH__)
  #define PLATFORM_MACOS   1
#elif defined(__OpenBSD__)
  #define PLATFORM_OPENBSD 1
#elif defined(__NetBSD__)
  #define PLATFORM_NETBSD  1
#else
  #error "Plateforme non supportée. Plateformes cibles : Windows, Linux, FreeBSD, macOS, OpenBSD, NetBSD."
#endif

/* =========================================================================
 * Includes communs (C99 standard)
 * ========================================================================= */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

/* =========================================================================
 * Includes spécifiques aux plateformes
 * ========================================================================= */
#ifdef PLATFORM_WINDOWS
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <windows.h>
  #include <winioctl.h>
  /* Sur Windows, pas de isatty POSIX, on utilise GetConsoleMode */
#else
  /* Toutes les plateformes Unix-like */
  #ifndef _POSIX_C_SOURCE
  #define _POSIX_C_SOURCE 200809L
  #endif
  #include <fcntl.h>
  #include <unistd.h>
  #include <sys/types.h>
  #include <sys/ioctl.h>
#endif

#ifdef PLATFORM_FREEBSD
  #include <sys/sysctl.h>
  #include <sys/disk.h>
#endif

#ifdef PLATFORM_LINUX
  #include <linux/fs.h>    /* BLKSSZGET, BLKGETSIZE64 */
#endif

#ifdef PLATFORM_MACOS
  #include <sys/disk.h>    /* DKIOCGETBLOCKSIZE, DKIOCGETBLOCKCOUNT */
#endif

#ifdef PLATFORM_OPENBSD
  #include <sys/disklabel.h>
  #include <sys/dkio.h>
#endif

#ifdef PLATFORM_NETBSD
  #include <sys/disklabel.h>
  #include <sys/dkio.h>
#endif

/* =========================================================================
 * Constantes globales
 * ========================================================================= */
#define VERSION_STR        "2.0.0"
#define DEFAULT_SECTOR     512
#define MAX_SECTOR         4096
#define MAX_DISKS          32
#define MAX_DISK_PATH      256
#define MAX_GPT_ENTRIES    128
#define GPT_ENTRY_SIZE     128
#define GPT_ENTRY_ARRAY_SZ (MAX_GPT_ENTRIES * GPT_ENTRY_SIZE)

/* MBR */
#define MBR_PART_TABLE_OFF 446
#define MBR_SIGNATURE_OFF  510
#define MBR_PART_ENTRY_SZ  16
#define MBR_NUM_PARTS      4
#define MBR_ACTIVE_FLAG    0x80
#define MBR_TYPE_EFI_GPT   0xEE

/* GPT Header (offsets dans LBA1) */
#define GPT_SIG_OFF        0
#define GPT_HDRSIZE_OFF    12
#define GPT_HDRCRC_OFF     16
#define GPT_PARTLBA_OFF    72
#define GPT_NPARTS_OFF     80
#define GPT_ENTSIZE_OFF    84
#define GPT_PARTCRC_OFF    88

/* =========================================================================
 * Couleurs ANSI (Unix uniquement — Windows utilise SetConsoleTextAttribute)
 * ========================================================================= */
#ifndef PLATFORM_WINDOWS
static int use_color = 0;
#define COL(c) (use_color ? (c) : "")
#define RED    "\x1B[31m"
#define GRN    "\x1B[32m"
#define YEL    "\x1B[33m"
#define CYN    "\x1B[36m"
#define BOLD   "\x1B[1m"
#define RESET  "\x1B[0m"
#else
/* Sur Windows on utilise des fonctions dédiées, pas de macros ANSI */
#define COL(c) ""
#define RED    ""
#define GRN    ""
#define YEL    ""
#define CYN    ""
#define BOLD   ""
#define RESET  ""
#endif

/* =========================================================================
 * Abstraction du handle de fichier (HANDLE sur Windows, int fd sur Unix)
 * ========================================================================= */
#ifdef PLATFORM_WINDOWS
typedef HANDLE disk_handle_t;
#define INVALID_DISK_HANDLE  INVALID_HANDLE_VALUE
#else
typedef int disk_handle_t;
#define INVALID_DISK_HANDLE  (-1)
#endif

/* =========================================================================
 * GUIDs types de partitions (little-endian sur disque)
 * ========================================================================= */
static const uint8_t GUID_ESP[16] = {
    0x28, 0x73, 0x2A, 0xC1,  0x1F, 0xF8,  0xD2, 0x11,
    0xBA, 0x4B, 0x00, 0xA0,  0xC9, 0x3E,  0xC9, 0x3B
};
static const uint8_t GUID_FREEBSD_BOOT[16] = {
    0x9D, 0x6B, 0xBD, 0x83,  0x41, 0x7F,  0xDC, 0x11,
    0xBE, 0x0B, 0x00, 0x15,  0x60, 0xB8,  0x4F, 0x0F
};
static const uint8_t GUID_FREEBSD_UFS[16] = {
    0xB6, 0x7C, 0x6E, 0x51,  0xCF, 0x6E,  0xD6, 0x11,
    0x8F, 0xF8, 0x00, 0x02,  0x2D, 0x09,  0x71, 0x2B
};
static const uint8_t GUID_FREEBSD_ZFS[16] = {
    0xBA, 0x7C, 0x6E, 0x51,  0xCF, 0x6E,  0xD6, 0x11,
    0x8F, 0xF8, 0x00, 0x02,  0x2D, 0x09,  0x71, 0x2B
};
/* Linux root x86-64 : 4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709 */
static const uint8_t GUID_LINUX_ROOT_X64[16] = {
    0xE3, 0xBC, 0x68, 0x4F,  0xCD, 0xE8,  0xB1, 0x4D,
    0x96, 0xE7, 0xFB, 0xCA,  0xF9, 0x84,  0xB7, 0x09
};
/* Linux data : EBD0A0A2-B9E5-4433-87C0-68B6B72699C7 */
static const uint8_t GUID_LINUX_DATA[16] = {
    0xA2, 0xA0, 0xD0, 0xEB,  0xE5, 0xB9,  0x33, 0x44,
    0x87, 0xC0, 0x68, 0xB6,  0xB7, 0x26,  0x99, 0xC7
};
/* Microsoft Basic Data : EBD0A0A2 (même GUID que Linux data, standard) */
/* Microsoft Reserved : E3C9E316-0B5C-4DB8-817D-F92DF00215AE */
static const uint8_t GUID_MS_RESERVED[16] = {
    0x16, 0xE3, 0xC9, 0xE3,  0x5C, 0x0B,  0xB8, 0x4D,
    0x81, 0x7D, 0xF9, 0x2D,  0xF0, 0x02,  0x15, 0xAE
};
/* Apple HFS+ : 48465300-0000-11AA-AA11-00306543ECAC */
static const uint8_t GUID_APPLE_HFS[16] = {
    0x00, 0x53, 0x46, 0x48,  0x00, 0x00,  0xAA, 0x11,
    0xAA, 0x11, 0x00, 0x30,  0x65, 0x43,  0xEC, 0xAC
};
/* Apple APFS : 7C3457EF-0000-11AA-AA11-00306543ECAC */
static const uint8_t GUID_APPLE_APFS[16] = {
    0xEF, 0x57, 0x34, 0x7C,  0x00, 0x00,  0xAA, 0x11,
    0xAA, 0x11, 0x00, 0x30,  0x65, 0x43,  0xEC, 0xAC
};

static const uint8_t GUID_ZERO[16] = { 0 };

/* =========================================================================
 * Structures de résultat
 * ========================================================================= */
typedef struct {
    /* MBR */
    int      mbr_signature_ok;
    int      mbr_active_part;
    int      mbr_is_protective;

    /* GPT */
    int      gpt_header_found;
    int      gpt_header_crc_ok;
    int      gpt_partcrc_ok;
    int      gpt_has_esp;
    int      gpt_has_fbsd_boot;
    int      gpt_has_fbsd_ufs;
    int      gpt_has_fbsd_zfs;
    int      gpt_has_linux_root;
    int      gpt_has_linux_data;
    int      gpt_has_ms_reserved;
    int      gpt_has_apple_hfs;
    int      gpt_has_apple_apfs;

    /* Disque */
    uint32_t sector_size;
    uint64_t disk_size_bytes;
    int      is_hybrid;

    /* Verdict */
    int      bootable_bios;
    int      bootable_uefi;
} DiskReport;

/* =========================================================================
 * Interface d'abstraction plateforme (HAL — Hardware Abstraction Layer)
 * Toutes les fonctions système spécifiques passent par cette interface.
 * ========================================================================= */
typedef struct {
    /* Ouvre un disque en lecture seule */
    disk_handle_t (*open_disk)(const char *path);
    /* Ferme le handle */
    void          (*close_disk)(disk_handle_t h);
    /* Lit 'size' octets depuis l'offset 'offset_bytes' */
    int           (*read_at)(disk_handle_t h, uint64_t offset_bytes,
                             uint8_t *buf, uint32_t size);
    /* Retourne la taille de secteur logique */
    uint32_t      (*get_sector_size)(disk_handle_t h);
    /* Retourne la capacité totale en octets */
    uint64_t      (*get_disk_size)(disk_handle_t h);
    /* Remplit disk_paths[] avec les chemins des disques détectés */
    int           (*list_disks)(char paths[MAX_DISKS][MAX_DISK_PATH]);
    /* Vérifie si stdout est un terminal (pour les couleurs) */
    int           (*is_tty)(void);
} PlatformOps;

/* =========================================================================
 * CRC32 ANSI (CCITT, polynôme 0x04C11DB7, seed ~0, XOR ~0)
 * ========================================================================= */
static uint32_t g_crc32_table[256];
static int      g_crc32_ready = 0;

static void crc32_init(void)
{
    uint32_t i, j, c;
    for (i = 0; i < 256; i++) {
        c = i;
        for (j = 0; j < 8; j++)
            c = (c & 1) ? ((c >> 1) ^ 0xEDB88320U) : (c >> 1);
        g_crc32_table[i] = c;
    }
    g_crc32_ready = 1;
}

static uint32_t crc32_buf(const uint8_t *buf, size_t len)
{
    uint32_t c = 0xFFFFFFFFU;
    size_t   i;
    if (!g_crc32_ready) crc32_init();
    for (i = 0; i < len; i++)
        c = (c >> 8) ^ g_crc32_table[(c ^ buf[i]) & 0xFF];
    return c ^ 0xFFFFFFFFU;
}

/* =========================================================================
 * Helpers lecture little-endian
 * ========================================================================= */
static inline uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8)
         | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}

static inline uint64_t le64(const uint8_t *p)
{
    return (uint64_t)le32(p) | ((uint64_t)le32(p+4) << 32);
}

/* =========================================================================
 * Moteur d'analyse MBR (indépendant de l'OS)
 * ========================================================================= */
static void engine_analyze_mbr(const uint8_t *sec0, DiskReport *r)
{
    int i;
    r->mbr_signature_ok = (sec0[510] == 0x55 && sec0[511] == 0xAA);
    if (!r->mbr_signature_ok) return;
    for (i = 0; i < MBR_NUM_PARTS; i++) {
        const uint8_t *e = sec0 + MBR_PART_TABLE_OFF + i * MBR_PART_ENTRY_SZ;
        if (e[0] == MBR_ACTIVE_FLAG)  r->mbr_active_part    = 1;
        if (e[4] == MBR_TYPE_EFI_GPT) r->mbr_is_protective  = 1;
    }
}

/* =========================================================================
 * Moteur d'analyse GPT (indépendant de l'OS)
 * Prend la PlatformOps pour relire les secteurs via le HAL.
 * ========================================================================= */
static void engine_analyze_gpt(disk_handle_t h, const uint8_t *sec1,
                                uint32_t ssize, DiskReport *r,
                                const PlatformOps *ops)
{
    uint32_t hdr_size, stored_crc, comp_crc;
    uint32_t nparts, entsize;
    uint64_t part_lba;
    uint8_t  hcopy[MAX_SECTOR];
    uint8_t *parr = NULL;
    size_t   arr_bytes;
    int      i;

    if (memcmp(sec1, "EFI PART", 8) != 0) return;
    r->gpt_header_found = 1;

    hdr_size = le32(sec1 + GPT_HDRSIZE_OFF);
    if (hdr_size < 92 || hdr_size > ssize) return;

    /* Validation CRC32 header */
    stored_crc = le32(sec1 + GPT_HDRCRC_OFF);
    memcpy(hcopy, sec1, hdr_size);
    memset(hcopy + GPT_HDRCRC_OFF, 0, 4);
    comp_crc = crc32_buf(hcopy, hdr_size);
    r->gpt_header_crc_ok = (comp_crc == stored_crc);

    nparts   = le32(sec1 + GPT_NPARTS_OFF);
    entsize  = le32(sec1 + GPT_ENTSIZE_OFF);
    part_lba = le64(sec1 + GPT_PARTLBA_OFF);

    if (nparts == 0 || entsize < 128 || entsize > 512 ||
        nparts > MAX_GPT_ENTRIES || part_lba < 2) return;

    arr_bytes = (size_t)nparts * entsize;
    if (arr_bytes > 2 * 1024 * 1024) return;  /* sanity cap */

    parr = (uint8_t *)malloc(arr_bytes);
    if (!parr) return;

    /* Lecture de la partition entry array via HAL */
    {
        uint64_t off = part_lba * ssize;
        uint64_t remaining = arr_bytes;
        uint8_t  tmp[MAX_SECTOR];
        uint64_t written = 0;

        while (written < (uint64_t)arr_bytes) {
            uint32_t chunk = ssize;
            if (remaining < chunk) chunk = (uint32_t)remaining;
            if (ops->read_at(h, off, tmp, ssize) < 0) {
                free(parr);
                return;
            }
            memcpy(parr + written, tmp, chunk);
            written   += chunk;
            remaining -= chunk;
            off       += ssize;
        }
    }

    /* Validation CRC32 partition array */
    {
        uint32_t s_pcrc = le32(sec1 + GPT_PARTCRC_OFF);
        uint32_t c_pcrc = crc32_buf(parr, arr_bytes);
        r->gpt_partcrc_ok = (s_pcrc == c_pcrc);
    }

    /* Scan des partitions */
    for (i = 0; i < (int)nparts; i++) {
        const uint8_t *e    = parr + i * entsize;
        const uint8_t *tguid = e;

        if (memcmp(tguid, GUID_ZERO, 16) == 0) continue;

        if      (memcmp(tguid, GUID_ESP,          16) == 0) r->gpt_has_esp         = 1;
        else if (memcmp(tguid, GUID_FREEBSD_BOOT, 16) == 0) r->gpt_has_fbsd_boot   = 1;
        else if (memcmp(tguid, GUID_FREEBSD_UFS,  16) == 0) r->gpt_has_fbsd_ufs    = 1;
        else if (memcmp(tguid, GUID_FREEBSD_ZFS,  16) == 0) r->gpt_has_fbsd_zfs    = 1;
        else if (memcmp(tguid, GUID_LINUX_ROOT_X64,16)== 0) r->gpt_has_linux_root  = 1;
        else if (memcmp(tguid, GUID_LINUX_DATA,   16) == 0) r->gpt_has_linux_data  = 1;
        else if (memcmp(tguid, GUID_MS_RESERVED,  16) == 0) r->gpt_has_ms_reserved = 1;
        else if (memcmp(tguid, GUID_APPLE_HFS,    16) == 0) r->gpt_has_apple_hfs   = 1;
        else if (memcmp(tguid, GUID_APPLE_APFS,   16) == 0) r->gpt_has_apple_apfs  = 1;
    }

    free(parr);
    r->is_hybrid = r->mbr_is_protective && r->gpt_header_found;
}

/* =========================================================================
 * Verdict final (commun toutes plateformes)
 * ========================================================================= */
static void compute_verdict(DiskReport *r)
{
    r->bootable_bios = 0;
    if (r->mbr_signature_ok && r->mbr_active_part && !r->mbr_is_protective)
        r->bootable_bios = 1;
    if (r->gpt_header_found && r->gpt_header_crc_ok && r->gpt_has_fbsd_boot)
        r->bootable_bios = 1;

    r->bootable_uefi = 0;
    if (r->gpt_header_found && r->gpt_header_crc_ok && r->gpt_has_esp)
        r->bootable_uefi = 1;
}

/* =========================================================================
 * Affichage du rapport (commun toutes plateformes)
 * ========================================================================= */
static void format_size(uint64_t b, char *buf, size_t blen)
{
    const uint64_t TB = (uint64_t)1024 * 1024 * 1024 * 1024;
    const uint64_t GB = (uint64_t)1024 * 1024 * 1024;
    const uint64_t MB = (uint64_t)1024 * 1024;
    if      (b == 0)   snprintf(buf, blen, "inconnu");
    else if (b >= TB)  snprintf(buf, blen, "%.2f To", (double)b / (double)TB);
    else if (b >= GB)  snprintf(buf, blen, "%.2f Go", (double)b / (double)GB);
    else if (b >= MB)  snprintf(buf, blen, "%.2f Mo", (double)b / (double)MB);
    else               snprintf(buf, blen, "%.2f Ko", (double)b / 1024.0);
}

static const char *os_name(void)
{
#if defined(PLATFORM_WINDOWS)
    return "Windows";
#elif defined(PLATFORM_LINUX)
    return "Linux";
#elif defined(PLATFORM_FREEBSD)
    return "FreeBSD";
#elif defined(PLATFORM_MACOS)
    return "macOS";
#elif defined(PLATFORM_OPENBSD)
    return "OpenBSD";
#elif defined(PLATFORM_NETBSD)
    return "NetBSD";
#else
    return "Unknown";
#endif
}

static void print_report(const char *path, const DiskReport *r)
{
    char sz[32];
    format_size(r->disk_size_bytes, sz, sizeof(sz));

    printf("\n%s%s[ RAPPORT : %s ]%s\n",
           COL(BOLD), COL(CYN), path, COL(RESET));
    printf("%s%s=================================================%s\n",
           COL(BOLD), COL(CYN), COL(RESET));
    printf("  Plateforme         : %s\n", os_name());
    printf("  Taille de secteur  : %u octets%s\n",
           r->sector_size,
           r->sector_size == 4096 ? " (4Kn natif)" : "");
    printf("  Capacité disque    : %s\n\n", sz);

    /* MBR */
    printf("%s--- Analyse MBR (LBA 0) ---%s\n", COL(BOLD), COL(RESET));
    printf("  Signature 0x55AA   : %s%s%s\n",
           r->mbr_signature_ok ? COL(GRN) : COL(RED),
           r->mbr_signature_ok ? "VALIDE" : "ABSENTE", COL(RESET));
    if (r->mbr_signature_ok) {
        if (r->mbr_is_protective)
            printf("  Type               : %sMBR PROTECTIF (0xEE) → GPT présent%s\n",
                   COL(YEL), COL(RESET));
        else
            printf("  Partition active   : %s%s%s\n",
                   r->mbr_active_part ? COL(GRN) : COL(RED),
                   r->mbr_active_part ? "OUI" : "NON", COL(RESET));
    }

    /* GPT */
    printf("\n%s--- Analyse GPT (LBA 1) ---%s\n", COL(BOLD), COL(RESET));
    printf("  Signature EFI PART : %s%s%s\n",
           r->gpt_header_found ? COL(GRN) : COL(RED),
           r->gpt_header_found ? "TROUVÉE" : "ABSENTE", COL(RESET));
    if (r->gpt_header_found) {
        printf("  CRC32 Header       : %s%s%s\n",
               r->gpt_header_crc_ok ? COL(GRN) : COL(RED),
               r->gpt_header_crc_ok ? "VALIDE" : "INVALIDE !", COL(RESET));
        printf("  CRC32 Partitions   : %s%s%s\n",
               r->gpt_partcrc_ok ? COL(GRN) : COL(RED),
               r->gpt_partcrc_ok ? "VALIDE" : "INVALIDE !", COL(RESET));
        printf("\n  %sPartitions GPT détectées :%s\n", COL(BOLD), COL(RESET));

        /* Partitions universelles */
        printf("    ESP (EFI System)   : %s%s%s\n",
               r->gpt_has_esp ? COL(GRN) : COL(YEL),
               r->gpt_has_esp ? "OUI" : "NON", COL(RESET));

        /* FreeBSD */
        if (r->gpt_has_fbsd_boot || r->gpt_has_fbsd_ufs || r->gpt_has_fbsd_zfs) {
            printf("    [FreeBSD] freebsd-boot : %s%s%s\n",
                   r->gpt_has_fbsd_boot ? COL(GRN) : COL(YEL),
                   r->gpt_has_fbsd_boot ? "OUI" : "NON", COL(RESET));
            printf("    [FreeBSD] freebsd-ufs  : %s%s%s\n",
                   r->gpt_has_fbsd_ufs ? COL(GRN) : COL(YEL),
                   r->gpt_has_fbsd_ufs ? "OUI" : "NON", COL(RESET));
            printf("    [FreeBSD] freebsd-zfs  : %s%s%s\n",
                   r->gpt_has_fbsd_zfs ? COL(GRN) : COL(YEL),
                   r->gpt_has_fbsd_zfs ? "OUI" : "NON", COL(RESET));
        }

        /* Linux */
        if (r->gpt_has_linux_root || r->gpt_has_linux_data) {
            printf("    [Linux]   root x86-64  : %s%s%s\n",
                   r->gpt_has_linux_root ? COL(GRN) : COL(YEL),
                   r->gpt_has_linux_root ? "OUI" : "NON", COL(RESET));
            printf("    [Linux]   data         : %s%s%s\n",
                   r->gpt_has_linux_data ? COL(GRN) : COL(YEL),
                   r->gpt_has_linux_data ? "OUI" : "NON", COL(RESET));
        }

        /* Windows */
        if (r->gpt_has_ms_reserved)
            printf("    [Windows] MS Reserved  : %sOUI%s\n", COL(GRN), COL(RESET));

        /* macOS */
        if (r->gpt_has_apple_hfs || r->gpt_has_apple_apfs) {
            printf("    [macOS]   HFS+         : %s%s%s\n",
                   r->gpt_has_apple_hfs ? COL(GRN) : COL(YEL),
                   r->gpt_has_apple_hfs ? "OUI" : "NON", COL(RESET));
            printf("    [macOS]   APFS         : %s%s%s\n",
                   r->gpt_has_apple_apfs ? COL(GRN) : COL(YEL),
                   r->gpt_has_apple_apfs ? "OUI" : "NON", COL(RESET));
        }

        if (r->is_hybrid)
            printf("\n  %sDISQUE HYBRIDE : MBR protectif + GPT valide%s\n",
                   COL(YEL), COL(RESET));
    }

    /* Verdict */
    printf("\n%s%s=================================================%s\n",
           COL(BOLD), COL(CYN), COL(RESET));
    printf("%s  VERDICT FINAL%s\n", COL(BOLD), COL(RESET));
    printf("%s%s=================================================%s\n",
           COL(BOLD), COL(CYN), COL(RESET));

    if (r->bootable_bios && r->bootable_uefi)
        printf("  %s%s✓ BOOTABLE — BIOS + UEFI (Dual Mode)%s\n",
               COL(BOLD), COL(GRN), COL(RESET));
    else if (r->bootable_bios)
        printf("  %s%s✓ BOOTABLE — BIOS (Legacy)%s\n",
               COL(BOLD), COL(GRN), COL(RESET));
    else if (r->bootable_uefi)
        printf("  %s%s✓ BOOTABLE — UEFI%s\n",
               COL(BOLD), COL(GRN), COL(RESET));
    else {
        printf("  %s%s✗ NON BOOTABLE%s\n",
               COL(BOLD), COL(RED), COL(RESET));
        printf("\n  %sDiagnostic :%s\n", COL(YEL), COL(RESET));
        if (!r->mbr_signature_ok && !r->gpt_header_found)
            printf("    → Aucune table de partition reconnue.\n");
        if (r->mbr_signature_ok && !r->mbr_active_part && !r->mbr_is_protective)
            printf("    → MBR présent sans partition active.\n");
        if (r->gpt_header_found && !r->gpt_header_crc_ok)
            printf("    → GPT header corrompu (CRC invalide).\n");
        if (r->gpt_header_found && r->gpt_header_crc_ok && !r->gpt_has_esp)
            printf("    → GPT valide mais pas d'ESP (partition UEFI manquante).\n");
    }
    printf("%s%s=================================================%s\n\n",
           COL(BOLD), COL(CYN), COL(RESET));
}

/* =========================================================================
 * Moteur principal : analyse un disque via le HAL
 * ========================================================================= */
static int run_analysis(const char *path, const PlatformOps *ops)
{
    DiskReport   r;
    disk_handle_t h;
    uint32_t     ssize;
    uint8_t      sec0[MAX_SECTOR];
    uint8_t      sec1[MAX_SECTOR];

    memset(&r, 0, sizeof(r));

    h = ops->open_disk(path);
    if (h == INVALID_DISK_HANDLE) {
#ifdef PLATFORM_WINDOWS
        fprintf(stderr, "Erreur : impossible d'ouvrir %s (code %lu)\n"
                "  → Relancez en tant qu'Administrateur.\n",
                path, (unsigned long)GetLastError());
#else
        fprintf(stderr, "%sErreur%s : impossible d'ouvrir %s : %s\n"
                "  → Relancez avec les droits root.\n",
                COL(RED), COL(RESET), path, strerror(errno));
#endif
        return -1;
    }

    ssize             = ops->get_sector_size(h);
    r.sector_size     = ssize;
    r.disk_size_bytes = ops->get_disk_size(h);

    memset(sec0, 0, MAX_SECTOR);
    memset(sec1, 0, MAX_SECTOR);

    if (ops->read_at(h, 0, sec0, ssize) < 0 ||
        ops->read_at(h, (uint64_t)ssize, sec1, ssize) < 0) {
        fprintf(stderr, "Erreur de lecture sur %s\n", path);
        ops->close_disk(h);
        return -1;
    }

    engine_analyze_mbr(sec0, &r);
    engine_analyze_gpt(h, sec1, ssize, &r, ops);
    compute_verdict(&r);
    ops->close_disk(h);
    print_report(path, &r);

    return (r.bootable_bios || r.bootable_uefi) ? 0 : 1;
}

/* =========================================================================
 * ██████████████████████████████████████████████████████████████████████
 * IMPLÉMENTATIONS HAL PAR PLATEFORME
 * ██████████████████████████████████████████████████████████████████████
 * ========================================================================= */

/* ================================================================
 * HAL WINDOWS
 * ================================================================ */
#ifdef PLATFORM_WINDOWS

static disk_handle_t win_open_disk(const char *path)
{
    HANDLE h = CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING,   /* nécessaire pour lecture alignée sur secteur */
        NULL
    );
    return (h == INVALID_HANDLE_VALUE) ? INVALID_DISK_HANDLE : h;
}

static void win_close_disk(disk_handle_t h) { CloseHandle(h); }

static int win_read_at(disk_handle_t h, uint64_t offset, uint8_t *buf, uint32_t size)
{
    LARGE_INTEGER li;
    DWORD         nread = 0;
    li.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN)) return -1;
    if (!ReadFile(h, buf, size, &nread, NULL) || nread != size) return -1;
    return 0;
}

static uint32_t win_get_sector_size(disk_handle_t h)
{
    STORAGE_PROPERTY_QUERY     spq;
    STORAGE_ACCESS_ALIGNMENT_PROPERTY saap;
    DWORD bytes = 0;
    memset(&spq,  0, sizeof(spq));
    memset(&saap, 0, sizeof(saap));
    spq.PropertyId = StorageAccessAlignmentProperty;
    spq.QueryType  = PropertyStandardQuery;
    if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
                        &spq, sizeof(spq), &saap, sizeof(saap), &bytes, NULL))
        return (saap.BytesPerLogicalSector > 0)
               ? saap.BytesPerLogicalSector : DEFAULT_SECTOR;
    return DEFAULT_SECTOR;
}

static uint64_t win_get_disk_size(disk_handle_t h)
{
    DISK_GEOMETRY_EX dge;
    DWORD bytes = 0;
    if (DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                        NULL, 0, &dge, sizeof(dge), &bytes, NULL))
        return (uint64_t)dge.DiskSize.QuadPart;
    return 0;
}

static int win_list_disks(char paths[MAX_DISKS][MAX_DISK_PATH])
{
    int count = 0;
    int i;
    HANDLE h;
    char   tmp[64];
    for (i = 0; i < MAX_DISKS; i++) {
        snprintf(tmp, sizeof(tmp), "\\\\.\\PhysicalDrive%d", i);
        h = CreateFileA(tmp, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            snprintf(paths[count], MAX_DISK_PATH, "%s", tmp);
            count++;
        }
    }
    return count;
}

static int win_is_tty(void)
{
    DWORD mode;
    return GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mode) ? 1 : 0;
}

static PlatformOps g_ops = {
    win_open_disk, win_close_disk, win_read_at,
    win_get_sector_size, win_get_disk_size, win_list_disks, win_is_tty
};

#endif /* PLATFORM_WINDOWS */

/* ================================================================
 * HAL UNIX GÉNÉRIQUE (Linux, FreeBSD, macOS, OpenBSD, NetBSD)
 * ================================================================ */
#ifndef PLATFORM_WINDOWS

static disk_handle_t unix_open_disk(const char *path)
{
    int fd = open(path, O_RDONLY);
    return (fd < 0) ? INVALID_DISK_HANDLE : fd;
}

static void unix_close_disk(disk_handle_t fd) { close(fd); }

static int unix_read_at(disk_handle_t fd, uint64_t offset, uint8_t *buf, uint32_t size)
{
    ssize_t n = pread(fd, buf, size, (off_t)offset);
    return (n == (ssize_t)size) ? 0 : -1;
}

static uint32_t unix_get_sector_size(disk_handle_t fd)
{
#if defined(PLATFORM_FREEBSD)
    u_int sz = 0;
    if (ioctl(fd, DIOCGSECTORSIZE, &sz) == 0 && sz > 0) return (uint32_t)sz;

#elif defined(PLATFORM_LINUX)
    int sz = 0;
    if (ioctl(fd, BLKSSZGET, &sz) == 0 && sz > 0) return (uint32_t)sz;

#elif defined(PLATFORM_MACOS)
    uint32_t sz = 0;
    if (ioctl(fd, DKIOCGETBLOCKSIZE, &sz) == 0 && sz > 0) return sz;

#elif defined(PLATFORM_OPENBSD) || defined(PLATFORM_NETBSD)
    struct disklabel dl;
    if (ioctl(fd, DIOCGDINFO, &dl) == 0 && dl.d_secsize > 0)
        return (uint32_t)dl.d_secsize;
#endif
    return DEFAULT_SECTOR;
}

static uint64_t unix_get_disk_size(disk_handle_t fd)
{
#if defined(PLATFORM_FREEBSD)
    off_t sz = 0;
    if (ioctl(fd, DIOCGMEDIASIZE, &sz) == 0) return (uint64_t)sz;

#elif defined(PLATFORM_LINUX)
    uint64_t sz = 0;
    if (ioctl(fd, BLKGETSIZE64, &sz) == 0) return sz;

#elif defined(PLATFORM_MACOS)
    uint32_t bsize = 0, count = 0;
    /* macOS : taille = nb blocs × taille bloc */
    if (ioctl(fd, DKIOCGETBLOCKSIZE,  &bsize) == 0 &&
        ioctl(fd, DKIOCGETBLOCKCOUNT, &count) == 0)
        return (uint64_t)bsize * count;

#elif defined(PLATFORM_OPENBSD) || defined(PLATFORM_NETBSD)
    struct disklabel dl;
    if (ioctl(fd, DIOCGDINFO, &dl) == 0)
        return (uint64_t)dl.d_secsize * dl.d_nsectors
               * dl.d_ntracks * dl.d_ncylinders;
#endif
    return 0;
}

/* ---- Listing des disques (dépend de l'OS) ---- */

#ifdef PLATFORM_FREEBSD
static int unix_list_disks(char paths[MAX_DISKS][MAX_DISK_PATH])
{
    char   raw[4096];
    size_t len = sizeof(raw);
    int    count = 0;
    char  *tok;
    if (sysctlbyname("kern.disks", raw, &len, NULL, 0) < 0) return -1;
    tok = strtok(raw, " \t\n");
    while (tok && count < MAX_DISKS) {
        if (strncmp(tok,"ada",3)==0 || strncmp(tok,"da",2)==0 ||
            strncmp(tok,"nvd",3)==0 || strncmp(tok,"vtblk",5)==0 ||
            strncmp(tok,"mmcsd",5)==0 || strncmp(tok,"md",2)==0) {
            snprintf(paths[count++], MAX_DISK_PATH, "/dev/%s", tok);
        }
        tok = strtok(NULL, " \t\n");
    }
    return count;
}
#endif

#ifdef PLATFORM_LINUX
static int unix_list_disks(char paths[MAX_DISKS][MAX_DISK_PATH])
{
    FILE *f;
    char  line[256], dev[64];
    int   count = 0;
    unsigned long long major_num, minor_num, blocks;

    f = fopen("/proc/partitions", "r");
    if (!f) return -1;

    /* Lire l'en-tête */
    if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }
    if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }

    while (fgets(line, sizeof(line), f) && count < MAX_DISKS) {
        if (sscanf(line, " %llu %llu %llu %63s",
                   &major_num, &minor_num, &blocks, dev) == 4) {
            /*
             * On ne garde que les disques entiers (pas de partitions) :
             * sda, sdb, nvme0n1, vda, hda, mmcblk0, etc.
             * On exclut sda1, sdb2, nvme0n1p1... (contiennent un chiffre
             * final après un 'p' ou directement collé à la lettre).
             */
            size_t dlen = strlen(dev);
            int    is_part = 0;
            if (dlen > 0 && dev[dlen-1] >= '0' && dev[dlen-1] <= '9') {
                /* nvme0n1p1 → a un 'p' avant le chiffre */
                if (dlen > 2 && dev[dlen-2] == 'p') is_part = 1;
                /* sda1 → lettre(s) puis chiffre(s) */
                else if (dlen > 2 && dev[dlen-2] >= 'a') is_part = 1;
            }
            if (!is_part) {
                snprintf(paths[count++], MAX_DISK_PATH, "/dev/%s", dev);
            }
        }
    }
    fclose(f);
    return count;
}
#endif

#ifdef PLATFORM_MACOS
static int unix_list_disks(char paths[MAX_DISKS][MAX_DISK_PATH])
{
    int  count = 0;
    int  i;
    char tmp[MAX_DISK_PATH];
    int  fd;
    /* macOS : /dev/disk0, /dev/disk1, ... */
    for (i = 0; i < MAX_DISKS; i++) {
        snprintf(tmp, sizeof(tmp), "/dev/disk%d", i);
        fd = open(tmp, O_RDONLY);
        if (fd >= 0) {
            close(fd);
            snprintf(paths[count++], MAX_DISK_PATH, "%s", tmp);
        }
    }
    return count;
}
#endif

#if defined(PLATFORM_OPENBSD) || defined(PLATFORM_NETBSD)
static int unix_list_disks(char paths[MAX_DISKS][MAX_DISK_PATH])
{
    /* OpenBSD/NetBSD : /dev/sd0c, /dev/wd0c, etc. */
    const char *prefixes[] = { "sd", "wd", "cd", NULL };
    int count = 0, i, n;
    char tmp[MAX_DISK_PATH];
    int  fd;
    for (n = 0; prefixes[n] && count < MAX_DISKS; n++) {
        for (i = 0; i < 8 && count < MAX_DISKS; i++) {
            /* On utilise la slice 'c' (whole disk) */
            snprintf(tmp, sizeof(tmp), "/dev/%s%dc", prefixes[n], i);
            fd = open(tmp, O_RDONLY);
            if (fd >= 0) {
                close(fd);
                snprintf(paths[count++], MAX_DISK_PATH, "%s", tmp);
            }
        }
    }
    return count;
}
#endif

static int unix_is_tty(void) { return isatty(STDOUT_FILENO); }

static PlatformOps g_ops = {
    unix_open_disk, unix_close_disk, unix_read_at,
    unix_get_sector_size, unix_get_disk_size, unix_list_disks, unix_is_tty
};

#endif /* !PLATFORM_WINDOWS */

/* =========================================================================
 * Mode interactif
 * ========================================================================= */
static void print_header(void)
{
    printf("\n%s%s", COL(BOLD), COL(CYN));
    printf("╔═══════════════════════════════════════════════════╗\n");
    printf("║   BOOTABILITY CHECKER v%s — Cross-Platform    ║\n", VERSION_STR);
    printf("║   Plateformes : FreeBSD/Linux/Windows/macOS/BSD   ║\n");
    printf("╚═══════════════════════════════════════════════════╝\n");
    printf("  Plateforme active : %s%s%s\n\n",
           COL(YEL), os_name(), COL(RESET));
}

static void print_help(const char *prog)
{
    printf("Usage:\n");
    printf("  %s                         Mode interactif\n",   prog);
    printf("  %s <chemin_disque>          Analyse directe\n",   prog);
    printf("  %s --all                    Tous les disques\n",  prog);
    printf("  %s --help                   Cette aide\n",        prog);
    printf("  %s --version                Version\n",           prog);
    printf("\nExemples par OS:\n");
    printf("  Linux   : sudo %s /dev/sda\n", prog);
    printf("  FreeBSD : sudo %s /dev/ada0\n", prog);
    printf("  macOS   : sudo %s /dev/disk0\n", prog);
    printf("  Windows : %s \\\\.\\PhysicalDrive0  (en Admin)\n", prog);
    printf("  OpenBSD : sudo %s /dev/sd0c\n", prog);
}

static int interactive_mode(const PlatformOps *ops)
{
    char paths[MAX_DISKS][MAX_DISK_PATH];
    int  count, choice, c;

    count = ops->list_disks(paths);
    if (count <= 0) {
        printf("Aucun disque détecté (ou droits insuffisants).\n");
        return 2;
    }

    printf("%sDisques détectés :%s\n", COL(BOLD), COL(RESET));
    for (int i = 0; i < count; i++)
        printf("  [%2d] %s\n", i + 1, paths[i]);

    printf("\nChoisissez un numéro (0 pour quitter) : ");
    fflush(stdout);

    if (scanf("%d", &choice) != 1) {
        while ((c = getchar()) != '\n' && c != EOF) {}
        fprintf(stderr, "Entrée invalide.\n");
        return 2;
    }
    while ((c = getchar()) != '\n' && c != EOF) {}

    if (choice == 0) return 0;
    if (choice < 1 || choice > count) {
        fprintf(stderr, "Choix hors plage [1-%d].\n", count);
        return 2;
    }

    return run_analysis(paths[choice - 1], ops) == 0 ? 0 : 1;
}

static int all_mode(const PlatformOps *ops)
{
    char paths[MAX_DISKS][MAX_DISK_PATH];
    int  count = ops->list_disks(paths);
    int  i, any = 0;

    if (count <= 0) {
        printf("Aucun disque détecté.\n");
        return count == 0 ? 0 : 2;
    }
    printf("%d disque(s) à analyser...\n", count);
    for (i = 0; i < count; i++)
        if (run_analysis(paths[i], ops) == 0) any = 1;
    return any ? 0 : 1;
}

/* =========================================================================
 * Point d'entrée
 * ========================================================================= */
int main(int argc, char *argv[])
{
    /* Initialisation couleurs */
#ifndef PLATFORM_WINDOWS
    use_color = g_ops.is_tty();
#endif

    print_header();

    if (argc == 1) return interactive_mode(&g_ops);

    if (argc == 2) {
        if (strcmp(argv[1], "--help")    == 0 ||
            strcmp(argv[1], "-h")        == 0) {
            print_help(argv[0]); return 0;
        }
        if (strcmp(argv[1], "--version") == 0 ||
            strcmp(argv[1], "-V")        == 0) {
            printf("bootability_checker %s (%s)\n", VERSION_STR, os_name());
            return 0;
        }
        if (strcmp(argv[1], "--all")     == 0 ||
            strcmp(argv[1], "-a")        == 0) {
            return all_mode(&g_ops);
        }
        if (argv[1][0] != '-') {
            return run_analysis(argv[1], &g_ops) == 0 ? 0 : 1;
        }
    }

    fprintf(stderr, "Argument invalide : %s\nUtilisez --help.\n", argv[1]);
    return 2;
}
