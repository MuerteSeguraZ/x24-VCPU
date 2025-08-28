#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define SECTOR_SIZE 512
#define DISK_SECTORS 16
#define DISK_FILE "filesystem/disk.img"

typedef struct {
    char filename[8];   // up to 7 chars + null
    uint16_t start_sector;
    uint16_t size_bytes;
    uint8_t reserved[4]; // padding/reserved
} __attribute__((packed)) FileEntry;

static FILE *disk_fp = NULL;

/// Open disk image
int OPEN_DISK(const char *path) {
    disk_fp = fopen(path, "r+b");
    if (!disk_fp) {
        perror("OPEN_DISK");
        return -1;
    }
    return 0;
}

/// Close disk image
void CLOSE_DISK() {
    if (disk_fp) fclose(disk_fp);
    disk_fp = NULL;
}

/// Read one sector into buffer
int READ_DISK(uint16_t sector, uint8_t *buffer) {
    if (!disk_fp) return -1;
    if (sector >= DISK_SECTORS) return -2;
    fseek(disk_fp, sector * SECTOR_SIZE, SEEK_SET);
    size_t r = fread(buffer, 1, SECTOR_SIZE, disk_fp);
    return (r == SECTOR_SIZE) ? 0 : -3;
}

/// Write one sector from buffer
int WRITE_DISK(uint16_t sector, const uint8_t *buffer) {
    if (!disk_fp) return -1;
    if (sector >= DISK_SECTORS) return -2;
    fseek(disk_fp, sector * SECTOR_SIZE, SEEK_SET);
    size_t w = fwrite(buffer, 1, SECTOR_SIZE, disk_fp);
    fflush(disk_fp);
    return (w == SECTOR_SIZE) ? 0 : -3;
}

/// Find file entry by name
int FIND_FILE(const char *name, FileEntry *out) {
    if (!disk_fp) return -1;
    uint8_t buffer[SECTOR_SIZE];
    if (READ_DISK(1, buffer) != 0) return -2; // file table at sector 1

    for (int i = 0; i < SECTOR_SIZE / sizeof(FileEntry); i++) {
        FileEntry *entry = (FileEntry*)(buffer + i * sizeof(FileEntry));
        if (entry->filename[0] == 0) continue; // empty entry
        if (strncmp(entry->filename, name, 7) == 0) {
            if (out) memcpy(out, entry, sizeof(FileEntry));
            return 0;
        }
    }
    return -3; // not found
}

/// Read a file by name into memory (malloc'd)
uint8_t* READ_FILE(const char *name, uint16_t *out_size) {
    FileEntry entry;
    if (FIND_FILE(name, &entry) != 0) return NULL;

    uint8_t *data = (uint8_t*)malloc(entry.size_bytes);
    if (!data) return NULL;

    uint16_t bytes_left = entry.size_bytes;
    uint16_t sector = entry.start_sector;
    uint16_t offset = 0;

    while (bytes_left > 0) {
        uint8_t buffer[SECTOR_SIZE];
        if (READ_DISK(sector, buffer) != 0) { free(data); return NULL; }

        uint16_t to_copy = (bytes_left > SECTOR_SIZE) ? SECTOR_SIZE : bytes_left;
        memcpy(data + offset, buffer, to_copy);

        bytes_left -= to_copy;
        offset += to_copy;
        sector++;
    }

    if (out_size) *out_size = entry.size_bytes;
    return data;
}
