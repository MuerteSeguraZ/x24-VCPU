#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define SECTOR_SIZE 512
#define DISK_SECTORS 16
#define DISK_SIZE (SECTOR_SIZE * DISK_SECTORS)

typedef struct {
    char filename[8];   // up to 7 chars + null
    uint16_t start_sector;
    uint16_t size_bytes;
    uint8_t reserved[4]; // padding/reserved
} __attribute__((packed)) FileEntry;

int main(void) {
    FILE *f = fopen("disk.img", "wb+");
    if (!f) {
        perror("disk.img");
        return 1;
    }

    // --- Step 1: Create empty disk ---
    uint8_t zeros[SECTOR_SIZE] = {0};
    for (int i = 0; i < DISK_SECTORS; i++) {
        fwrite(zeros, 1, SECTOR_SIZE, f);
    }

    // --- Step 2: Write superblock (sector 0) ---
    uint8_t superblock[SECTOR_SIZE] = {0};
    memcpy(superblock, "VCFS", 4);    // Magic
    superblock[4] = 0x01;             // Version
    *(uint16_t*)&superblock[5] = DISK_SECTORS; // total sectors
    *(uint16_t*)&superblock[7] = 1;   // file table start
    *(uint16_t*)&superblock[9] = 2;   // data start
    fseek(f, 0, SEEK_SET);
    fwrite(superblock, 1, SECTOR_SIZE, f);

    // --- Step 3: Write file table (sector 1) ---
    uint8_t filetable[SECTOR_SIZE] = {0};
    FileEntry entry = {0};
    strcpy(entry.filename, "HELLO");  // filename
    entry.start_sector = 2;           // where data begins
    entry.size_bytes = 13;            // "Hello, World!" length
    memcpy(filetable, &entry, sizeof(FileEntry));
    fseek(f, SECTOR_SIZE * 1, SEEK_SET);
    fwrite(filetable, 1, SECTOR_SIZE, f);

    // --- Step 4: Write file data (sector 2) ---
    uint8_t filedata[SECTOR_SIZE] = {0};
    memcpy(filedata, "Hello, World!", 13);
    fseek(f, SECTOR_SIZE * 2, SEEK_SET);
    fwrite(filedata, 1, SECTOR_SIZE, f);

    fclose(f);

    printf("disk.img created successfully with HELLO file.\n");
    return 0;
}
