// gcc silent-note.c -o silent-note -O0 -fstack-protector-all -z noexecstack -fPIE -no-pie -s
#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<stdlib.h>
#include <sys/mman.h>

#define SIZE 32

typedef unsigned long uint32;
typedef unsigned long long uint64;
typedef struct struct_note
{
    uint64 note_size;
    char* note_content;
} note;

uint32 notes_size;
note* notes[SIZE];

void read_buffer(char *buffer, uint32 len);
void initialize();
void new_note();
void edit_note();
void delete_note();

int main() {
    initialize();
    while (1) {
        int choice = 0;
        scanf("%d", &choice);
        switch (choice) {
        case 1:
            new_note();
            break;
        case 2:
            edit_note();
            break;
        case 3:
            delete_note();
            break;
        default:
            exit(0);
            break;
        }
    }
    return 0;
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    notes_size = 0;
    memset(notes, 0, 8 * SIZE);
    mprotect((void*)0x601000, 0x1000, PROT_READ | PROT_WRITE);
    alarm(60);
}

void read_buffer(char *buffer, uint32 len) {
    uint32 i;
    char c;
    for (i = 0; i < len; i++) {
        c = '\0';
        if (read(0, &c, 1) < 0) exit(1);
        buffer[i] = c;
    }
}

void new_note() {
    uint32 i = 0;
    int size = 0;
    if (notes_size >= SIZE) exit(2);
    note* p = (note*)calloc(sizeof(note), 1);
    if (!p) exit(3);
    scanf("%d", &size);
    if (size <= 0) exit(4);
    if (size > 0x400) size = 0x400;
    p->note_size = (uint64)size;
    p->note_content = (char*)calloc(size, 1);
    if (!p->note_content) exit(5);
    read_buffer(p->note_content, size);
    for (i = 0; i < SIZE; i++) {
        if (NULL == notes[i]) {
            notes[i] = p;
            notes_size++;
            return;
        }
    }
    exit(6);
}

void edit_note() {
    int index = 0;
    scanf("%d", &index);
    if (!notes[index]) exit(7);
    note* p = (note*)notes[index];
    uint32 size = (uint32)p->note_size;
    read_buffer(p->note_content, size);
}

void delete_note() {
    int index = 0;
    scanf("%d", &index);
    if (!notes[index]) exit(8);
    free((note*)notes[index]->note_content);
    free(notes[index]);
}
