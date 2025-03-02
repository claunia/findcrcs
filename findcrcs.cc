/*
  Copyright 2013, V.

  This file is part of findcrcs.

  This is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this software.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
  This software is using crcutil-1.0 for providing fast crc calculations
  crcutil is made by Andrew Kadatch and Bob Jenkins and can be found on http://code.google.com/p/crcutil/
  Do not contact them for support on this software

  Also, this software makes use of the MD5 implementation of Alexander Peslyak.
  This is found at http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5
  Changes were made for OpenSSL compatibility and a small casting patch for g++ support.
  These changes are released under the same license as the original md5.c file.
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "md5.h"
#include "interface.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define BUFFERSIZE 65536
#define POLY 0xedb88320

int isuint(char *string);
int iscrc(char *string);
int ismd5(char *string);
unsigned int getcrc(char *file);
void usage();

void findcrcs();
int checkcrcs(unsigned int crc, int offset);
void foundcrc(int index, int offset);
unsigned char *md5(int offset);
char *md5hash2string(unsigned char *md5hash);
void extractwindow(int offset, char *md5string);

void extract_init(int offset);
int extract_read(void *buffer, unsigned int size);

char *file, *seedfile, *extractfile;
int fd, extract, single, totalcrcs;
unsigned int padding, filesize, windowsize, seedcrc;

typedef struct {
  unsigned int crc;
  int checkmd5;
  unsigned char md5hash[MD5_DIGEST_LENGTH];
} crc_t;

crc_t *crcs;

int main(int argc, char *argv[]) {
  int i, option;
  struct stat stats;
  unsigned long int ulargument;
  char md5byte[3];
  crc_t *reallocation;

  windowsize = 0;
  extract = 0;
  single = 0;
  padding = 0;
  seedfile = NULL;
  extractfile = NULL;
  
  while ((option = getopt(argc, argv, "ef:p:qs:h?")) != -1) {
    switch (option) {
      case 'e':
        extract = 1;
        break;
      case 'f':
        extractfile = optarg;
        extract = 1;
        single = 1;
        break;
      case 'p':
        if (!isuint(optarg)) {
          fprintf(stderr, "%s: padding size must be a positive integer\n", argv[0]);
          return 1;
        }
        errno = 0;
        ulargument = strtoul(optarg, 0, 10);
        padding = (unsigned int)ulargument;
        if (errno || ulargument > UINT_MAX) {
          fprintf(stderr, "%s: padding size too big\n", argv[0]);
          return 1;
        }
        break;
      case 'q':
        single = 1;
        break;
      case 's':
        seedfile = optarg;
        if ((fd = open(seedfile, O_RDONLY | O_BINARY)) == -1) {
          perror(seedfile);
          return 1;
        }
        close(fd);
        break;
      case 'h':
      case '?':
      default:
        usage();
        return 1;
    }
  }

  if (argc < optind + 2) {
    usage();
    return 1;
  }

  file = argv[optind++];
  if ((fd = open(file, O_RDONLY | O_BINARY)) == -1) {
    perror(file);
    return 1;
  }

  if (stat(file, &stats) == -1) {
    perror(file);
    return 1;
  }
  filesize = stats.st_size;

  if (!isuint(argv[optind])) {
    fprintf(stderr, "%s: Window size must be a positive integer\n", argv[0]);
    return 1;
  }

  errno = 0;
  ulargument = strtoul(argv[optind++], 0, 10);
  windowsize = (unsigned int)ulargument;
  if (errno || ulargument > UINT_MAX || (windowsize + (2 * padding)) > filesize) {
    fprintf(stderr, "%s: Window size too big\n", argv[0]);
    return 1;
  }

  if (windowsize == 0) {
    fprintf(stderr, "%s: Window size can not be 0\n", argv[0]);
    return 1;
  }

  totalcrcs = 0;
  crcs = NULL;
  do {
    if((reallocation = (crc_t *)realloc(crcs, sizeof(crc_t) * (totalcrcs + 1))) == NULL) {
      fprintf(stderr, "crcs realloc failed. Out of memory?\n");
      return 1;
    }
    crcs = reallocation;
    memset(&crcs[totalcrcs], 0, sizeof(crc_t));

    if (!iscrc(argv[optind])) {
      fprintf(stderr, "%s: %s does not look like an crc\n", argv[0], argv[optind]);
      return 1;
    }
    crcs[totalcrcs].crc = (unsigned int)strtoul(argv[optind++], 0, 16);

    if ((optind < argc) && ismd5(argv[optind])) {
      crcs[totalcrcs].checkmd5 = 1;
      for (i = 0; i < MD5_DIGEST_LENGTH * 2; i += 2) {
        md5byte[0] = argv[optind][i];
        md5byte[1] = argv[optind][i + 1];
        md5byte[2] = 0;
        crcs[totalcrcs].md5hash[i / 2] = (unsigned char)strtol(md5byte, 0, 16);
      }
      optind++;
    }

    totalcrcs++;
  } while (optind < argc);

  if (seedfile) {
    seedcrc = getcrc(seedfile);
    printf("seedcrc: %08x\n", seedcrc);
    fflush(stdout);
  }

  findcrcs();

  free(crcs);
  close(fd);
  return 0;
}

int isuint(char *string) {
  if (strlen(string) == 0) return 0;
  if (strspn(string, "0123456789") != strlen(string)) return 0;
  if (string[0] == '0' && strlen(string) != 1) return 0;
  return 1;
}

int iscrc(char *string) {
  if (strlen(string) != 8) return 0;
  if (strspn(string, "0123456789abcdefABCDEF") != strlen(string)) return 0;
  return 1;
}

int ismd5(char *string) {
  if (strlen(string) != MD5_DIGEST_LENGTH * 2) return 0;
  if (strspn(string, "0123456789abcdefABCDEF") != strlen(string)) return 0;
  return 1;
}

unsigned int getcrc(char *file) {
  int fd, bytes;
  crcutil_interface::CRC *crcutil;
  unsigned long long crc;
  unsigned char buffer[BUFFERSIZE];

  crcutil = crcutil_interface::CRC::Create(POLY, 0, 32, true, 0, 0, 0, 0, NULL);
  fd = open(file, O_RDONLY | O_BINARY);

  crc = 0;
  while ((bytes = read(fd, &buffer, BUFFERSIZE)) != 0) {
    crcutil->Compute(&buffer, bytes, &crc);
  }

  close(fd);
  crcutil->Delete();

  return (unsigned int)crc;
}

void usage() {
  fprintf(stderr, "\n");
  fprintf(stderr, "Usage: findcrcs [OPTION]... [--] <FILE> <WINDOWSIZE> <CRC> [MD5] [CRC [MD5]...]\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Find the offset of CRCs in FILE with a window size of WINDOWSIZE.\n");
  fprintf(stderr, "Outputs the crc, offset and md5 of a found segment.\n");
  fprintf(stderr, "If an MD5 is given, it will only output or extract on a matching md5 hash.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "  -e              extract the found segments with the md5 hash as filename\n");
  fprintf(stderr, "  -f EXTRACTFILE  use EXTRACTFILE as file to extract to\n");
  fprintf(stderr, "                  implies -e and -q\n");
  fprintf(stderr, "  -p PADDING      use PADDING amount of zero bytes around the input file\n");
  fprintf(stderr, "                  this can result in a negative offset in the results\n");
  fprintf(stderr, "                  if used with -s only an end padding will be added\n");
  fprintf(stderr, "  -q              quit processing after finding a match and optionally\n");
  fprintf(stderr, "                  extracting that match\n");
  fprintf(stderr, "  -s SEEDFILE     get an initial crc from SEEDFILE\n");
  fprintf(stderr, "                  if used with -e, the SEEDFILE will be joined with the found\n");
  fprintf(stderr, "                  segment\n");
  fprintf(stderr, "\n");
}

void findcrcs() {
  unsigned int i1;
  int i2, fd1, fd2, readbytes;
  crcutil_interface::CRC *crcutil;
  unsigned long long crc;
  unsigned char buffer1[BUFFERSIZE], buffer2[BUFFERSIZE];

  crcutil = crcutil_interface::CRC::Create(POLY, 0, 32, true, 0, 0, windowsize, 0, NULL);

  fd1 = open(file, O_RDONLY | O_BINARY);
  fd2 = open(file, O_RDONLY | O_BINARY);

  crc = 0;
  for (i1 = 0; i1 < windowsize / BUFFERSIZE; i1++) {
    read(fd1, &buffer1, BUFFERSIZE);
    crcutil->Compute(&buffer1, BUFFERSIZE, &crc);
  }
  if ((windowsize % BUFFERSIZE) != 0) {
    read(fd1, &buffer1, (windowsize % BUFFERSIZE));
    crcutil->Compute(&buffer1, (windowsize % BUFFERSIZE), &crc);
  }

  /* --- force check from offset 0 when not single --- */
  if (checkcrcs((unsigned int)crc, 0)) {
    if (single) {
      close(fd2);
      close(fd1);
      crcutil->Delete();
      return;
    }
  }

  /* Continue scanning the rest of the file starting from offset 1 */
  for (i1 = 0; i1 < ((filesize - windowsize) / BUFFERSIZE) + 1; i1++) {
    readbytes = read(fd1, &buffer1, BUFFERSIZE);
    read(fd2, &buffer2, BUFFERSIZE);
    for (i2 = 0; i2 < readbytes; i2++) {
      crcutil->Roll(buffer2[i2], buffer1[i2], &crc, NULL);
      if (checkcrcs((unsigned int)crc, (i1 * BUFFERSIZE) + i2 + 1)) {
        if (single) {
          close(fd2);
          close(fd1);
          crcutil->Delete();
          return;
        }
      }
    }
  }

  close(fd2);
  close(fd1);
  crcutil->Delete();
}

int checkcrcs(unsigned int crc, int offset) {
  int i;
  for (i = 0; i < totalcrcs; i++) {
    if (crc == crcs[i].crc) {
      foundcrc(i, offset);
      return 1;
    }
  }
  return 0;
}

void foundcrc(int index, int offset) {
  char *md5string;
  unsigned char *md5hash;

  md5hash = md5(offset);
  md5string = md5hash2string(md5hash);

  if (!crcs[index].checkmd5 || (memcmp(crcs[index].md5hash, md5hash, MD5_DIGEST_LENGTH) == 0)) {
    printf("%d  %08x  %s\n", offset, crcs[index].crc, md5string);
    fflush(stdout);
    if (extract) {
      printf("Extracting...");
      fflush(stdout);
      extractwindow(offset, md5string);
      printf(" Done\n");
      fflush(stdout);
    }
  }

  free(md5string);
  free(md5hash);
}

unsigned char *md5(int offset) {
  int seedfd, bytes;
  MD5_CTX ctx;
  unsigned char *md5hash;
  unsigned char buffer[BUFFERSIZE];

  if((md5hash = (unsigned char *)calloc(MD5_DIGEST_LENGTH, sizeof(unsigned char))) == NULL) {
    fprintf(stderr, "MD5 calloc failed. Out of memory?\n");
    exit(1);
  }

  MD5_Init(&ctx);

  if (seedfile) {
    seedfd = open(seedfile, O_RDONLY | O_BINARY);
    while ((bytes = read(seedfd, &buffer, BUFFERSIZE)) != 0) {
      MD5_Update(&ctx, &buffer, bytes);
    }
    close(seedfd);
  }

  extract_init(offset);
  while ((bytes = extract_read(&buffer, BUFFERSIZE)) != 0) {
    MD5_Update(&ctx, &buffer, bytes);
  }

  MD5_Final(md5hash, &ctx);
  return md5hash;
}

char *md5hash2string(unsigned char *md5hash) {
  int i;
  char *md5string;
  
  if((md5string = (char *)calloc(((MD5_DIGEST_LENGTH * 2) + 1), sizeof(char))) == NULL) {
    fprintf(stderr, "MD5 string calloc failed. Out of memory?\n");
    exit(1);
  }

  for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
    sprintf(md5string + (i * 2), "%02x", md5hash[i]);
  }

  return md5string;
}

void extractwindow(int offset, char *md5string) {
  int extractfd, seedfd, bytes;
  char *file;
  unsigned char buffer[BUFFERSIZE];

  if (extractfile == NULL) {
    if((file = (char *)malloc((MD5_DIGEST_LENGTH * 2) + 5)) == NULL) {
      fprintf(stderr, "extractfile malloc failed. Out of memory?\n");
      exit(1);
    }
    sprintf(file, "%s.bin", md5string);
  } else {
    file = extractfile;
  }

  if ((extractfd = open(file, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR)) == -1) {
    perror(file);
    exit(1);
  }

  if (seedfile) {
    seedfd = open(seedfile, O_RDONLY | O_BINARY);
    while ((bytes = read(seedfd, &buffer, BUFFERSIZE)) != 0) {
      write(extractfd, &buffer, bytes);
    }
    close(seedfd);
  }

  extract_init(offset);
  while ((bytes = extract_read(&buffer, BUFFERSIZE)) != 0) {
    write(extractfd, &buffer, bytes);
  }

  close(extractfd);
  if (extractfile == NULL) free(file);
}

int extract_offset;
unsigned int extract_bytesleft = 0;

void extract_init(int offset) {
  extract_offset = offset;
  extract_bytesleft = windowsize;
}

int extract_read(void *buffer, unsigned int size) {
  unsigned int bytesread, returnvalue;
  if (size == 0 || extract_bytesleft == 0) return 0;
  if (size > extract_bytesleft) {
    size = extract_bytesleft;
  }
  returnvalue = 0;
  if (extract_offset < 0) {
    if ((unsigned int)(extract_offset * -1) >= size) {
      memset(buffer, 0, size);
      extract_offset += size;
      extract_bytesleft -= size;
      return size;
    } else {
      returnvalue = extract_offset * -1;
      memset(buffer, 0, returnvalue);
      buffer = (char *)buffer + returnvalue;
      size -= returnvalue;
      extract_bytesleft -= returnvalue;
      extract_offset = 0;
    }
  }
  lseek(fd, extract_offset, SEEK_SET);
  bytesread = read(fd, buffer, size);
  extract_bytesleft -= bytesread;
  extract_offset += bytesread;
  returnvalue += bytesread;
  if (bytesread < size) {
    size -= bytesread;
    buffer = (char *)buffer + bytesread;
    memset(buffer, 0, size);
    extract_bytesleft -= size;
    extract_offset += size;
    returnvalue += size;
  }
  return returnvalue;
}

