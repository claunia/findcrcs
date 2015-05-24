/*
  Copyright 2013, V.

  This file is part of findcrcs.

  findcrcs is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  findcrcs is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with findcrcs.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
  findcrcs is using crcutil-1.0 for providing fast crc calculations
  crcutil is made by Andrew Kadatch and Bob Jenkins and can be found on http://code.google.com/p/crcutil/
  Do not contact them for support on findcrcs

  Also, findcrcs makes use of the MD5 implementation of Alexander Peslyak.
  This is found at http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5
  A small casting patch was made to support g++.
  This patch is released under the same license as the original md5.c file.
*/

// Usage: findcrcs <file> <size of window> <crc> [more crcs...]
// not yet idiotproof
// code comments also not included (yet, if ever)

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "md5.h"
#include "interface.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define BUFFERSIZE 65536
#define MD5_DIGEST_LENGTH 16

void checkcrcs(unsigned int crc, unsigned int crcs[], int totalcrcs, int fd, int offset, int windowsize);

int main(int argc, char *argv[]) {
  int i1, i2, fd1, fd2, fd3, filesize, windowsize, readbytes;
  char *filename;
  crcutil_interface::CRC *crc;
  unsigned long long returnvalue;
  unsigned char buffer1[BUFFERSIZE], buffer2[BUFFERSIZE];
  struct stat stats;
  unsigned int crcs[argc - 3];

  if (argc < 4) {
    fprintf(stderr, "usage: findcrcs <file> <size of window> <crc> [more crcs...]\n");
    return 1;
  }

  filename = argv[1];
  if (stat(filename, &stats) == -1) {
    perror("findcrcs");
    return 1;
  }
  filesize = stats.st_size;

  windowsize = atoi(argv[2]);
  if (windowsize > filesize) {
    fprintf(stderr, "findcrcs: window size too big\n");
    return 1;
  }

  for (i1 = 0; i1 < argc - 3; i1++) {
    crcs[i1] = (unsigned int)strtoul(argv[i1 + 3], 0, 16);
  }

  crc = crcutil_interface::CRC::Create(0xedb88320, 0, 32, true, 0, 0, windowsize, 0, NULL);

  fd1 = open(filename, O_RDONLY | O_BINARY);
  fd2 = open(filename, O_RDONLY | O_BINARY);
  fd3 = open(filename, O_RDONLY | O_BINARY);

  returnvalue = 0;
  for (i1 = 0; i1 < windowsize / BUFFERSIZE; i1++) {
    read(fd1, &buffer1, BUFFERSIZE);
    crc->Compute(&buffer1, BUFFERSIZE, &returnvalue);
  }
  if ((windowsize % BUFFERSIZE) != 0) {
    read(fd1, &buffer1, (windowsize % BUFFERSIZE));
    crc->Compute(&buffer1, (windowsize % BUFFERSIZE), &returnvalue);
  }
  checkcrcs((unsigned int)returnvalue, crcs, argc - 3, fd3, 0, windowsize);

  for (i1 = 0; i1 < ((filesize - windowsize) / BUFFERSIZE) + 1; i1++) {
    readbytes = read(fd1, &buffer1, BUFFERSIZE);
    read(fd2, &buffer2, BUFFERSIZE);
    for (i2 = 0; i2 < readbytes; i2++) {
      crc->Roll(buffer2[i2], buffer1[i2], &returnvalue, NULL);
      checkcrcs((unsigned int)returnvalue, crcs, argc - 3, fd3, (i1 * BUFFERSIZE) + i2 + 1, windowsize);
    }
  }

  close(fd3);
  close(fd2);
  close(fd1);
  crc->Delete();
  return 0;
}

void checkcrcs(unsigned int crc, unsigned int crcs[], int totalcrcs, int fd, int offset, int windowsize) {
  int i1, i2;
  unsigned int buffer[BUFFERSIZE];
  unsigned char md5[MD5_DIGEST_LENGTH];
  MD5_CTX ctx;

  for (i1 = 0; i1 < totalcrcs; i1++) {
    if (crc == crcs[i1]) {
      lseek(fd, offset, SEEK_SET);
      MD5_Init(&ctx);

      for (i2 = 0; i2 < windowsize / BUFFERSIZE; i2++) {
        read(fd, &buffer, BUFFERSIZE);
        MD5_Update(&ctx, &buffer, BUFFERSIZE);
      }
      if ((windowsize % BUFFERSIZE) != 0) {
        read(fd, &buffer, (windowsize % BUFFERSIZE));
        MD5_Update(&ctx, &buffer, (windowsize % BUFFERSIZE));
      }

      MD5_Final(md5, &ctx);
      printf("%d  %08x  ", offset, crc);
      for (i2 = 0; i2 < MD5_DIGEST_LENGTH; i2++) {
        printf("%02x", md5[i2]);
      }
      printf("\n");
      return;
    }
  }
}
