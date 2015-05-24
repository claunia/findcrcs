What:
 This is a not yet idiotproof version of findcrcs.
 It is to be used for finding a block of data which matches a specific crc.

How:
 findcrcs <file> <size of window> <crc> [more crcs...]

 File is a big file which should or may contain the searched for data.
 Size of window is the size of the block of data to find.
 Crc is the crc to find in the file (may be more then 1, but all will be matched on the window size).

 If a match is found it will print out an md5sum of the matched block for further inspection.
 For best results, add some (1MB or so) zero bytes padding around the file first.
 In a future version, this might be a selectable option of this program.

Why:
 Useful for finding audio offsets in disk images together with the redump.org database.

Warning:
 This software is not yet idiotproof!
 - It does not check arguments for validity yet (especially size of window and crc's.)
 - No paddiong option yet.
   if matching audiodata, you should pad the combined audiotracks with zero bytes at the start and end.

Compiling:
 Use "make" on any linux/unix/bsd console nearby, or if you must, an msys or cygwin environment.
 You need to use a relatively recent gcc (4.5.0+ ish I guess).
 On windows, if you have a 64bit MinGW, you can use "make 64=1" to build a (much faster) 64bit version.

 This software uses crcutil-1.0 for providing fast crc calculations.
 crcutil is made by Andrew Kadatch and Bob Jenkins and can be found on http://code.google.com/p/crcutil/
 Do not contact them for support on findcrcs.
 The Makefile will try to pull in version 1.0 through wget if it is not supplied yet.

 Also, this program makes use of the MD5 implementation of Alexander Peslyak.
 This is found at http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5
 A small casting patch was made to support g++, this small patch is released under the same license as the original md5.c file.

Contact:
 At the moment, see the redump.org forum thread where you got this.

-V.
