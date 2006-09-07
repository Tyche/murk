/***************************************************************************
 *  Original Diku Mud copyright (C) 1990, 1991 by Sebastian Hammer,        *
 *  Michael Seifert, Hans Henrik St{rfeldt, Tom Madsen, and Katja Nyboe.   *
 *                                                                         *
 *  Merc Diku Mud improvments copyright (C) 1992, 1993 by Michael          *
 *  Chastain, Michael Quan, and Mitchell Tse.                              *
 *                                                                         *
 *  In order to use any part of this Merc Diku Mud, you must comply with   *
 *  both the original Diku license in 'license.doc' as well the Merc       *
 *  license in 'license.txt'.  In particular, you may not remove either of *
 *  these copyright notices.                                               *
 *                                                                         *
 *  Much time and thought has gone into this software and you are          *
 *  benefitting.  We hope that you share your changes too.  What goes      *
 *  around, comes around.                                                  *
 ***************************************************************************/

/*
 MurkMUD++ - A Windows compatible, C++ compatible Merc 2.2 Mud.

 \author Jon A. Lambert
 \date 08/30/2006
 \version 1.2
 \remarks
  This source code copyright (C) 2005, 2006 by Jon A. Lambert
  All rights reserved.

  The crypt code credits and license is included inlined below.

  MurkMUD++ Public License
  Copyright(c) 2005, 2006 Jon A. Lambert. All rights reserved.

  Permission is hereby granted, free of charge, to any person obtaining a
  copy of this software and associated documentation files, the rights to
  use, copy, modify, create derivative works, merge, publish, distribute,
  sublicense, and/or sell copies of this software, and to permit persons
  to whom the software is furnished to do so, subject to the following
  conditions:

  1. Redistribution in source code must retain the copyright information
  and attributions in the original source code, the above copyright notice,
  this list of conditions, the CONTRIBUTORS file and the following
  disclaimer.

  2. Redistribution in binary form must reproduce the above copyright
  notice, this list of conditions, and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The rights granted to you under this license automatically terminate
  should you attempt to assert any patent claims against the licensor or
  contributors, which in any way restrict the ability of any party to use
  this software or portions thereof in any form under the terms of this
  license.

  4. You must also comply with both the original Diku license in
  'license.diku' as well the Merc license in 'license.merc'.

  Disclaimer:
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

/*-----------------------------------------------------------------------*/
/* OS DEPENDENT INCLUDES AND DEFINITIONS                                 */
/*-----------------------------------------------------------------------*/
#include <cstdlib>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include "sqlite3/sqlite3.h"

#include <cstdarg>
#include <string>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <list>
#include <map>
//#include "boost/format.hpp"

// replacement or substitute for itoa
std::string itoa(int value, int base) {
  std::string buf;

  if (base < 2 || base > 16)
    return buf;
  int quotient = value;
  do {
    buf += "0123456789abcdef"[ std::abs( quotient % base ) ];
    quotient /= base;
  } while ( quotient );

  if ( value < 0 && base == 10)
    buf += '-';
  std::reverse( buf.begin(), buf.end() );
  return buf;
}

/*-----------------------------------------------------------------------*/
/* WINDOWS DEFINITIONS SECTION                                           */
/*-----------------------------------------------------------------------*/
#ifdef WIN32                    /* Windows portability */
#if defined _MSC_VER
#define NOMINMAX
#endif
#define FD_SETSIZE 1024
#include <winsock2.h>

#define GETERROR     WSAGetLastError()
#define WIN32STARTUP \
    { \
      WSADATA wsaData; \
      int err = WSAStartup(0x202,&wsaData); \
      if (err) \
        std::cerr << "Error(WSAStartup):" << err << std::endl; \
    }
#define WIN32CLEANUP WSACleanup();

#define EWOULDBLOCK       WSAEWOULDBLOCK

#define OS_RAND rand
#define OS_SRAND srand
#if defined _MSC_VER
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#endif

/*
  Not implemented in windows, although all the structural support is
  found in winsock.h

 \author Jon A. Lambert

 \remarks
  This version has millisecond granularity.
 */
void gettimeofday (struct timeval *tp, struct timezone *tzp)
{
  tp->tv_sec = time (NULL);
  tp->tv_usec = (GetTickCount () % 1000) * 1000;
}

/*-------------------------------------------------------------------*/
/*
 Crypt is from Andy Tanenbaum's book "Computer Networks", rewritten in C.

 \author Andy Tanenbaum

 \remarks
  This does generate the exact same password string as glibc and newlib
  so your files containg passwords are portable.  I am not sure about
  FreeBSD.
 */
/*
  Copyright (c) 1987,1997, Prentice Hall
  All rights reserved.

  Redistribution and use of the MINIX operating system in source and
  binary forms, with or without modification, are permitted provided
  that the following conditions are met:

     * Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.

     * Redistributions in binary form must reproduce the above
       copyright notice, this list of conditions and the following
       disclaimer in the documentation and/or other materials provided
       with the distribution.

     * Neither the name of Prentice Hall nor the names of the software
       authors or contributors may be used to endorse or promote
       products derived from this software without specific prior
       written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS, AUTHORS, AND
  CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
  IN NO EVENT SHALL PRENTICE HALL OR ANY AUTHORS OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
  OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

struct block {
  unsigned char b_data[64];
};

struct ordering {
  unsigned char o_data[64];
};

static struct block key;

static struct ordering InitialTr = {
 {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7}
};

static struct ordering FinalTr = {
 {40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
  38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25}
};

static struct ordering swap = {
 {33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
  49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
  17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
};

static struct ordering KeyTr1 = {
 {57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
  10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
  14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4}
};

static struct ordering KeyTr2 = {
 {14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
  23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32}
};

static struct ordering etr = {
 {32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
  8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
  24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1}
};

static struct ordering ptr = {
 {16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
  2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25}
};

static unsigned char s_boxes[8][64] = {
  {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
      0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
      4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
      15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    },

  {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
      3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
      0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
      13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    },

  {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
      13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
      13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
      1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    },

  {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
      13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
      10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
      3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    },

  {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
      14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
      4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
      11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    },

  {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
      10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
      9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
      4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    },

  {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
      13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
      1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
      6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    },

  {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
      1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
      7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
      2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    },
};

static int rots[] = {
  1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
};

static void transpose (struct block *data, struct ordering *t, int n)
{
  struct block x;

  x = *data;

  while (n-- > 0) {
    data->b_data[n] = x.b_data[t->o_data[n] - 1];
  }
}

static void rotate (struct block *key)
{
  register unsigned char *p = key->b_data;
  register unsigned char *ep = &(key->b_data[55]);
  int data0 = key->b_data[0], data28 = key->b_data[28];

  while (p++ < ep)
    *(p - 1) = *p;
  key->b_data[27] = (char) data0;
  key->b_data[55] = (char) data28;
}

static struct ordering *EP = &etr;

static void f (int i, struct block *key, struct block *a, struct block *x)
{
  struct block e, ikey, y;
  int k;
  register unsigned char *p, *q, *r;

  e = *a;
  transpose (&e, EP, 48);
  for (k = rots[i]; k; k--)
    rotate (key);
  ikey = *key;
  transpose (&ikey, &KeyTr2, 48);
  p = &(y.b_data[48]);
  q = &(e.b_data[48]);
  r = &(ikey.b_data[48]);
  while (p > y.b_data) {
    *--p = *--q ^ *--r;
  }
  q = x->b_data;
  for (k = 0; k < 8; k++) {
    register int xb, r;

    r = *p++ << 5;
    r += *p++ << 3;
    r += *p++ << 2;
    r += *p++ << 1;
    r += *p++;
    r += *p++ << 4;

    xb = s_boxes[k][r];

    *q++ = (char) (xb >> 3) & 1;
    *q++ = (char) (xb >> 2) & 1;
    *q++ = (char) (xb >> 1) & 1;
    *q++ = (char) (xb & 1);
  }
  transpose (x, &ptr, 32);
}

void definekey (char *k)
{

  key = *((struct block *) k);
  transpose (&key, &KeyTr1, 56);
}

void encrypt (char *blck, int edflag)
{
  register struct block *p = (struct block *) blck;
  register int i;

  transpose (p, &InitialTr, 64);
  for (i = 15; i >= 0; i--) {
    int j = edflag ? i : 15 - i;
    register int k;
    struct block b, x;

    b = *p;
    for (k = 31; k >= 0; k--) {
      p->b_data[k] = b.b_data[k + 32];
    }
    f (j, &key, p, &x);
    for (k = 31; k >= 0; k--) {
      p->b_data[k + 32] = b.b_data[k] ^ x.b_data[k];
    }
  }
  transpose (p, &swap, 64);
  transpose (p, &FinalTr, 64);
}

char *crypt (char *pw, const char *salt)
{

  char pwb[66];
  static char result[16];
  register char *p = pwb;
  struct ordering new_etr;
  register int i;

  while (*pw && p < &pwb[64]) {
    register int j = 7;

    while (j--) {
      *p++ = (*pw >> j) & 01;
    }
    pw++;
    *p++ = 0;
  }
  while (p < &pwb[64])
    *p++ = 0;

  definekey (p = pwb);

  while (p < &pwb[66])
    *p++ = 0;

  new_etr = etr;
  EP = &new_etr;
  for (i = 0; i < 2; i++) {
    register char c = *salt++;
    register int j;

    result[i] = c;
    if (c > 'Z')
      c -= 6 + 7 + '.';         /* c was a lower case letter */
    else if (c > '9')
      c -= 7 + '.';             /* c was upper case letter */
    else
      c -= '.';                 /* c was digit, '.' or '/'. */
    /* now, 0 <= c <= 63 */
    for (j = 0; j < 6; j++) {
      if ((c >> j) & 01) {
        int t = 6 * i + j;
        int temp = new_etr.o_data[t];
        new_etr.o_data[t] = new_etr.o_data[t + 24];
        new_etr.o_data[t + 24] = (char) temp;
      }
    }
  }

  if (result[1] == 0)
    result[1] = result[0];

  for (i = 0; i < 25; i++)
    encrypt (pwb, 0);
  EP = &etr;

  p = pwb;
  pw = result + 2;
  while (p < &pwb[66]) {
    register int c = 0;
    register int j = 6;

    while (j--) {
      c <<= 1;
      c |= *p++;
    }
    c += '.';                   /* becomes >= '.' */
    if (c > '9')
      c += 7;                   /* not in [./0-9], becomes upper */
    if (c > 'Z')
      c += 6;                   /* not in [A-Z], becomes lower */
    *pw++ = (char) c;
  }
  *pw = 0;
  return result;
}

/*-----------------------------------------------------------------------*/
/* UNIX DEFINITION SECTION                                               */
/*-----------------------------------------------------------------------*/
#else /* Unix portability - some a consequence of above */

#include <sys/time.h>           /* Redhat and BSD need this */
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#ifndef __FreeBSD__
#include <crypt.h>
#endif

#define GETERROR  errno
#define INVALID_SOCKET -1       /* 0 on Windows */
#define SOCKET_ERROR -1
#define SOCKET int
#define WIN32STARTUP
#define WIN32CLEANUP
#define OS_RAND rand
#define OS_SRAND srand
#define closesocket(X) close(X)
#endif

/* stuff for Telnet */
#define IAC 255     /* interpret as command: */
#define WONT    252     /* I won't use option */
#define WILL    251     /* I will use option */
#define GA  249     /* you may reverse the line */
#define TELOPT_ECHO 1   /* echo */


/*-----------------------------------------------------------------------*/
/* MurkMUD++ BEGINS HERE                                                 */
/*-----------------------------------------------------------------------*/

typedef short int sh_int;

/*
 * Structure types.
 */
class Affect;
class Area;
class Ban;
class Character;
class Descriptor;
class Exit;
class ExtraDescription;
class Help;
class MobPrototype;
class Note;
class Object;
class ObjectPrototype;
class PCData;
class Reset;
class Room;
class Shop;
class MobProgam;        /* MOBprogram */
class MobProgramActList;        /* MOBprogram */


/*
 * Function types.
 */
typedef bool SPEC_FUN (Character * ch);

/*
 * String and memory management parameters.
 */
#define MAX_STRING_LENGTH    4096
#define MAX_INPUT_LENGTH      160

/*
 * Game parameters.
 * Increase the max'es if you add more of something.
 * Adjust the pulse numbers to suit yourself.
 */
#define MAX_SKILL          90
#define MAX_LEVEL          40
#define LEVEL_HERO         (MAX_LEVEL - 4)
#define LEVEL_IMMORTAL         (MAX_LEVEL - 3)

#define PULSE_PER_SECOND        4
#define PULSE_VIOLENCE        ( 3 * PULSE_PER_SECOND)
#define PULSE_MOBILE          ( 4 * PULSE_PER_SECOND)
#define PULSE_TICK        (30 * PULSE_PER_SECOND)
#define PULSE_AREA        (60 * PULSE_PER_SECOND)

/*
 * Time and weather stuff.
 */
enum {SUN_DARK, SUN_RISE, SUN_LIGHT, SUN_SET };
enum {SKY_CLOUDLESS, SKY_CLOUDY, SKY_RAINING, SKY_LIGHTNING};

/*
 * Connected state for a channel.
 */
enum {CON_PLAYING, CON_GET_NAME, CON_GET_OLD_PASSWORD, CON_CONFIRM_NEW_NAME,
      CON_GET_NEW_PASSWORD, CON_CONFIRM_NEW_PASSWORD, CON_GET_NEW_SEX,
      CON_GET_NEW_CLASS, CON_READ_MOTD};

/*
 * TO types for actflags.
 */
enum {TO_ROOM, TO_NOTVICT, TO_VICT, TO_CHAR };

/***************************************************************************
 *                                                                         *
 *                   VALUES OF INTEREST TO AREA BUILDERS                   *
 *                   (Start of section ... start here)                     *
 *                                                                         *
 ***************************************************************************/
/*
 * Well known mob virtual numbers.
 * Defined in #MOBILES.
 */
#define MOB_VNUM_CITYGUARD     3060
#define MOB_VNUM_VAMPIRE       3404

/*
 * ACT bits for mobs.
 * Used in #MOBILES.
 */
#define ACT_IS_NPC      1 << 0  /* Auto set for mobs    */
#define ACT_SENTINEL    1 << 1  /* Stays in one room    */
#define ACT_SCAVENGER   1 << 2  /* Picks up objects */
#define ACT_AGGRESSIVE  1 << 5  /* Attacks PC's     */
#define ACT_STAY_AREA   1 << 6  /* Won't leave area */
#define ACT_WIMPY       1 << 7 /* Flees when hurt  */
#define ACT_PET         1 << 8 /* Auto set for pets    */
#define ACT_TRAIN       1 << 9 /* Can train PC's   */
#define ACT_PRACTICE    1 << 10     /* Can practice PC's    */

/*
 * Bits for 'affected_by'.
 * Used in #MOBILES.
 */
#define AFF_BLIND          1 << 0
#define AFF_INVISIBLE      1 << 1
#define AFF_DETECT_EVIL    1 << 2
#define AFF_DETECT_INVIS   1 << 3
#define AFF_DETECT_MAGIC   1 << 4
#define AFF_DETECT_HIDDEN  1 << 5

#define AFF_SANCTUARY      1 << 7
#define AFF_FAERIE_FIRE    1 << 8
#define AFF_INFRARED       1 << 9
#define AFF_CURSE          1 << 10

#define AFF_POISON         1 << 12
#define AFF_PROTECT        1 << 13

#define AFF_SNEAK          1 << 15
#define AFF_HIDE           1 << 16
#define AFF_SLEEP          1 << 17
#define AFF_CHARM          1 << 18
#define AFF_FLYING         1 << 19
#define AFF_PASS_DOOR      1 << 20

/*
 * Sex.
 * Used in #MOBILES.
 */
enum {SEX_NEUTRAL, SEX_MALE, SEX_FEMALE};

/*
 * Well known object virtual numbers.
 * Defined in #OBJECTS.
 */
#define OBJ_VNUM_MONEY_ONE        2
#define OBJ_VNUM_MONEY_SOME       3

#define OBJ_VNUM_CORPSE_NPC      10
#define OBJ_VNUM_CORPSE_PC       11
#define OBJ_VNUM_SEVERED_HEAD    12
#define OBJ_VNUM_TORN_HEART      13
#define OBJ_VNUM_SLICED_ARM      14
#define OBJ_VNUM_SLICED_LEG      15
#define OBJ_VNUM_FINAL_TURD      16

#define OBJ_VNUM_MUSHROOM        20
#define OBJ_VNUM_LIGHT_BALL      21
#define OBJ_VNUM_SPRING          22

#define OBJ_VNUM_SCHOOL_MACE       3700
#define OBJ_VNUM_SCHOOL_DAGGER     3701
#define OBJ_VNUM_SCHOOL_SWORD      3702
#define OBJ_VNUM_SCHOOL_VEST       3703
#define OBJ_VNUM_SCHOOL_SHIELD     3704
#define OBJ_VNUM_SCHOOL_BANNER     3716

/*
 * Item types.
 * Used in #OBJECTS.
 */
#define ITEM_LIGHT            1
#define ITEM_SCROLL           2
#define ITEM_WAND             3
#define ITEM_STAFF            4
#define ITEM_WEAPON           5
#define ITEM_TREASURE         8
#define ITEM_ARMOR            9
#define ITEM_POTION          10
#define ITEM_FURNITURE       12
#define ITEM_TRASH           13
#define ITEM_CONTAINER       15
#define ITEM_DRINK_CON       17
#define ITEM_KEY             18
#define ITEM_FOOD            19
#define ITEM_MONEY           20
#define ITEM_BOAT            22
#define ITEM_CORPSE_NPC      23
#define ITEM_CORPSE_PC       24
#define ITEM_FOUNTAIN        25
#define ITEM_PILL            26

/*
 * Extra flags.
 * Used in #OBJECTS.
 */
#define ITEM_GLOW          1 << 0
#define ITEM_HUM           1 << 1
#define ITEM_DARK          1 << 2
#define ITEM_LOCK          1 << 3
#define ITEM_EVIL          1 << 4
#define ITEM_INVIS         1 << 5
#define ITEM_MAGIC         1 << 6
#define ITEM_NODROP        1 << 7
#define ITEM_BLESS         1 << 8
#define ITEM_ANTI_GOOD     1 << 9
#define ITEM_ANTI_EVIL     1 << 10
#define ITEM_ANTI_NEUTRAL  1 << 11
#define ITEM_NOREMOVE      1 << 12
#define ITEM_INVENTORY     1 << 13

/*
 * Wear flags.
 * Used in #OBJECTS.
 */
#define ITEM_TAKE          1 << 0
#define ITEM_WEAR_FINGER   1 << 1
#define ITEM_WEAR_NECK     1 << 2
#define ITEM_WEAR_BODY     1 << 3
#define ITEM_WEAR_HEAD     1 << 4
#define ITEM_WEAR_LEGS     1 << 5
#define ITEM_WEAR_FEET     1 << 6
#define ITEM_WEAR_HANDS    1 << 7
#define ITEM_WEAR_ARMS     1 << 8
#define ITEM_WEAR_SHIELD   1 << 9
#define ITEM_WEAR_ABOUT    1 << 10
#define ITEM_WEAR_WAIST    1 << 11
#define ITEM_WEAR_WRIST    1 << 12
#define ITEM_WIELD         1 << 13
#define ITEM_HOLD          1 << 14

/*
 * Apply types (for affects).
 * Used in #OBJECTS.
 */
enum {APPLY_NONE, APPLY_STR, APPLY_DEX, APPLY_INT, APPLY_WIS, APPLY_CON,
      APPLY_SEX, APPLY_CLASS, APPLY_LEVEL, APPLY_AGE, APPLY_HEIGHT,
      APPLY_WEIGHT, APPLY_MANA, APPLY_HIT, APPLY_MOVE, APPLY_GOLD, APPLY_EXP,
      APPLY_AC, APPLY_HITROLL, APPLY_DAMROLL, APPLY_SAVING_PARA,
      APPLY_SAVING_ROD, APPLY_SAVING_PETRI, APPLY_SAVING_BREATH,
      APPLY_SAVING_SPELL};

/*
 * Values for containers (value[1]).
 * Used in #OBJECTS.
 */
#define CONT_CLOSEABLE   1 << 0
#define CONT_PICKPROOF   1 << 1
#define CONT_CLOSED      1 << 2
#define CONT_LOCKED      1 << 3

/*
 * Well known room virtual numbers.
 * Defined in #ROOMS.
 */
#define ROOM_VNUM_LIMBO           2
#define ROOM_VNUM_CHAT         1200
#define ROOM_VNUM_TEMPLE       3001
#define ROOM_VNUM_ALTAR        3054
#define ROOM_VNUM_SCHOOL       3700

/*
 * Room flags.
 * Used in #ROOMS.
 */
#define ROOM_DARK      1 << 0
#define ROOM_NO_MOB    1 << 2
#define ROOM_INDOORS   1 << 3
#define ROOM_PRIVATE   1 << 9
#define ROOM_SAFE      1 << 10
#define ROOM_SOLITARY  1 << 11
#define ROOM_PET_SHOP  1 << 12
#define ROOM_NO_RECALL 1 << 13

/*
 * Directions.
 * Used in #ROOMS.
 */
enum {DIR_NORTH, DIR_EAST, DIR_SOUTH, DIR_WEST, DIR_UP, DIR_DOWN };

/*
 * Exit flags.
 * Used in #ROOMS.
 */
#define EX_ISDOOR     1 << 0
#define EX_CLOSED     1 << 1
#define EX_LOCKED     1 << 2
#define EX_PICKPROOF  1 << 5

/*
 * Sector types.
 * Used in #ROOMS.
 */
enum {SECT_INSIDE, SECT_CITY, SECT_FIELD, SECT_FOREST, SECT_HILLS,
      SECT_MOUNTAIN, SECT_WATER_SWIM, SECT_WATER_NOSWIM, SECT_UNUSED,
      SECT_AIR, SECT_DESERT, SECT_MAX};

/*
 * Equpiment wear locations.
 * Used in #RESETS.
 */
enum {WEAR_NONE=-1, WEAR_LIGHT=0, WEAR_FINGER_L, WEAR_FINGER_R,
      WEAR_NECK_1, WEAR_NECK_2, WEAR_BODY, WEAR_HEAD, WEAR_LEGS,
      WEAR_FEET, WEAR_HANDS, WEAR_ARMS, WEAR_SHIELD, WEAR_ABOUT,
      WEAR_WAIST, WEAR_WRIST_L, WEAR_WRIST_R, WEAR_WIELD,
      WEAR_HOLD, MAX_WEAR};

/***************************************************************************
 *                                                                         *
 *                   VALUES OF INTEREST TO AREA BUILDERS                   *
 *                   (End of this section ... stop here)                   *
 *                                                                         *
 ***************************************************************************/
/*
 * Conditions.
 */
enum {COND_DRUNK, COND_FULL, COND_THIRST};

/*
 * Positions.
 */
enum {POS_DEAD, POS_MORTAL, POS_INCAP, POS_STUNNED, POS_SLEEPING,
      POS_RESTING, POS_FIGHTING, POS_STANDING};

/*
 * ACT bits for players.
 */
#define PLR_IS_NPC      1 << 0 /* Don't EVER set.  */
#define PLR_BOUGHT_PET  1 << 1

#define PLR_AUTOEXIT    1 << 3
#define PLR_AUTOLOOT    1 << 4
#define PLR_AUTOSAC     1 << 5
#define PLR_BLANK       1 << 6
#define PLR_BRIEF       1 << 7
#define PLR_COMBINE     1 << 9
#define PLR_PROMPT      1 << 10
#define PLR_TELNET_GA   1 << 11
#define PLR_HOLYLIGHT   1 << 12
#define PLR_WIZINVIS    1 << 13

#define PLR_SILENCE     1 << 15
#define PLR_NO_EMOTE    1 << 16
#define PLR_NO_TELL     1 << 18
#define PLR_DENY        1 << 20
#define PLR_FREEZE      1 << 21
#define PLR_THIEF       1 << 22
#define PLR_KILLER      1 << 23

/*
 * Channel bits.
 */
#define CHANNEL_AUCTION    1 << 0
#define CHANNEL_CHAT       1 << 1
#define CHANNEL_HACKER     1 << 2
#define CHANNEL_IMMTALK    1 << 3
#define CHANNEL_MUSIC      1 << 4
#define CHANNEL_QUESTION   1 << 5
#define CHANNEL_SHOUT      1 << 6
#define CHANNEL_YELL       1 << 7

#define ERROR_PROG        -1
#define IN_FILE_PROG       0

#define ACT_PROG        1 << 0
#define SPEECH_PROG     1 << 1
#define RAND_PROG       1 << 2
#define FIGHT_PROG      1 << 3
#define DEATH_PROG      1 << 4
#define HITPRCNT_PROG   1 << 5
#define ENTRY_PROG      1 << 6
#define GREET_PROG      1 << 7
#define ALL_GREET_PROG  1 << 8
#define GIVE_PROG       1 << 9
#define BRIBE_PROG      1 << 10

/*
 * Liquids.
 */
#define LIQ_WATER    0
#define LIQ_MAX     16

#define MAX_TRADE    5
/*
 * Types of attacks.
 * Must be non-overlapping with spell/skill types,
 * but may be arbitrary beyond that.
 */
#define TYPE_UNDEFINED               -1
#define TYPE_HIT                     1000

/*
 *  Target types.
 */
enum {TAR_IGNORE, TAR_CHAR_OFFENSIVE,
  TAR_CHAR_DEFENSIVE, TAR_CHAR_SELF, TAR_OBJ_INV};

/*
 * Data files used by the server.
 *
 * AREA_LIST contains a list of areas to boot.
 * All files are read in completely at bootup.
 * Most output files (bug, idea, typo, shutdown) are append-only.
 */
#if defined WIN32
#define PLAYER_DIR  ".\\"    /* Player files                 */
#define MOB_DIR     ".\\"    /* MOBProg files                */
#else
#define PLAYER_DIR  "./"     /* Player files         */
#define MOB_DIR     "./"     /* MOBProg files                */
#endif

#define AREA_LIST   "area.lst"  /* List of areas        */

#define BUG_FILE    "bugs.txt"  /* For 'bug' and bug( )     */
#define IDEA_FILE   "ideas.txt" /* For 'idea'           */
#define TYPO_FILE   "typos.txt" /* For 'typo'           */
#define NOTE_FILE   "notes.txt" /* For 'notes'          */
#define SHUTDOWN_FILE   "shutdown.txt"  /* For 'shutdown'       */

/*
 * God Levels
 */
#define L_GOD       MAX_LEVEL
#define L_SUP       L_GOD - 1
#define L_DEI       L_SUP - 1
#define L_ANG       L_DEI - 1
#define L_HER       L_ANG - 1

enum {CLASS_MAGE, CLASS_CLERIC, CLASS_THIEF, CLASS_WARRIOR, CLASS_MAX};

/*
 * Utility macros.
 */
#define URANGE(a, b, c)     ((b) < (a) ? (a) : ((b) > (c) ? (c) : (b)))
#define IS_SET(flag, bit)   ((flag) & (bit))
#define SET_BIT(var, bit)   ((var) |= (bit))
#define REMOVE_BIT(var, bit)    ((var) &= ~(bit))

/* file read macro */
#if defined(KEY)
#undef KEY
#endif
#define KEY( literal, field, value )                    \
                if ( !str_cmp( word, literal ) )    \
                {                   \
                    field  = value;         \
                    fMatch = true;          \
                    break;              \
                }

/*
 * Global constants for Telnet.
 */
const char echo_off_str[] = { IAC, WILL, TELOPT_ECHO, '\0' };
const char echo_on_str[] = { IAC, WONT, TELOPT_ECHO, '\0' };
const char go_ahead_str[] = { IAC, GA, '\0' };

/*
 * Globals.
 */
std::list<Area *> area_list;
Area *area_last = NULL;
std::list<Ban *> ban_list;
std::list<Character *> char_list;
std::list<Descriptor *> descriptor_list;       /* All open descriptors     */
std::list<Help *> help_list;
std::list<Note *> note_list;
std::list<Object *> object_list;
std::list<Shop *> shop_list;

typedef std::list<Affect *>::iterator AffIter;
typedef std::list<Character *>::iterator CharIter;
typedef std::list<Descriptor *>::iterator DescIter;
typedef std::list<Object *>::iterator ObjIter;

// These iterators used on loops where the next iterator can be invalidated
// because of a nested method that erases an object in the list.
CharIter deepchnext, deeprmnext;
ObjIter deepobnext;
DescIter deepdenext;
//bool character_invalidated = false;  // This is set in Mprogs if we

std::map<int, MobPrototype *> mob_table;
std::map<int, ObjectPrototype *> obj_table;
std::map<int, Room *> room_table;

struct time_info_data {
  int hour;
  int day;
  int month;
  int year;
} time_info;

struct weather_data {
  int mmhg;
  int change;
  int sky;
  int sunlight;
} weather_info;

/*
 * A kill structure (indexed by level).
 */
struct kill_data {
  int number;
  int killed;
} kill_table[MAX_LEVEL];

/*
 * Global variables.
 */
bool merc_down;                 /* Shutdown         */
bool wizlock;                   /* Game is wizlocked        */
std::string str_boot_time;
time_t current_time;            /* Time of this pulse       */
std::string help_greeting;
sqlite3 *database = NULL;

/*
 * The kludgy global is for spells who want more stuff from command line.
 */
std::string target_name;

bool fBootDb;
std::ifstream * fpArea;
std::string strArea;

/*
 * Array of containers read for proper re-nesting of objects.
 */
#define MAX_NEST    100
Object *rgObjNest[MAX_NEST];

bool MOBtrigger;

/*
 * These are skill_lookup return values for common skills and spells.
 */
sh_int gsn_backstab;
sh_int gsn_dodge;
sh_int gsn_hide;
sh_int gsn_peek;
sh_int gsn_pick_lock;
sh_int gsn_sneak;
sh_int gsn_steal;

sh_int gsn_disarm;
sh_int gsn_enhanced_damage;
sh_int gsn_kick;
sh_int gsn_parry;
sh_int gsn_rescue;
sh_int gsn_second_attack;
sh_int gsn_third_attack;

sh_int gsn_blindness;
sh_int gsn_charm_person;
sh_int gsn_curse;
sh_int gsn_invis;
sh_int gsn_mass_invis;
sh_int gsn_poison;
sh_int gsn_sleep;

const std::string dir_name[] = {
  "north", "east", "south", "west", "up", "down"
};

const sh_int rev_dir[] = {
  2, 3, 0, 1, 5, 4
};

const sh_int movement_loss[SECT_MAX] = {
  1, 2, 2, 3, 4, 6, 4, 1, 6, 10, 6
};

const std::string day_name[] = {
  "the Moon", "the Bull", "Deception", "Thunder", "Freedom",
  "the Great Gods", "the Sun"
};

const std::string month_name[] = {
  "Winter", "the Winter Wolf", "the Frost Giant", "the Old Forces",
  "the Grand Struggle", "the Spring", "Nature", "Futility", "the Dragon",
  "the Sun", "the Heat", "the Battle", "the Dark Shades", "the Shadows",
  "the Long Shadows", "the Ancient Darkness", "the Great Evil"
};

const std::string where_name[] = {
  "<used as light>     ",
  "<worn on finger>    ",
  "<worn on finger>    ",
  "<worn around neck>  ",
  "<worn around neck>  ",
  "<worn on body>      ",
  "<worn on head>      ",
  "<worn on legs>      ",
  "<worn on feet>      ",
  "<worn on hands>     ",
  "<worn on arms>      ",
  "<worn as shield>    ",
  "<worn about body>   ",
  "<worn about waist>  ",
  "<worn around wrist> ",
  "<worn around wrist> ",
  "<wielded>           ",
  "<held>              "
};

/*
 * Class table.
 */
const struct class_type {
  char who_name[4];             /* Three-letter name for 'who'  */
  sh_int attr_prime;            /* Prime attribute      */
  sh_int weapon;                /* First weapon         */
  sh_int guild;                 /* Vnum of guild room       */
  sh_int skill_adept;           /* Maximum skill level      */
  sh_int thac0_00;              /* Thac0 for level  0       */
  sh_int thac0_32;              /* Thac0 for level 32       */
  sh_int hp_min;                /* Min hp gained on leveling    */
  sh_int hp_max;                /* Max hp gained on leveling    */
  bool fMana;                   /* Class gains mana on level    */
} class_table[CLASS_MAX] = {
  { "Mag", APPLY_INT, OBJ_VNUM_SCHOOL_DAGGER,
    3018, 95, 18, 10, 6, 8, true},
  { "Cle", APPLY_WIS, OBJ_VNUM_SCHOOL_MACE,
    3003, 95, 18, 12, 7, 10, true},
  { "Thi", APPLY_DEX, OBJ_VNUM_SCHOOL_DAGGER,
    3028, 85, 18, 8, 8, 13, false},
  { "War", APPLY_STR, OBJ_VNUM_SCHOOL_SWORD,
    3022, 85, 18, 6, 11, 15, false}
};

/*
 * Titles.
 */
char *const title_table[CLASS_MAX][MAX_LEVEL + 1][2] = {
  {
      {"Man", "Woman"},

      {"Apprentice of Magic", "Apprentice of Magic"},
      {"Spell Student", "Spell Student"},
      {"Scholar of Magic", "Scholar of Magic"},
      {"Delver in Spells", "Delveress in Spells"},
      {"Medium of Magic", "Medium of Magic"},

      {"Scribe of Magic", "Scribess of Magic"},
      {"Seer", "Seeress"},
      {"Sage", "Sage"},
      {"Illusionist", "Illusionist"},
      {"Abjurer", "Abjuress"},

      {"Invoker", "Invoker"},
      {"Enchanter", "Enchantress"},
      {"Conjurer", "Conjuress"},
      {"Magician", "Witch"},
      {"Creator", "Creator"},

      {"Savant", "Savant"},
      {"Magus", "Craftess"},
      {"Wizard", "Wizard"},
      {"Warlock", "War Witch"},
      {"Sorcerer", "Sorceress"},

      {"Elder Sorcerer", "Elder Sorceress"},
      {"Grand Sorcerer", "Grand Sorceress"},
      {"Great Sorcerer", "Great Sorceress"},
      {"Golem Maker", "Golem Maker"},
      {"Greater Golem Maker", "Greater Golem Maker"},

      {"Maker of Stones", "Maker of Stones",},
      {"Maker of Potions", "Maker of Potions",},
      {"Maker of Scrolls", "Maker of Scrolls",},
      {"Maker of Wands", "Maker of Wands",},
      {"Maker of Staves", "Maker of Staves",},

      {"Demon Summoner", "Demon Summoner"},
      {"Greater Demon Summoner", "Greater Demon Summoner"},
      {"Dragon Charmer", "Dragon Charmer"},
      {"Greater Dragon Charmer", "Greater Dragon Charmer"},
      {"Master of all Magic", "Master of all Magic"},

      {"Mage Hero", "Mage Heroine"},
      {"Angel of Magic", "Angel of Magic"},
      {"Deity of Magic", "Deity of Magic"},
      {"Supremity of Magic", "Supremity of Magic"},
      {"Implementor", "Implementress"}
    },

  {
      {"Man", "Woman"},

      {"Believer", "Believer"},
      {"Attendant", "Attendant"},
      {"Acolyte", "Acolyte"},
      {"Novice", "Novice"},
      {"Missionary", "Missionary"},

      {"Adept", "Adept"},
      {"Deacon", "Deaconess"},
      {"Vicar", "Vicaress"},
      {"Priest", "Priestess"},
      {"Minister", "Lady Minister"},

      {"Canon", "Canon"},
      {"Levite", "Levitess"},
      {"Curate", "Curess"},
      {"Monk", "Nun"},
      {"Healer", "Healess"},

      {"Chaplain", "Chaplain"},
      {"Expositor", "Expositress"},
      {"Bishop", "Bishop"},
      {"Arch Bishop", "Arch Lady of the Church"},
      {"Patriarch", "Matriarch"},

      {"Elder Patriarch", "Elder Matriarch"},
      {"Grand Patriarch", "Grand Matriarch"},
      {"Great Patriarch", "Great Matriarch"},
      {"Demon Killer", "Demon Killer"},
      {"Greater Demon Killer", "Greater Demon Killer"},

      {"Cardinal of the Sea", "Cardinal of the Sea"},
      {"Cardinal of the Earth", "Cardinal of the Earth"},
      {"Cardinal of the Air", "Cardinal of the Air"},
      {"Cardinal of the Ether", "Cardinal of the Ether"},
      {"Cardinal of the Heavens", "Cardinal of the Heavens"},

      {"Avatar of an Immortal", "Avatar of an Immortal"},
      {"Avatar of a Deity", "Avatar of a Deity"},
      {"Avatar of a Supremity", "Avatar of a Supremity"},
      {"Avatar of an Implementor", "Avatar of an Implementor"},
      {"Master of all Divinity", "Mistress of all Divinity"},

      {"Holy Hero", "Holy Heroine"},
      {"Angel", "Angel"},
      {"Deity", "Deity"},
      {"Supreme Master", "Supreme Mistress"},
      {"Implementor", "Implementress"}
    },

  {
      {"Man", "Woman"},

      {"Pilferer", "Pilferess"},
      {"Footpad", "Footpad"},
      {"Filcher", "Filcheress"},
      {"Pick-Pocket", "Pick-Pocket"},
      {"Sneak", "Sneak"},

      {"Pincher", "Pincheress"},
      {"Cut-Purse", "Cut-Purse"},
      {"Snatcher", "Snatcheress"},
      {"Sharper", "Sharpress"},
      {"Rogue", "Rogue"},

      {"Robber", "Robber"},
      {"Magsman", "Magswoman"},
      {"Highwayman", "Highwaywoman"},
      {"Burglar", "Burglaress"},
      {"Thief", "Thief"},

      {"Knifer", "Knifer"},
      {"Quick-Blade", "Quick-Blade"},
      {"Killer", "Murderess"},
      {"Brigand", "Brigand"},
      {"Cut-Throat", "Cut-Throat"},

      {"Spy", "Spy"},
      {"Grand Spy", "Grand Spy"},
      {"Master Spy", "Master Spy"},
      {"Assassin", "Assassin"},
      {"Greater Assassin", "Greater Assassin"},

      {"Master of Vision", "Mistress of Vision"},
      {"Master of Hearing", "Mistress of Hearing"},
      {"Master of Smell", "Mistress of Smell"},
      {"Master of Taste", "Mistress of Taste"},
      {"Master of Touch", "Mistress of Touch"},

      {"Crime Lord", "Crime Mistress"},
      {"Infamous Crime Lord", "Infamous Crime Mistress"},
      {"Greater Crime Lord", "Greater Crime Mistress"},
      {"Master Crime Lord", "Master Crime Mistress"},
      {"Godfather", "Godmother"},

      {"Assassin Hero", "Assassin Heroine"},
      {"Angel of Death", "Angel of Death"},
      {"Deity of Assassins", "Deity of Assassins"},
      {"Supreme Master", "Supreme Mistress"},
      {"Implementor", "Implementress"}
    },

  {
      {"Man", "Woman"},

      {"Swordpupil", "Swordpupil"},
      {"Recruit", "Recruit"},
      {"Sentry", "Sentress"},
      {"Fighter", "Fighter"},
      {"Soldier", "Soldier"},

      {"Warrior", "Warrior"},
      {"Veteran", "Veteran"},
      {"Swordsman", "Swordswoman"},
      {"Fencer", "Fenceress"},
      {"Combatant", "Combatess"},

      {"Hero", "Heroine"},
      {"Myrmidon", "Myrmidon"},
      {"Swashbuckler", "Swashbuckleress"},
      {"Mercenary", "Mercenaress"},
      {"Swordmaster", "Swordmistress"},

      {"Lieutenant", "Lieutenant"},
      {"Champion", "Lady Champion"},
      {"Dragoon", "Lady Dragoon"},
      {"Cavalier", "Lady Cavalier"},
      {"Knight", "Lady Knight"},

      {"Grand Knight", "Grand Knight"},
      {"Master Knight", "Master Knight"},
      {"Paladin", "Paladin"},
      {"Grand Paladin", "Grand Paladin"},
      {"Demon Slayer", "Demon Slayer"},

      {"Greater Demon Slayer", "Greater Demon Slayer"},
      {"Dragon Slayer", "Dragon Slayer"},
      {"Greater Dragon Slayer", "Greater Dragon Slayer"},
      {"Underlord", "Underlord"},
      {"Overlord", "Overlord"},

      {"Baron of Thunder", "Baroness of Thunder"},
      {"Baron of Storms", "Baroness of Storms"},
      {"Baron of Tornadoes", "Baroness of Tornadoes"},
      {"Baron of Hurricanes", "Baroness of Hurricanes"},
      {"Baron of Meteors", "Baroness of Meteors"},

      {"Knight Hero", "Knight Heroine"},
      {"Angel of War", "Angel of War"},
      {"Deity of War", "Deity of War"},
      {"Supreme Master of War", "Supreme Mistress of War"},
      {"Implementor", "Implementress"}
    }
};

/*
 * Attribute bonus structures.
 */
const struct str_app_type {
  sh_int tohit;
  sh_int todam;
  sh_int carry;
  sh_int wield;
} str_app[26] = {
  {-5, -4, 0, 0}, {-5, -4, 3, 1}, {-3, -2, 3, 2}, {-3, -1, 10, 3},
  {-2, -1, 25, 4}, {-2, -1, 55, 5}, {-1, 0, 80, 6}, {-1, 0, 90, 7},
  {0, 0, 100, 8}, {0, 0, 100, 9}, {0, 0, 115, 10},  {0, 0, 115, 11},
  {0, 0, 140, 12}, {0, 0, 140, 13}, {0, 1, 170, 14}, {1, 1, 170, 15}, /* 15  */
  {1, 2, 195, 16}, {2, 3, 220, 22}, {2, 4, 250, 25}, {3, 5, 400, 30},
  {3, 6, 500, 35}, {4, 7, 600, 40}, {5, 7, 700, 45}, {6, 8, 800, 50},
  {8, 10, 900, 55}, {10, 12, 999, 60}      /* 25   */
};

const struct int_app_type {
  sh_int learn;
} int_app[26] = {
  {3}, {5}, {7}, {8}, {9}, {10},      /*  5 */
  {11}, {12}, {13}, {15}, {17},       /* 10 */
  {19}, {22}, {25}, {28}, {31},       /* 15 */
  {34}, {37}, {40}, {44}, {49},       /* 20 */
  {55}, {60}, {70}, {85}, {99}        /* 25 */
};

const struct wis_app_type {
  sh_int practice;
} wis_app[26] = {
  {0}, {0}, {0}, {0}, {0}, {1},       /*  5 */
  {1}, {1}, {1}, {2}, {2},            /* 10 */
  {2}, {2}, {2}, {2}, {3},            /* 15 */
  {3}, {4}, {4}, {5}, {5},            /* 20 */
  {6}, {7}, {7}, {7}, {8}             /* 25 */
};

const struct dex_app_type {
  sh_int defensive;
} dex_app[26] = {
  {60}, {50}, {50}, {40}, {30}, {20}, /* 5 */
  {10}, {0}, {0}, {0}, {0},           /* 10 */
  {0}, {0}, {0}, {0}, {-10},          /* 15 */
  {-15}, {-20}, {-30}, {-40}, {-50},  /* 20 */
  {-65}, {-75}, {-90}, {-105}, {-120} /* 25 */
};

const struct con_app_type {
  sh_int hitp;
  sh_int shock;
} con_app[26] = {
  {-4, 20}, {-3, 25}, {-2, 30}, {-2, 35}, {-1, 40}, {-1, 45}, /*  5 */
  {-1, 50}, {0, 55}, {0, 60}, {0, 65}, {0, 70},               /* 10 */
  {0, 75}, {0, 80}, {0, 85}, {0, 88}, {1, 90},                /* 15 */
  {2, 95}, {2, 97}, {3, 99}, {3, 99}, {4, 99},                /* 20 */
  {4, 99}, {5, 99}, {6, 99}, {7, 99}, {8, 99}                 /* 25 */
};

/*
 * Liquid properties.
 * Used in world.obj.
 */
const struct liq_type {
  const char * liq_name;
  const char * liq_color;
  sh_int liq_affect[3];
} liq_table[LIQ_MAX] = {
  {"water", "clear", {0, 1, 10}},       /*  0 */
  {"beer", "amber", {3, 2, 5}},
  {"wine", "rose", {5, 2, 5}},
  {"ale", "brown", {2, 2, 5}},
  {"dark ale", "dark", {1, 2, 5}},

  {"whisky", "golden", {6, 1, 4}},      /*  5 */
  {"lemonade", "pink", {0, 1, 8}},
  {"firebreather", "boiling", {10, 0, 0}},
  {"local specialty", "everclear", {3, 3, 3}},
  {"slime mold juice", "green", {0, 4, -8}},

  {"milk", "white", {0, 3, 6}}, /* 10 */
  {"tea", "tan", {0, 1, 6}},
  {"coffee", "black", {0, 1, 6}},
  {"blood", "red", {0, 2, -1}},
  {"salt water", "clear", {0, 1, -2}},

  {"cola", "cherry", {0, 1, 5}} /* 15 */
};

/* prototypes */
int number_percent (void);
std::string one_argument (const std::string & argument, std::string & arg_first);
void multi_hit(Character *ch, Character *victim, int dt);
void damage(Character *ch, Character *victim, int dam, int dt);

bool dragon(Character *ch, char *spell_name);

void mprog_act_trigger(const std::string & buf, Character *mob, Character *ch, Object *obj, void *vo);
void mprog_bribe_trigger(Character *mob, Character *ch, int amount);
void mprog_death_trigger(Character *mob);
void mprog_entry_trigger(Character *mob);
void mprog_fight_trigger(Character *mob, Character *ch);
void mprog_give_trigger(Character *mob, Character *ch, Object *obj);
void mprog_greet_trigger(Character *mob);
void mprog_hitprcnt_trigger(Character *mob, Character *ch);
void mprog_random_trigger(Character *mob);
void mprog_speech_trigger(char *txt, Character *mob);

bool spec_breath_any(Character *ch);
bool spec_breath_acid(Character *ch);
bool spec_breath_fire(Character *ch);
bool spec_breath_frost(Character *ch);
bool spec_breath_gas(Character *ch);
bool spec_breath_lightning(Character *ch);
bool spec_cast_adept(Character *ch);
bool spec_cast_cleric(Character *ch);
bool spec_cast_judge(Character *ch);
bool spec_cast_mage(Character *ch);
bool spec_cast_undead(Character *ch);
bool spec_executioner(Character *ch);
bool spec_fido(Character *ch);
bool spec_guard(Character *ch);
bool spec_janitor(Character *ch);
bool spec_mayor(Character *ch);
bool spec_poison(Character *ch);
bool spec_thief(Character *ch);

/* Structs */

/*
 * Site ban structure.
 */
class Ban {
public:
  std::string name;

  Ban(std::string & _name) :
    name(_name) {
  }

};

/*
 * Descriptor (channel) structure.
 */
class Descriptor {
public:
  Character *character;
  Character *original;
  std::string host;
  SOCKET descriptor;
  sh_int connected;
  bool fcommand;
  char inbuf[4 * MAX_INPUT_LENGTH];
  std::string incomm;
  std::string inlast;
  int repeat;
  char *showstr_head;
  char *showstr_point;
  std::string outbuf;

  Descriptor(SOCKET desc) :
    character(NULL), original(NULL),
    descriptor(desc), connected(CON_GET_NAME), fcommand(false),
    repeat(0), showstr_head(NULL), showstr_point(NULL) {
    memset(inbuf, 0, sizeof inbuf);
  }

  void show_string (const std::string & input);
  void nanny (std::string argument);
  void read_from_buffer ();
  bool check_reconnect (const std::string & name, bool fConn);
  bool check_playing (const std::string & name);
  void close_socket ();
  bool read_from_descriptor ();
  bool load_char_obj (const std::string & name);
  void write_to_buffer (const std::string & txt);
  bool process_output (bool fPrompt);

};

/*
 * Help table types.
 */
class Help {
public:
  static int top_help;
  sh_int level;
  std::string keyword;
  std::string text;

  Help() : level(0) {
    top_help++;
  }

};

int Help::top_help = 0;

/*
 * Shop types.
 */
class Shop {
public:
  static int top_shop;

  sh_int keeper;                /* Vnum of shop keeper mob  */
  sh_int buy_type[MAX_TRADE];   /* Item types shop will buy */
  sh_int profit_buy;            /* Cost multiplier for buying   */
  sh_int profit_sell;           /* Cost multiplier for selling  */
  sh_int open_hour;             /* First opening hour       */
  sh_int close_hour;            /* First closing hour       */

  Shop() :
    keeper(0), profit_buy(0), profit_sell(0), open_hour(0),
    close_hour(0) {
    memset(buy_type, 0, sizeof buy_type);
    top_shop++;
  }

};

int Shop::top_shop = 0;

/*
 * Data structure for notes.
 */
class Note {
public:
  std::string sender;
  std::string date;
  std::string to_list;
  std::string subject;
  std::string text;
  time_t date_stamp;

  Note() :
    date_stamp(0) {
  }

};

/*
 * An affect.
 */
class Affect {
public:
  static int top_affect;
  sh_int type;
  sh_int duration;
  sh_int location;
  sh_int modifier;
  int bitvector;

  Affect() :
    type(0), duration(0), location(0), modifier(0), bitvector(0) {
    top_affect++;
  }

};

int Affect::top_affect = 0;

/*
 * MOBprogram block
*/
class MobProgramActList {
public:
  MobProgramActList *next;
  std::string buf;
  Character *ch;
  Object *obj;
  void *vo;

  MobProgramActList() :
    next(NULL), ch(NULL), obj(NULL), vo(NULL) {
  }

};

class MobProgram {
public:
  MobProgram *next;
  int type;
  std::string arglist;
  std::string comlist;

  MobProgram() :
    next(NULL), type(0) {
  }

};

/*
 * Exit data.
 */
class Exit {
public:
  static int top_exit;
  Room *to_room;
  sh_int vnum;
  sh_int exit_info;
  sh_int key;
  std::string keyword;
  std::string description;

  Exit() :
    to_room(NULL), vnum(0), exit_info(0), key(0) {
    top_exit++;
  }

};

int Exit::top_exit = 0;

/*
 * Reset commands:
 *   '*': comment
 *   'M': read a mobile
 *   'O': read an object
 *   'P': put object in object
 *   'G': give object to mobile
 *   'E': equip object to mobile
 *   'D': set state of door
 *   'R': randomize room exits
 *   'S': stop (end of list)
 */

/*
 * Area-reset definition.
 */
class Reset {
public:
  static int top_reset;
  char command;
  sh_int arg1;
  sh_int arg2;
  sh_int arg3;

  Reset() :
    command(0), arg1(0), arg2(0), arg3(0) {
    top_reset++;
  }

};

int Reset::top_reset = 0;

/*
 * Area definition.
 */
struct Area {
public:
  static int top_area;

  std::list<Reset *> reset_list;
  std::string name;
  sh_int age;
  sh_int nplayer;

  Area() :
    age(0), nplayer(0) {
    top_area++;
  }
};

int Area::top_area = 0;

/*
 * Room type.
 */
class Room {
public:
  static int top_room;
  std::list<Character *> people;
  std::list<Object *> contents;
  std::list<ExtraDescription *> extra_descr;
  Area *area;
  Exit *exit[6];
  std::string name;
  std::string description;
  sh_int vnum;
  sh_int room_flags;
  sh_int light;
  int sector_type;

  Room() :
    area(NULL),
    vnum(0), room_flags(0), light(0), sector_type(0) {
    memset(exit, 0, sizeof exit);
    top_room++;
  }

  bool is_private();
  bool is_dark ();

};

int Room::top_room = 0;

/*
 * Prototype for an object.
 */
class ObjectPrototype {
public:
  static int top_obj;
  std::list<ExtraDescription *> extra_descr;
  std::list<Affect *> affected;
  std::string name;
  std::string short_descr;
  std::string description;
  sh_int vnum;
  sh_int item_type;
  sh_int extra_flags;
  sh_int wear_flags;
  sh_int count;
  sh_int weight;
  int cost;                     /* Unused */
  int value[4];

  ObjectPrototype() :
    vnum(0), item_type(0),
    extra_flags(0), wear_flags(0), count(0), weight(0), cost(0) {
    memset(value, 0, sizeof value);
    top_obj++;
  }

  int count_obj_list (std::list<Object *> & list);
  Object * get_obj_type ();
  Object * create_object (int lvl);

};

int ObjectPrototype::top_obj = 0;

/*
 * One object.
 */
class Object {
public:
  std::list<Object *> contains;
  Object *in_obj;
  Character *carried_by;
  std::list<ExtraDescription *> extra_descr;
  std::list<Affect *> affected;
  ObjectPrototype *pIndexData;
  Room *in_room;
  std::string name;
  std::string short_descr;
  std::string description;
  sh_int item_type;
  sh_int extra_flags;
  sh_int wear_flags;
  sh_int wear_loc;
  sh_int weight;
  int cost;
  sh_int level;
  sh_int timer;
  int value[4];

  Object() :
    in_obj(NULL), carried_by(NULL), pIndexData(NULL),
    in_room(NULL), item_type(0), extra_flags(0), wear_flags(0), wear_loc(0),
    weight(0), cost(0), level(0), timer(0) {
    memset(value, 0, sizeof value);
  }

  std::string item_type_name ();
  int apply_ac (int iWear);
  int get_obj_number ();
  int get_obj_weight ();
  bool can_wear (sh_int part);
  bool is_obj_stat(sh_int stat);
  void obj_from_room ();
  void obj_to_room (Room * pRoomIndex);
  void obj_to_obj (Object * obj_to);
  void obj_from_obj ();
  void obj_to_char (Character * ch);
  void obj_from_char ();
  void extract_obj ();
  void fwrite_obj (Character * ch, std::ofstream & fp, int iNest);
  bool fread_obj (Character * ch, std::ifstream & fp);
  std::string format_obj_to_char (Character * ch, bool fShort);

};

/*
 * Prototype for a mob.
 * This is the in-memory version of #MOBILES.
 */
class MobPrototype {
public:
  static int top_mob;
  SPEC_FUN *spec_fun;
  Shop *pShop;
  std::string player_name;
  std::string short_descr;
  std::string long_descr;
  std::string description;
  sh_int vnum;
  int count;
  int killed;
  sh_int sex;
  int level;
  int actflags;
  int affected_by;
  sh_int alignment;
  MobProgram *mobprogs;         /* Used by MOBprogram */
  int progtypes;                /* Used by MOBprogram */

  MobPrototype() :
    spec_fun(NULL), pShop(NULL), vnum(0), count(0), killed(0),
    sex(0), level(0), actflags(0), affected_by(0), alignment(0),
    mobprogs(NULL), progtypes(0) {
    top_mob++;
  }

  Character * create_mobile ();
};

int MobPrototype::top_mob = 0;

/*
 * Data which only PC's have.
 */
class PCData {
public:
  std::string pwd;
  std::string bamfin;
  std::string bamfout;
  std::string title;
  sh_int perm_str;
  sh_int perm_int;
  sh_int perm_wis;
  sh_int perm_dex;
  sh_int perm_con;
  sh_int mod_str;
  sh_int mod_int;
  sh_int mod_wis;
  sh_int mod_dex;
  sh_int mod_con;
  sh_int condition[3];
  sh_int pagelen;
  sh_int learned[MAX_SKILL];

  PCData() :
    perm_str(13), perm_int(13), perm_wis(13), perm_dex(13), perm_con(13),
    mod_str(0), mod_int(0), mod_wis(0), mod_dex(0), mod_con(0), pagelen(20) {
    memset(condition, 0, sizeof condition);
    memset(learned, 0, sizeof learned);
  }

};

/*
 * One character (PC or NPC).
 */
class Character {
public:
  Character *master;
  Character *leader;
  Character *fighting;
  Character *reply;
  SPEC_FUN *spec_fun;
  MobPrototype *pIndexData;
  Descriptor *desc;
  std::list<Affect *> affected;
  Note *pnote;
  std::list<Object *> carrying;
  Room *in_room;
  Room *was_in_room;
  PCData *pcdata;
  std::string name;
  std::string short_descr;
  std::string long_descr;
  std::string description;
  std::string prompt;
  sh_int sex;
  sh_int klass;
  sh_int race;
  int level;
  sh_int trust;
  bool wizbit;
  int played;
  time_t logon;
  time_t save_time;
  time_t last_note;
  sh_int timer;
  int wait;
  int hit;
  int max_hit;
  int mana;
  int max_mana;
  int move;
  int max_move;
  int gold;
  int exp;
  int actflags;
  int affected_by;
  sh_int position;
  sh_int practice;
  sh_int carry_weight;
  sh_int carry_number;
  sh_int saving_throw;
  sh_int alignment;
  sh_int hitroll;
  sh_int damroll;
  sh_int armor;
  sh_int wimpy;
  sh_int deaf;
  MobProgramActList *mpact;        /* Used by MOBprogram */
  int mpactnum;                 /* Used by MOBprogram */

  Character() :
    master(NULL), leader(NULL), fighting(NULL),
    reply(NULL), spec_fun(NULL), pIndexData(NULL), desc(NULL),
    pnote(NULL), in_room(NULL), was_in_room(NULL),
    pcdata(NULL), sex(0), klass(0), race(0), level(0), trust(0), wizbit(false),
    played(0), logon(current_time), save_time(0), last_note(0), timer(0),
    wait(0), hit(20), max_hit(20), mana(100), max_mana(100), move(100),
    max_move(100), gold(0), exp(0), actflags(0), affected_by(0),
    position(POS_STANDING), practice(21), carry_weight(0), carry_number(0),
    saving_throw(0), alignment(0), hitroll(0), damroll(0), armor(100),
    wimpy(0), deaf(0), mpact(NULL), mpactnum(0) {
  }

  /*
   * Free a character.
   */
  ~Character()
  {
    Object *obj;
    Affect *paf;

    ObjIter o, onext;
    for (o = carrying.begin(); o != carrying.end(); o = onext) {
      obj = *o;
      onext = ++o;
      obj->extract_obj ();
    }

    AffIter af, anext;
    for (af = affected.begin(); af != affected.end(); af = anext) {
      paf = *af;
      anext = ++af;
      affect_remove (paf);
    }

    if (pcdata != NULL) {
      delete pcdata;
    }

    return;
  }

  void do_areas(std::string argument);
  void do_memory(std::string argument);
  void do_kill(std::string argument);
  void do_murde(std::string argument);
  void do_murder(std::string argument);
  void do_backstab(std::string argument);
  void do_flee(std::string argument);
  void do_rescue(std::string argument);
  void do_kick(std::string argument);
  void do_disarm(std::string argument);
  void do_sla(std::string argument);
  void do_slay(std::string argument);
  void do_cast(std::string argument);
  void do_note(std::string argument);
  void do_auction(std::string argument);
  void do_chat(std::string argument);
  void do_music(std::string argument);
  void do_question(std::string argument);
  void do_answer(std::string argument);
  void do_shout(std::string argument);
  void do_yell(std::string argument);
  void do_immtalk(std::string argument);
  void do_say(std::string argument);
  void do_tell(std::string argument);
  void do_reply(std::string argument);
  void do_emote(std::string argument);
  void do_bug(std::string argument);
  void do_idea(std::string argument);
  void do_typo(std::string argument);
  void do_rent(std::string argument);
  void do_qui(std::string argument);
  void do_quit(std::string argument);
  void do_save(std::string argument);
  void do_follow(std::string argument);
  void do_order(std::string argument);
  void do_group(std::string argument);
  void do_split(std::string argument);
  void do_gtell(std::string argument);
  void do_look(std::string argument);
  void do_examine(std::string argument);
  void do_exits(std::string argument);
  void do_score(std::string argument);
  void do_time(std::string argument);
  void do_weather(std::string argument);
  void do_help(std::string argument);
  void do_who(std::string argument);
  void do_inventory(std::string argument);
  void do_equipment(std::string argument);
  void do_compare(std::string argument);
  void do_credits(std::string argument);
  void do_where(std::string argument);
  void do_consider(std::string argument);
  void do_title(std::string argument);
  void do_description(std::string argument);
  void do_report(std::string argument);
  void do_practice(std::string argument);
  void do_wimpy(std::string argument);
  void do_password(std::string argument);
  void do_socials(std::string argument);
  void do_commands(std::string argument);
  void do_channels(std::string argument);
  void do_config(std::string argument);
  void do_wizlist(std::string argument);
  void do_spells(std::string argument);
  void do_slist(std::string argument);
  void do_autoexit(std::string argument);
  void do_autoloot(std::string argument);
  void do_autosac(std::string argument);
  void do_blank(std::string argument);
  void do_brief(std::string argument);
  void do_combine(std::string argument);
  void do_pagelen(std::string argument);
  void do_prompt(std::string argument);
  void do_auto(std::string argument);
  void do_north(std::string argument);
  void do_east(std::string argument);
  void do_south(std::string argument);
  void do_west(std::string argument);
  void do_up(std::string argument);
  void do_down(std::string argument);
  void do_open(std::string argument);
  void do_close(std::string argument);
  void do_lock(std::string argument);
  void do_unlock(std::string argument);
  void do_pick(std::string argument);
  void do_stand(std::string argument);
  void do_rest(std::string argument);
  void do_sleep(std::string argument);
  void do_wake(std::string argument);
  void do_sneak(std::string argument);
  void do_hide(std::string argument);
  void do_visible(std::string argument);
  void do_recall(std::string argument);
  void do_train(std::string argument);
  void do_get(std::string argument);
  void do_put(std::string argument);
  void do_drop(std::string argument);
  void do_give(std::string argument);
  void do_fill(std::string argument);
  void do_drink(std::string argument);
  void do_eat(std::string argument);
  void do_wear(std::string argument);
  void do_remove(std::string argument);
  void do_sacrifice(std::string argument);
  void do_quaff(std::string argument);
  void do_recite(std::string argument);
  void do_brandish(std::string argument);
  void do_zap(std::string argument);
  void do_steal(std::string argument);
  void do_buy(std::string argument);
  void do_list(std::string argument);
  void do_sell(std::string argument);
  void do_value(std::string argument);
  void do_wizhelp(std::string argument);
  void do_bamfin(std::string argument);
  void do_bamfout(std::string argument);
  void do_deny(std::string argument);
  void do_disconnect(std::string argument);
  void do_pardon(std::string argument);
  void do_echo(std::string argument);
  void do_recho(std::string argument);
  void do_transfer(std::string argument);
  void do_at(std::string argument);
  void do_goto(std::string argument);
  void do_rstat(std::string argument);
  void do_ostat(std::string argument);
  void do_mstat(std::string argument);
  void do_mfind(std::string argument);
  void do_ofind(std::string argument);
  void do_mwhere(std::string argument);
  void do_reboo(std::string argument);
  void do_reboot(std::string argument);
  void do_shutdow(std::string argument);
  void do_shutdown(std::string argument);
  void do_switch(std::string argument);
  void do_return(std::string argument);
  void do_mload(std::string argument);
  void do_oload(std::string argument);
  void do_purge(std::string argument);
  void do_advance(std::string argument);
  void do_trust(std::string argument);
  void do_restore(std::string argument);
  void do_freeze(std::string argument);
  void do_noemote(std::string argument);
  void do_notell(std::string argument);
  void do_silence(std::string argument);
  void do_peace(std::string argument);
  void do_ban(std::string argument);
  void do_allow(std::string argument);
  void do_wizlock(std::string argument);
  void do_slookup(std::string argument);
  void do_sset(std::string argument);
  void do_mset(std::string argument);
  void do_oset(std::string argument);
  void do_rset(std::string argument);
  void do_users(std::string argument);
  void do_force(std::string argument);
  void do_invis(std::string argument);
  void do_holylight(std::string argument);
  void do_wizify(std::string argument);
  void do_owhere(std::string argument);
  void do_mpstat(std::string argument);
  void do_mpasound(std::string argument);
  void do_mpkill(std::string argument);
  void do_mpjunk(std::string argument);
  void do_mpechoaround(std::string argument);
  void do_mpechoat(std::string argument);
  void do_mpecho(std::string argument);
  void do_mpmload(std::string argument);
  void do_mpoload(std::string argument);
  void do_mppurge(std::string argument);
  void do_mpgoto(std::string argument);
  void do_mpat(std::string argument);
  void do_mptransfer(std::string argument);
  void do_mpforce(std::string argument);

  void spell_acid_blast(int sn, int level, void *vo);
  void spell_armor(int sn, int level, void *vo);
  void spell_bless(int sn, int level, void *vo);
  void spell_blindness(int sn, int level, void *vo);
  void spell_burning_hands(int sn, int level, void *vo);
  void spell_call_lightning(int sn, int level, void *vo);
  void spell_cause_light(int sn, int level, void *vo);
  void spell_cause_critical(int sn, int level, void *vo);
  void spell_cause_serious(int sn, int level, void *vo);
  void spell_change_sex(int sn, int level, void *vo);
  void spell_charm_person(int sn, int level, void *vo);
  void spell_chill_touch(int sn, int level, void *vo);
  void spell_colour_spray(int sn, int level, void *vo);
  void spell_continual_light(int sn, int level, void *vo);
  void spell_control_weather(int sn, int level, void *vo);
  void spell_create_food(int sn, int level, void *vo);
  void spell_create_spring(int sn, int level, void *vo);
  void spell_create_water(int sn, int level, void *vo);
  void spell_cure_blindness(int sn, int level, void *vo);
  void spell_cure_critical(int sn, int level, void *vo);
  void spell_cure_light(int sn, int level, void *vo);
  void spell_cure_poison(int sn, int level, void *vo);
  void spell_cure_serious(int sn, int level, void *vo);
  void spell_curse(int sn, int level, void *vo);
  void spell_detect_evil(int sn, int level, void *vo);
  void spell_detect_hidden(int sn, int level, void *vo);
  void spell_detect_invis(int sn, int level, void *vo);
  void spell_detect_magic(int sn, int level, void *vo);
  void spell_detect_poison(int sn, int level, void *vo);
  void spell_dispel_magic(int sn, int level, void *vo);
  void spell_dispel_evil(int sn, int level, void *vo);
  void spell_earthquake(int sn, int level, void *vo);
  void spell_enchant_weapon(int sn, int level, void *vo);
  void spell_energy_drain(int sn, int level, void *vo);
  void spell_fireball(int sn, int level, void *vo);
  void spell_flamestrike(int sn, int level, void *vo);
  void spell_faerie_fire(int sn, int level, void *vo);
  void spell_faerie_fog(int sn, int level, void *vo);
  void spell_fly(int sn, int level, void *vo);
  void spell_gate(int sn, int level, void *vo);
  void spell_general_purpose(int sn, int level, void *vo);
  void spell_giant_strength(int sn, int level, void *vo);
  void spell_harm(int sn, int level, void *vo);
  void spell_heal(int sn, int level, void *vo);
  void spell_high_explosive(int sn, int level, void *vo);
  void spell_identify(int sn, int level, void *vo);
  void spell_infravision(int sn, int level, void *vo);
  void spell_invis(int sn, int level, void *vo);
  void spell_know_alignment(int sn, int level, void *vo);
  void spell_lightning_bolt(int sn, int level, void *vo);
  void spell_locate_object(int sn, int level, void *vo);
  void spell_magic_missile(int sn, int level, void *vo);
  void spell_mass_invis(int sn, int level, void *vo);
  void spell_null(int sn, int level, void *vo);
  void spell_pass_door(int sn, int level, void *vo);
  void spell_poison(int sn, int level, void *vo);
  void spell_protection(int sn, int level, void *vo);
  void spell_refresh(int sn, int level, void *vo);
  void spell_remove_curse(int sn, int level, void *vo);
  void spell_sanctuary(int sn, int level, void *vo);
  void spell_shield(int sn, int level, void *vo);
  void spell_shocking_grasp(int sn, int level, void *vo);
  void spell_sleep(int sn, int level, void *vo);
  void spell_stone_skin(int sn, int level, void *vo);
  void spell_summon(int sn, int level, void *vo);
  void spell_teleport(int sn, int level, void *vo);
  void spell_ventriloquate(int sn, int level, void *vo);
  void spell_weaken(int sn, int level, void *vo);
  void spell_word_of_recall(int sn, int level, void *vo);
  void spell_acid_breath(int sn, int level, void *vo);
  void spell_fire_breath(int sn, int level, void *vo);
  void spell_frost_breath(int sn, int level, void *vo);
  void spell_gas_breath(int sn, int level, void *vo);
  void spell_lightning_breath(int sn, int level, void *vo);

  int is_npc();
  bool is_awake();
  bool is_good();
  bool is_evil();
  bool is_neutral();
  bool is_affected(int flg);
  int get_ac();
  int get_hitroll();
  int get_damroll();
  int get_curr_str();
  int get_curr_int();
  int get_curr_wis();
  int get_curr_dex();
  int get_curr_con();
  int get_age();
  int can_carry_n();
  int can_carry_w();
  int get_trust();
  bool is_immortal();
  bool is_hero();
  int is_outside();
  void wait_state(int npulse);
  int mana_cost(int sn);
  bool saves_spell (int lvl);
  std::string describe_to (Character* looker);
  Object * get_eq_char (int iWear);
  void affect_modify (Affect * paf, bool fAdd);
  bool can_see (Character * victim);
  bool can_see_obj (Object * obj);
  void unequip_char (Object * obj);
  void char_from_room ();
  void char_to_room (Room * pRoomIndex);
  void send_to_char (const std::string & txt);
  void interpret (std::string argument);
  bool check_social (const std::string & command, const std::string & argument);
  void set_title (const std::string & title);
  bool is_switched ();
  void advance_level ();
  bool mp_commands ();
  void gain_exp(int gain);
  int hit_gain ();
  int mana_gain ();
  int move_gain ();
  void add_follower (Character * master);
  void stop_follower();
  void die_follower();
  void update_pos ();
  void set_fighting (Character * victim);
  bool check_blind ();
  bool has_key (int key);
  void affect_to_char (Affect * paf);
  void affect_remove (Affect * paf);
  void affect_strip (int sn);
  bool has_affect (int sn);
  void affect_join (Affect * paf);
  bool remove_obj (int iWear, bool fReplace);
  void wear_obj (Object * obj, bool fReplace);
  void equip_char (Object * obj, int iWear);
  void act (const std::string & format, const void *arg1, const void *arg2, int type);
  bool can_drop_obj (Object * obj);
  Object * get_obj_wear (const std::string & argument);
  Object * get_obj_carry (const std::string & argument);
  Object * get_obj_here (const std::string & argument);
  void fwrite_char (std::ofstream & fp);
  void append_file (char *file, const std::string & str);
  Character * get_char_room (const std::string & argument);
  Character * get_char_world (const std::string & argument);
  Object * get_obj_list (const std::string & argument, std::list<Object *> & list);
  Object * get_obj_world (const std::string & argument);
  void save_char_obj ();
  void fread_char (std::ifstream & fp);
  void gain_condition (int iCond, int value);
  void stop_fighting (bool fBoth);
  int find_door (const std::string & arg);
  void get_obj (Object * obj, Object * container);
  void extract_char (bool fPull);
  void stop_idling ();
  void show_list_to_char (std::list<Object *> & list, bool fShort, bool fShowNothing);
  void show_char_to_char_0 (Character * victim);
  void show_char_to_char_1 (Character * victim);
  void show_char_to_char (std::list<Character *> & list);
  void move_char (int door);


};

/*
 * Extra description data for a room or object.
 */
class ExtraDescription {
public:
  static int top_ed;
  std::string keyword;          /* Keyword in look/examine          */
  std::string description;      /* What to see                      */

  ExtraDescription() {
    top_ed++;
  }

};

int ExtraDescription::top_ed = 0;

/*
 * Command table.
 */
typedef void (Character::*cmdfun_T) (std::string);

const struct cmd_type {
  const char * name;
  cmdfun_T do_fun;
  sh_int position;
  sh_int level;
} cmd_table[] = {
  /*
   * Common movement commands.
   */
  {"north", &Character::do_north, POS_STANDING, 0},
  {"east", &Character::do_east, POS_STANDING, 0},
  {"south", &Character::do_south, POS_STANDING, 0},
  {"west", &Character::do_west, POS_STANDING, 0},
  {"up", &Character::do_up, POS_STANDING, 0},
  {"down", &Character::do_down, POS_STANDING, 0},

  /*
   * Common other commands.
   * Placed here so one and two letter abbreviations work.
   */
  {"buy", &Character::do_buy, POS_RESTING, 0},
  {"cast", &Character::do_cast, POS_FIGHTING, 0},
  {"exits", &Character::do_exits, POS_RESTING, 0},
  {"get", &Character::do_get, POS_RESTING, 0},
  {"inventory", &Character::do_inventory, POS_DEAD, 0},
  {"kill", &Character::do_kill, POS_FIGHTING, 0},
  {"look", &Character::do_look, POS_RESTING, 0},
  {"order", &Character::do_order, POS_RESTING, 0},
  {"rest", &Character::do_rest, POS_RESTING, 0},
  {"sleep", &Character::do_sleep, POS_SLEEPING, 0},
  {"stand", &Character::do_stand, POS_SLEEPING, 0},
  {"tell", &Character::do_tell, POS_RESTING, 0},
  {"wield", &Character::do_wear, POS_RESTING, 0},
  {"wizhelp", &Character::do_wizhelp, POS_DEAD, L_HER},

  /*
   * Informational commands.
   */
  {"areas", &Character::do_areas, POS_DEAD, 0},
  {"bug", &Character::do_bug, POS_DEAD, 0},
  {"commands", &Character::do_commands, POS_DEAD, 0},
  {"compare", &Character::do_compare, POS_RESTING, 0},
  {"consider", &Character::do_consider, POS_RESTING, 0},
  {"credits", &Character::do_credits, POS_DEAD, 0},
  {"equipment", &Character::do_equipment, POS_DEAD, 0},
  {"examine", &Character::do_examine, POS_RESTING, 0},
  {"help", &Character::do_help, POS_DEAD, 0},
  {"idea", &Character::do_idea, POS_DEAD, 0},
  {"report", &Character::do_report, POS_DEAD, 0},
  {"pagelength", &Character::do_pagelen, POS_DEAD, 0},
  {"score", &Character::do_score, POS_DEAD, 0},
  {"slist", &Character::do_slist, POS_DEAD, 0},
  {"socials", &Character::do_socials, POS_DEAD, 0},
  {"time", &Character::do_time, POS_DEAD, 0},
  {"typo", &Character::do_typo, POS_DEAD, 0},
  {"weather", &Character::do_weather, POS_RESTING, 0},
  {"who", &Character::do_who, POS_DEAD, 0},
  {"wizlist", &Character::do_wizlist, POS_DEAD, 0},

  /*
   * Configuration commands.
   */
  {"auto", &Character::do_auto, POS_DEAD, 0},
  {"autoexit", &Character::do_autoexit, POS_DEAD, 0},
  {"autoloot", &Character::do_autoloot, POS_DEAD, 0},
  {"autosac", &Character::do_autosac, POS_DEAD, 0},
  {"blank", &Character::do_blank, POS_DEAD, 0},
  {"brief", &Character::do_brief, POS_DEAD, 0},
  {"channels", &Character::do_channels, POS_DEAD, 0},
  {"combine", &Character::do_combine, POS_DEAD, 0},
  {"config", &Character::do_config, POS_DEAD, 0},
  {"description", &Character::do_description, POS_DEAD, 0},
  {"password", &Character::do_password, POS_DEAD, 0},
  {"prompt", &Character::do_prompt, POS_DEAD, 0},
  {"title", &Character::do_title, POS_DEAD, 0},
  {"wimpy", &Character::do_wimpy, POS_DEAD, 0},

  /*
   * Communication commands.
   */
  {"answer", &Character::do_answer, POS_SLEEPING, 0},
  {"auction", &Character::do_auction, POS_SLEEPING, 0},
  {"chat", &Character::do_chat, POS_SLEEPING, 0},
  {".", &Character::do_chat, POS_SLEEPING, 0},
  {"emote", &Character::do_emote, POS_RESTING, 0},
  {",", &Character::do_emote, POS_RESTING, 0},
  {"gtell", &Character::do_gtell, POS_DEAD, 0},
  {";", &Character::do_gtell, POS_DEAD, 0},
  {"music", &Character::do_music, POS_SLEEPING, 0},
  {"note", &Character::do_note, POS_SLEEPING, 0},
  {"question", &Character::do_question, POS_SLEEPING, 0},
  {"reply", &Character::do_reply, POS_RESTING, 0},
  {"say", &Character::do_say, POS_RESTING, 0},
  {"'", &Character::do_say, POS_RESTING, 0},
  {"shout", &Character::do_shout, POS_RESTING, 3},
  {"yell", &Character::do_yell, POS_RESTING, 0},

  /*
   * Object manipulation commands.
   */
  {"brandish", &Character::do_brandish, POS_RESTING, 0},
  {"close", &Character::do_close, POS_RESTING, 0},
  {"drink", &Character::do_drink, POS_RESTING, 0},
  {"drop", &Character::do_drop, POS_RESTING, 0},
  {"eat", &Character::do_eat, POS_RESTING, 0},
  {"fill", &Character::do_fill, POS_RESTING, 0},
  {"give", &Character::do_give, POS_RESTING, 0},
  {"hold", &Character::do_wear, POS_RESTING, 0},
  {"list", &Character::do_list, POS_RESTING, 0},
  {"lock", &Character::do_lock, POS_RESTING, 0},
  {"open", &Character::do_open, POS_RESTING, 0},
  {"pick", &Character::do_pick, POS_RESTING, 0},
  {"put", &Character::do_put, POS_RESTING, 0},
  {"quaff", &Character::do_quaff, POS_RESTING, 0},
  {"recite", &Character::do_recite, POS_RESTING, 0},
  {"remove", &Character::do_remove, POS_RESTING, 0},
  {"sell", &Character::do_sell, POS_RESTING, 0},
  {"take", &Character::do_get, POS_RESTING, 0},
  {"sacrifice", &Character::do_sacrifice, POS_RESTING, 0},
  {"unlock", &Character::do_unlock, POS_RESTING, 0},
  {"value", &Character::do_value, POS_RESTING, 0},
  {"wear", &Character::do_wear, POS_RESTING, 0},
  {"zap", &Character::do_zap, POS_RESTING, 0},

  /*
   * Combat commands.
   */
  {"backstab", &Character::do_backstab, POS_STANDING, 0},
  {"bs", &Character::do_backstab, POS_STANDING, 0},
  {"disarm", &Character::do_disarm, POS_FIGHTING, 0},
  {"flee", &Character::do_flee, POS_FIGHTING, 0},
  {"kick", &Character::do_kick, POS_FIGHTING, 0},
  {"murde", &Character::do_murde, POS_FIGHTING, 5},
  {"murder", &Character::do_murder, POS_FIGHTING, 5},
  {"rescue", &Character::do_rescue, POS_FIGHTING, 0},

  /*
   * Miscellaneous commands.
   */
  {"follow", &Character::do_follow, POS_RESTING, 0},
  {"group", &Character::do_group, POS_SLEEPING, 0},
  {"hide", &Character::do_hide, POS_RESTING, 0},
  {"practice", &Character::do_practice, POS_SLEEPING, 0},
  {"qui", &Character::do_qui, POS_DEAD, 0},
  {"quit", &Character::do_quit, POS_DEAD, 0},
  {"recall", &Character::do_recall, POS_FIGHTING, 0},
  {"/", &Character::do_recall, POS_FIGHTING, 0},
  {"rent", &Character::do_rent, POS_DEAD, 0},
  {"save", &Character::do_save, POS_DEAD, 0},
  {"sleep", &Character::do_sleep, POS_SLEEPING, 0},
  {"sneak", &Character::do_sneak, POS_STANDING, 0},
  {"spells", &Character::do_spells, POS_SLEEPING, 0},
  {"split", &Character::do_split, POS_RESTING, 0},
  {"steal", &Character::do_steal, POS_STANDING, 0},
  {"train", &Character::do_train, POS_RESTING, 0},
  {"visible", &Character::do_visible, POS_SLEEPING, 0},
  {"wake", &Character::do_wake, POS_SLEEPING, 0},
  {"where", &Character::do_where, POS_RESTING, 0},

  /*
   * Immortal commands.
   */
  {"advance", &Character::do_advance, POS_DEAD, L_GOD},
  {"trust", &Character::do_trust, POS_DEAD, L_GOD},

  {"allow", &Character::do_allow, POS_DEAD, L_SUP},
  {"ban", &Character::do_ban, POS_DEAD, L_SUP},
  {"deny", &Character::do_deny, POS_DEAD, L_SUP},
  {"disconnect", &Character::do_disconnect, POS_DEAD, L_SUP},
  {"freeze", &Character::do_freeze, POS_DEAD, L_SUP},
  {"reboo", &Character::do_reboo, POS_DEAD, L_SUP},
  {"reboot", &Character::do_reboot, POS_DEAD, L_SUP},
  {"shutdow", &Character::do_shutdow, POS_DEAD, L_SUP},
  {"shutdown", &Character::do_shutdown, POS_DEAD, L_SUP},
  {"users", &Character::do_users, POS_DEAD, L_SUP},
  {"wizify", &Character::do_wizify, POS_DEAD, L_SUP},
  {"wizlock", &Character::do_wizlock, POS_DEAD, L_SUP},

  {"force", &Character::do_force, POS_DEAD, L_DEI},
  {"mload", &Character::do_mload, POS_DEAD, L_DEI},
  {"mset", &Character::do_mset, POS_DEAD, L_DEI},
  {"noemote", &Character::do_noemote, POS_DEAD, L_DEI},
  {"notell", &Character::do_notell, POS_DEAD, L_DEI},
  {"oload", &Character::do_oload, POS_DEAD, L_DEI},
  {"oset", &Character::do_oset, POS_DEAD, L_DEI},
  {"owhere", &Character::do_owhere, POS_DEAD, L_DEI},
  {"pardon", &Character::do_pardon, POS_DEAD, L_DEI},
  {"peace", &Character::do_peace, POS_DEAD, L_DEI},
  {"purge", &Character::do_purge, POS_DEAD, L_DEI},
  {"restore", &Character::do_restore, POS_DEAD, L_DEI},
  {"rset", &Character::do_rset, POS_DEAD, L_DEI},
  {"silence", &Character::do_silence, POS_DEAD, L_DEI},
  {"sla", &Character::do_sla, POS_DEAD, L_DEI},
  {"slay", &Character::do_slay, POS_DEAD, L_DEI},
  {"sset", &Character::do_sset, POS_DEAD, L_DEI},
  {"transfer", &Character::do_transfer, POS_DEAD, L_DEI},
  {"mpstat", &Character::do_mpstat, POS_DEAD, L_DEI},

  {"at", &Character::do_at, POS_DEAD, L_ANG},
  {"bamfin", &Character::do_bamfin, POS_DEAD, L_ANG},
  {"bamfout", &Character::do_bamfout, POS_DEAD, L_ANG},
  {"echo", &Character::do_echo, POS_DEAD, L_ANG},
  {"goto", &Character::do_goto, POS_DEAD, L_ANG},
  {"holylight", &Character::do_holylight, POS_DEAD, L_ANG},
  {"invis", &Character::do_invis, POS_DEAD, L_ANG},
  {"memory", &Character::do_memory, POS_DEAD, L_ANG},
  {"mfind", &Character::do_mfind, POS_DEAD, L_ANG},
  {"mstat", &Character::do_mstat, POS_DEAD, L_ANG},
  {"mwhere", &Character::do_mwhere, POS_DEAD, L_ANG},
  {"ofind", &Character::do_ofind, POS_DEAD, L_ANG},
  {"ostat", &Character::do_ostat, POS_DEAD, L_ANG},
  {"recho", &Character::do_recho, POS_DEAD, L_ANG},
  {"return", &Character::do_return, POS_DEAD, L_ANG},
  {"rstat", &Character::do_rstat, POS_DEAD, L_ANG},
  {"slookup", &Character::do_slookup, POS_DEAD, L_ANG},
  {"switch", &Character::do_switch, POS_DEAD, L_ANG},

  {"immtalk", &Character::do_immtalk, POS_DEAD, L_ANG},
  {":", &Character::do_immtalk, POS_DEAD, L_ANG},

  /*
   * MOBprogram commands.
   */
  {"mpasound", &Character::do_mpasound, POS_DEAD, 41},
  {"mpjunk", &Character::do_mpjunk, POS_DEAD, 41},
  {"mpecho", &Character::do_mpecho, POS_DEAD, 41},
  {"mpechoat", &Character::do_mpechoat, POS_DEAD, 41},
  {"mpechoaround", &Character::do_mpechoaround, POS_DEAD, 41},
  {"mpkill", &Character::do_mpkill, POS_DEAD, 41},
  {"mpmload", &Character::do_mpmload, POS_DEAD, 41},
  {"mpoload", &Character::do_mpoload, POS_DEAD, 41},
  {"mppurge", &Character::do_mppurge, POS_DEAD, 41},
  {"mpgoto", &Character::do_mpgoto, POS_DEAD, 41},
  {"mpat", &Character::do_mpat, POS_DEAD, 41},
  {"mptransfer", &Character::do_mptransfer, POS_DEAD, 41},
  {"mpforce", &Character::do_mpforce, POS_DEAD, 41},

  /*
   * End of list.
   */
  {"", 0, POS_DEAD, 0}
};

/*
 * The skill and spell table.
 * Slot numbers must never be changed as they appear in #OBJECTS sections.
 * Skills include spells as a particular case.
 */
typedef void (Character::*spellfun_T) (int sn, int lvl, void *vo);

const struct skill_type {
  const char * name;                   /* Name of skill        */
  sh_int skill_level[CLASS_MAX];        /* Level needed by class    */
  spellfun_T spell_fun;         /* Spell pointer (for spells)   */
  sh_int target;                /* Legal targets        */
  sh_int minimum_position;      /* Position for caster / user   */
  sh_int *pgsn;                 /* Pointer to associated gsn    */
  sh_int slot;                  /* Slot for #OBJECT loading */
  int min_mana;              /* Minimum mana used        */
  int beats;                 /* Waiting time after use   */
  const char * noun_damage;            /* Damage message       */
  const char * msg_off;                /* Wear off message     */
} skill_table[MAX_SKILL] = {

/*
 * Magic spells.
 */

  {   "reserved", {99, 99, 99, 99},
      NULL, TAR_IGNORE, POS_STANDING,
      NULL, 0, 0, 0, "", ""},
  {   "acid blast", {20, 37, 37, 37},
      &Character::spell_acid_blast, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 70, 20, 12, "acid blast", "!Acid Blast!"},
  {   "armor", {5, 1, 37, 37},
      &Character::spell_armor, TAR_CHAR_DEFENSIVE, POS_STANDING,
      NULL, 1, 5, 12, "", "You feel less protected."},
  {   "bless", {37, 5, 37, 37},
      &Character::spell_bless, TAR_CHAR_DEFENSIVE, POS_STANDING,
      NULL, 3, 5, 12, "", "You feel less righteous."},
  {   "blindness", {8, 5, 37, 37},
      &Character::spell_blindness, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      &gsn_blindness, 4, 5, 12, "", "You can see again."},
  {   "burning hands", {5, 37, 37, 37},
      &Character::spell_burning_hands, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 5, 15, 12, "burning hands", "!Burning Hands!"},
  {   "call lightning", {37, 12, 37, 37},
      &Character::spell_call_lightning, TAR_IGNORE, POS_FIGHTING,
      NULL, 6, 15, 12, "lightning bolt", "!Call Lightning!"},
  {   "cause critical", {37, 9, 37, 37},
      &Character::spell_cause_critical, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 63, 20, 12, "spell", "!Cause Critical!"},
  {   "cause light", {37, 1, 37, 37},
      &Character::spell_cause_light, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 62, 15, 12, "spell", "!Cause Light!"},
  {   "cause serious", {37, 5, 37, 37},
      &Character::spell_cause_serious, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 64, 17, 12, "spell", "!Cause Serious!"},
  {   "change sex", {37, 37, 37, 37},
      &Character::spell_change_sex, TAR_CHAR_DEFENSIVE, POS_FIGHTING,
      NULL, 82, 15, 12, "", "Your body feels familiar again."},
  {   "charm person", {14, 37, 37, 37},
      &Character::spell_charm_person, TAR_CHAR_OFFENSIVE, POS_STANDING,
      &gsn_charm_person, 7, 5, 12, "", "You feel more self-confident."},
  {   "chill touch", {3, 37, 37, 37},
      &Character::spell_chill_touch, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 8, 15, 12, "chilling touch", "You feel less cold."},
  {   "colour spray", {11, 37, 37, 37},
      &Character::spell_colour_spray, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 10, 15, 12, "colour spray", "!Colour Spray!"},
  {   "continual light", {4, 2, 37, 37},
      &Character::spell_continual_light, TAR_IGNORE, POS_STANDING,
      NULL, 57, 7, 12, "", "!Continual Light!"},
  {   "control weather", {10, 13, 37, 37},
      &Character::spell_control_weather, TAR_IGNORE, POS_STANDING,
      NULL, 11, 25, 12, "", "!Control Weather!"},
  {   "create food", {37, 3, 37, 37},
      &Character::spell_create_food, TAR_IGNORE, POS_STANDING,
      NULL, 12, 5, 12, "", "!Create Food!"},
  {   "create spring", {10, 37, 37, 37},
      &Character::spell_create_spring, TAR_IGNORE, POS_STANDING,
      NULL, 80, 20, 12, "", "!Create Spring!"},
  {   "create water", {37, 2, 37, 37},
      &Character::spell_create_water, TAR_OBJ_INV, POS_STANDING,
      NULL, 13, 5, 12, "", "!Create Water!"},
  {   "cure blindness", {37, 4, 37, 37},
      &Character::spell_cure_blindness, TAR_CHAR_DEFENSIVE, POS_FIGHTING,
      NULL, 14, 5, 12, "", "!Cure Blindness!"},
  {   "cure critical", {37, 9, 37, 37},
      &Character::spell_cure_critical, TAR_CHAR_DEFENSIVE, POS_FIGHTING,
      NULL, 15, 20, 12, "", "!Cure Critical!"},
  {   "cure light", {37, 1, 37, 37},
      &Character::spell_cure_light, TAR_CHAR_DEFENSIVE, POS_FIGHTING,
      NULL, 16, 10, 12, "", "!Cure Light!"},
  {   "cure poison", {37, 9, 37, 37},
      &Character::spell_cure_poison, TAR_CHAR_DEFENSIVE, POS_STANDING,
      NULL, 43, 5, 12, "", "!Cure Poison!"},
  {   "cure serious", {37, 5, 37, 37},
      &Character::spell_cure_serious, TAR_CHAR_DEFENSIVE, POS_FIGHTING,
      NULL, 61, 15, 12, "", "!Cure Serious!"},
  {   "curse", {12, 12, 37, 37},
      &Character::spell_curse, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      &gsn_curse, 17, 20, 12, "curse", "The curse wears off."},
  {   "detect evil", {37, 4, 37, 37},
      &Character::spell_detect_evil, TAR_CHAR_SELF, POS_STANDING,
      NULL, 18, 5, 12, "", "The red in your vision disappears."},
  {   "detect hidden", {37, 7, 37, 37},
      &Character::spell_detect_hidden, TAR_CHAR_SELF, POS_STANDING,
      NULL, 44, 5, 12, "", "You feel less aware of your suroundings."},
  {   "detect invis", {2, 5, 37, 37},
      &Character::spell_detect_invis, TAR_CHAR_SELF, POS_STANDING,
      NULL, 19, 5, 12, "", "You no longer see invisible objects."},
  {   "detect magic", {2, 3, 37, 37},
      &Character::spell_detect_magic, TAR_CHAR_SELF, POS_STANDING,
      NULL, 20, 5, 12, "", "The detect magic wears off."},
  {   "detect poison", {37, 5, 37, 37},
      &Character::spell_detect_poison, TAR_OBJ_INV, POS_STANDING,
      NULL, 21, 5, 12, "", "!Detect Poison!"},
  {   "dispel evil", {37, 10, 37, 37},
      &Character::spell_dispel_evil, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 22, 15, 12, "dispel evil", "!Dispel Evil!"},
  {   "dispel magic", {26, 31, 37, 37},
      &Character::spell_dispel_magic, TAR_CHAR_OFFENSIVE, POS_STANDING,
      NULL, 59, 15, 12, "", "!Dispel Magic!"},
  {   "earthquake", {37, 7, 37, 37},
      &Character::spell_earthquake, TAR_IGNORE, POS_FIGHTING,
      NULL, 23, 15, 12, "earthquake", "!Earthquake!"},
  {   "enchant weapon", {12, 37, 37, 37},
      &Character::spell_enchant_weapon, TAR_OBJ_INV, POS_STANDING,
      NULL, 24, 100, 24, "", "!Enchant Weapon!"},
  {   "energy drain", {13, 37, 37, 37},
      &Character::spell_energy_drain, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 25, 35, 12, "energy drain", "!Energy Drain!"},
  {   "faerie fire", {4, 2, 37, 37},
      &Character::spell_faerie_fire, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 72, 5, 12, "faerie fire", "The pink aura around you fades away."},
  {   "faerie fog", {10, 14, 37, 37},
      &Character::spell_faerie_fog, TAR_IGNORE, POS_STANDING,
      NULL, 73, 12, 12, "faerie fog", "!Faerie Fog!"},
  {   "fireball", {15, 37, 37, 37},
      &Character::spell_fireball, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 26, 15, 12, "fireball", "!Fireball!"},
  {   "flamestrike", {37, 13, 37, 37},
      &Character::spell_flamestrike, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 65, 20, 12, "flamestrike", "!Flamestrike!"},
  {   "fly", {7, 12, 37, 37},
      &Character::spell_fly, TAR_CHAR_DEFENSIVE, POS_STANDING,
      NULL, 56, 10, 18, "", "You slowly float to the ground."},
  {   "gate", {37, 37, 37, 37},
      &Character::spell_gate, TAR_CHAR_DEFENSIVE, POS_FIGHTING,
      NULL, 83, 50, 12, "", "!Gate!"},
  {   "giant strength", {7, 37, 37, 37},
      &Character::spell_giant_strength, TAR_CHAR_DEFENSIVE, POS_STANDING,
      NULL, 39, 20, 12, "", "You feel weaker."},
  {   "harm", {37, 15, 37, 37},
      &Character::spell_harm, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 27, 35, 12, "harm spell", "!Harm!"},
  {   "heal", {37, 14, 37, 37},
      &Character::spell_heal, TAR_CHAR_DEFENSIVE, POS_FIGHTING,
      NULL, 28, 50, 12, "", "!Heal!"},
  {   "identify", {10, 10, 37, 37},
      &Character::spell_identify, TAR_OBJ_INV, POS_STANDING,
      NULL, 53, 12, 24, "", "!Identify!"},
  {   "infravision", {6, 9, 37, 37},
      &Character::spell_infravision, TAR_CHAR_DEFENSIVE, POS_STANDING,
      NULL, 77, 5, 18, "", "You no longer see in the dark."},
  {   "invis", {4, 37, 37, 37},
      &Character::spell_invis, TAR_CHAR_DEFENSIVE, POS_STANDING,
      &gsn_invis, 29, 5, 12, "", "You are no longer invisible."},
  {   "know alignment", {8, 5, 37, 37},
      &Character::spell_know_alignment, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 58, 9, 12, "", "!Know Alignment!"},
  {   "lightning bolt", {9, 37, 37, 37},
      &Character::spell_lightning_bolt, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 30, 15, 12, "lightning bolt", "!Lightning Bolt!"},
  {   "locate object", {6, 10, 37, 37},
      &Character::spell_locate_object, TAR_IGNORE, POS_STANDING,
      NULL, 31, 20, 18, "", "!Locate Object!"},
  {   "magic missile", {1, 37, 37, 37},
      &Character::spell_magic_missile, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 32, 15, 12, "magic missile", "!Magic Missile!"},
  {   "mass invis", {15, 17, 37, 37},
      &Character::spell_mass_invis, TAR_IGNORE, POS_STANDING,
      &gsn_mass_invis, 69, 20, 24, "", "!Mass Invis!"},
  {   "pass door", {18, 37, 37, 37},
      &Character::spell_pass_door, TAR_CHAR_SELF, POS_STANDING,
      NULL, 74, 20, 12, "", "You feel solid again."},
  {   "poison", {37, 8, 37, 37},
      &Character::spell_poison, TAR_CHAR_OFFENSIVE, POS_STANDING,
      &gsn_poison, 33, 10, 12, "poison", "You feel less sick."},
  {   "protection", {37, 6, 37, 37},
      &Character::spell_protection, TAR_CHAR_SELF, POS_STANDING,
      NULL, 34, 5, 12, "", "You feel less protected."},
  {   "refresh", {5, 3, 37, 37},
      &Character::spell_refresh, TAR_CHAR_DEFENSIVE, POS_STANDING,
      NULL, 81, 12, 18, "refresh", "!Refresh!"},
  {   "remove curse", {37, 12, 37, 37},
      &Character::spell_remove_curse, TAR_CHAR_DEFENSIVE, POS_STANDING,
      NULL, 35, 5, 12, "", "!Remove Curse!"},
  {   "sanctuary", {37, 13, 37, 37},
      &Character::spell_sanctuary, TAR_CHAR_DEFENSIVE, POS_STANDING,
      NULL, 36, 75, 12, "", "The white aura around your body fades."},
  {   "shield", {13, 37, 37, 37},
      &Character::spell_shield, TAR_CHAR_DEFENSIVE, POS_STANDING,
      NULL, 67, 12, 18, "", "Your force shield shimmers then fades away."},
  {   "shocking grasp", {7, 37, 37, 37},
      &Character::spell_shocking_grasp, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 37, 15, 12, "shocking grasp", "!Shocking Grasp!"},
  {   "sleep", {14, 37, 37, 37},
      &Character::spell_sleep, TAR_CHAR_OFFENSIVE, POS_STANDING,
      &gsn_sleep, 38, 15, 12, "", "You feel less tired."},
  {   "stone skin", {17, 37, 37, 37},
      &Character::spell_stone_skin, TAR_CHAR_SELF, POS_STANDING,
      NULL, 66, 12, 18, "", "Your skin feels soft again."},
  {   "summon", {37, 8, 37, 37},
      &Character::spell_summon, TAR_IGNORE, POS_STANDING,
      NULL, 40, 50, 12, "", "!Summon!"},
  {   "teleport", {8, 37, 37, 37},
      &Character::spell_teleport, TAR_CHAR_SELF, POS_FIGHTING,
      NULL, 2, 35, 12, "", "!Teleport!"},
  {   "ventriloquate", {1, 37, 37, 37},
      &Character::spell_ventriloquate, TAR_IGNORE, POS_STANDING,
      NULL, 41, 5, 12, "", "!Ventriloquate!"},
  {   "weaken", {7, 37, 37, 37},
      &Character::spell_weaken, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 68, 20, 12, "spell", "You feel stronger."},
  {   "word of recall", {37, 37, 37, 37},
      &Character::spell_word_of_recall, TAR_CHAR_SELF, POS_RESTING,
      NULL, 42, 5, 12, "", "!Word of Recall!"},
/*
 * Dragon breath
 */
  {   "acid breath", {33, 37, 37, 37},
      &Character::spell_acid_breath, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 200, 0, 4, "blast of acid", "!Acid Breath!"},
  {   "fire breath", {34, 37, 37, 37},
      &Character::spell_fire_breath, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 201, 0, 4, "blast of flame", "!Fire Breath!"},
  {   "frost breath", {31, 37, 37, 37},
      &Character::spell_frost_breath, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 202, 0, 4, "blast of frost", "!Frost Breath!"},
  {   "gas breath", {35, 37, 37, 37},
      &Character::spell_gas_breath, TAR_IGNORE, POS_FIGHTING,
      NULL, 203, 0, 4, "blast of gas", "!Gas Breath!"},
  {   "lightning breath", {32, 37, 37, 37},
      &Character::spell_lightning_breath, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 204, 0, 4, "blast of lightning", "!Lightning Breath!"},
/*
 * Fighter and thief skills.
 */
  {   "backstab", {37, 37, 1, 37},
      &Character::spell_null, TAR_IGNORE, POS_STANDING,
      &gsn_backstab, 0, 0, 24, "backstab", "!Backstab!"},
  {   "disarm", {37, 37, 10, 37},
      &Character::spell_null, TAR_IGNORE, POS_FIGHTING,
      &gsn_disarm, 0, 0, 24, "", "!Disarm!"},
  {   "dodge", {37, 37, 1, 37},
      &Character::spell_null, TAR_IGNORE, POS_FIGHTING,
      &gsn_dodge, 0, 0, 0, "", "!Dodge!"},
  {   "enhanced damage", {37, 37, 37, 1},
      &Character::spell_null, TAR_IGNORE, POS_FIGHTING,
      &gsn_enhanced_damage, 0, 0, 0, "", "!Enhanced Damage!"},
  {   "hide", {37, 37, 1, 37},
      &Character::spell_null, TAR_IGNORE, POS_RESTING,
      &gsn_hide, 0, 0, 12, "", "!Hide!"},
  {   "kick", {37, 37, 37, 1},
      &Character::spell_null, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      &gsn_kick, 0, 0, 8, "kick", "!Kick!"},
  {   "parry", {37, 37, 37, 1},
      &Character::spell_null, TAR_IGNORE, POS_FIGHTING,
      &gsn_parry, 0, 0, 0, "", "!Parry!"},
  {   "peek", {37, 37, 1, 37},
      &Character::spell_null, TAR_IGNORE, POS_STANDING,
      &gsn_peek, 0, 0, 0, "", "!Peek!"},
  {   "pick lock", {37, 37, 1, 37},
      &Character::spell_null, TAR_IGNORE, POS_STANDING,
      &gsn_pick_lock, 0, 0, 12, "", "!Pick!"},
  {   "rescue", {37, 37, 37, 1},
      &Character::spell_null, TAR_IGNORE, POS_FIGHTING,
      &gsn_rescue, 0, 0, 12, "", "!Rescue!"},
  {   "second attack", {37, 37, 1, 1},
      &Character::spell_null, TAR_IGNORE, POS_FIGHTING,
      &gsn_second_attack, 0, 0, 0, "", "!Second Attack!"},
  {   "sneak", {37, 37, 1, 37},
      &Character::spell_null, TAR_IGNORE, POS_STANDING,
      &gsn_sneak, 0, 0, 12, "", NULL},
  {   "steal", {37, 37, 1, 37},
      &Character::spell_null, TAR_IGNORE, POS_STANDING,
      &gsn_steal, 0, 0, 24, "", "!Steal!"},
  {   "third attack", {37, 37, 37, 1},
      &Character::spell_null, TAR_IGNORE, POS_FIGHTING,
      &gsn_third_attack, 0, 0, 0, "", "!Third Attack!"},
/*
 *  Spells for mega1.are from Glop/Erkenbrand.
*/
  {   "general purpose", {37, 37, 37, 37},
      &Character::spell_general_purpose, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 205, 0, 12, "general purpose ammo", "!General Purpose Ammo!"},
  {   "high explosive", {37, 37, 37, 37},
      &Character::spell_high_explosive, TAR_CHAR_OFFENSIVE, POS_FIGHTING,
      NULL, 206, 0, 12, "high explosive ammo", "!High Explosive Ammo!"}
};

///////////////////
// start of code //
///////////////////

/* The heart of the pager.  Thanks to N'Atas-Ha, ThePrincedom
   for porting this SillyMud code for MERC 2.0 and laying down the groundwork.
   Thanks to Blackstar, hopper.cs.uiowa.edu 4000 for which
   the improvements to the pager was modeled from.  - Kahn */
void Descriptor::show_string (const std::string & input) {
  char buffer[MAX_STRING_LENGTH];
  std::string buf;
  register char *scan, *chk;
  int lines = 0, toggle = 1;

  one_argument (input, buf);
  incomm.erase();

  if (!buf.empty()) {
    switch (toupper (buf[0])) {
    case 'C':                    /* show next page of text */
      lines = 0;
      break;

    case 'R':                    /* refresh current page of text */
      lines = -1 - (character->pcdata->pagelen);
      break;

    case 'B':                    /* scroll back a page of text */
      lines = -(2 * character->pcdata->pagelen);
      break;

    case 'H':                    /* Show some help */
      write_to_buffer ("C, or Return = continue, R = redraw this page,\r\n");
      write_to_buffer (
        "B = back one page, H = this help, Q or other keys = exit.\r\n\r\n");
      lines = -1 - (character->pcdata->pagelen);
      break;

    default:                     /*otherwise, stop the text viewing */
      if (showstr_head) {
        free(showstr_head);
        showstr_head = NULL;
      }
      showstr_point = 0;
      return;

    }
  }

  /* do any backing up necessary */
  if (lines < 0) {
    for (scan = showstr_point; scan > showstr_head; scan--)
      if ((*scan == '\n') || (*scan == '\r')) {
        toggle = -toggle;
        if (toggle < 0)
          if (!(++lines))
            break;
      }
    showstr_point = scan;
  }

  /* show a chunk */
  lines = 0;
  toggle = 1;
  for (scan = buffer;; scan++, showstr_point++) {
    *scan = *showstr_point;
    if ((*scan == '\n' || *scan == '\r') && (toggle = -toggle) < 0) {
      lines++;
    } else if (!*scan || (character && !character->is_npc ()
        && lines >= character->pcdata->pagelen)) {

      *scan = '\0';
      write_to_buffer (buffer);

      /* See if this is the end (or near the end) of the string */
      for (chk = showstr_point; isspace (*chk); chk++);
      if (!*chk) {
        if (showstr_head) {
          free(showstr_head);
          showstr_head = NULL;
        }
        showstr_point = 0;
      }
      return;
    }
  }
}

/*
 * Generate a random number in an inclusive range.
 */
int number_range (int from, int to)
{
  if (to <= from)
    return from;
  return (from + (OS_RAND () % (1 + to - from)));
}

/*
 * Stick a little fuzz on a number.
 */
int number_fuzzy (int number)
{
  switch (number_range (0, 3)) {
  case 0:
    number -= 1;
    break;
  case 3:
    number += 1;
    break;
  }

  return std::max (1, number);
}

/*
 * Roll some dice.
 */
int dice (int number, int size)
{
  int idice;
  int sum;

  switch (size) {
  case 0:
    return 0;
  case 1:
    return number;
  }

  for (idice = 0, sum = 0; idice < number; idice++)
    sum += number_range (1, size);

  return sum;
}

/*
 * Generate a percentile roll.
 */
int number_percent (void)
{
  return number_range (1, 100);
}

/*
 * Generate a random door.
 */
int number_door (void)
{
  return number_range (0, 5);
}

/*
 * Simple linear interpolation.
 */
int interpolate (int level, int value_00, int value_32)
{
  return value_00 + level * (value_32 - value_00) / 32;
}

/*
print a series of warnings - do not exit
*/
/* VARARGS */
void log_printf (const char * str, ...) {
  char buf[MAX_STRING_LENGTH];
  char *strtime;
  va_list args;

  strtime = ctime (&current_time);
  strtime[strlen (strtime) - 1] = '\0';

  va_start (args, str);
  vsnprintf (buf, sizeof buf, str, args);
  va_end (args);

  std::cerr << strtime << " :: " << buf << std::endl;
  return;
}

/*
 * Reports a bug.
 */
void bug_printf (const char * str, ...)
{
  char buf[MAX_STRING_LENGTH];
  std::ofstream fp;
  va_list args;

  if (fpArea != NULL) {
    int iLine;
    std::ifstream::pos_type iChar;

    iChar = fpArea->tellg();
    fpArea->seekg(0);
    for (iLine = 0; fpArea->tellg() < iChar; iLine++) {
      while (fpArea->get() != '\n');
    }
    fpArea->seekg(iChar);

    snprintf (buf, sizeof buf, "[*****] FILE: %s LINE: %d", strArea.c_str(), iLine);
    log_printf(buf);

    fp.open ("shutdown.txt", std::ofstream::out | std::ofstream::app | std::ofstream::binary);
    if (fp.is_open()) {
      fp << buf << std::endl;
      fp.close();
    }
  }

  char buf2[MAX_STRING_LENGTH];
  snprintf (buf2, sizeof buf2, "[*****] BUG: %s", str);
  va_start (args, str);
  vsnprintf (buf, sizeof buf, buf2, args);
  va_end (args);

  log_printf(buf);

  fp.open (BUG_FILE, std::ofstream::out | std::ofstream::app | std::ofstream::binary);
  if (fp.is_open()) {
    fp << buf << std::endl;
    fp.close();
  }
  return;
}

/*
 * Reports a bug.
 */
void fatal_printf (const char * str, ...)
{
  char buf[MAX_STRING_LENGTH];
  va_list args;

  va_start (args, str);
  vsnprintf (buf, sizeof buf, str, args);
  va_end (args);
  bug_printf (buf);
  WIN32CLEANUP
  sqlite3_close(database);
  abort();
  return;
}

// replaces all occurances of a s1 in str with s2
void global_replace (std::string & str, const std::string & s1, const std::string & s2)
{
  std::string::size_type pos = 0;

  try {
    while ((pos = str.find(s1, pos)) != std::string::npos) {
      str.replace(pos, s1.size(), s2);
      pos += s2.size();
    }
  } catch(...) {
    fatal_printf("global_replace: length error or maximum string size exceeded");
  }
}

/*
 * Removes the tildes from a string.
 * Used for player-entered strings that go into disk files.
 */
void smash_tilde (std::string & str)
{
  global_replace(str, "~", "-");
}

// Case insensitive compare
bool str_cmp(const std::string & s1, const std::string & s2)
{
  if (s1.size() != s2.size())
    return true;

  std::string::const_iterator p1 = s1.begin(), p2 = s2.begin();
  while(p1 != s1.end() && p2 != s2.end()) {
    if(tolower(*p1) != tolower(*p2))
      return true;
    p1++;
    p2++;
  }
  return false;
}

/*
 * Compare strings, case insensitive, for prefix matching.
 * Return true if s1 not a prefix of bstr
 *   (compatibility with historical functions).
 */
bool str_prefix(const std::string & s1, const std::string & s2)
{
  if (s1.size() > s2.size())
    return true;

  std::string::const_iterator p1 = s1.begin(), p2 = s2.begin();
  while(p1 != s1.end() && p2 != s2.end()) {
    if(tolower(*p1) != tolower(*p2))
      return true;
    p1++;
    p2++;
  }
  return false;
}

/*
 * Compare strings, case insensitive, for match anywhere.
 * Returns true is astr not part of bstr.
 *   (compatibility with historical functions).
 */
bool str_infix (const std::string & astr, const std::string & bstr)
{
  if (astr.empty())
    return false;

  int cmpsz = bstr.size() - astr.size();
  char c0 = tolower(astr[0]);

  for (int ichar = 0; ichar <= cmpsz; ichar++) {
    if (c0 == tolower(bstr[ichar]) && !str_prefix(astr, bstr.substr(ichar)))
      return false;
  }

  return true;
}

/*
 * Compare strings, case insensitive, for suffix matching.
 * Return true if astr not a suffix of bstr
 *   (compatibility with historical functions).
 */
bool str_suffix(const std::string& s1, const std::string& s2)
{
  if (s1.size() <= s2.size() && !str_cmp(s1, s2.substr(s2.size() - s1.size())))
    return false;
  else
    return true;
}

/*
 * Returns an initial-capped string.
 */
std::string capitalize (const std::string & str)
{
  std::string strcap;

  std::string::const_iterator p = str.begin();
  while(p != str.end()) {
    if (p == str.begin())
      strcap.append(1, (char)toupper(*p));
    else
      strcap.append(1, (char)tolower(*p));
    p++;
  }
  return strcap;
}

int Character::mana_cost(int sn) {
  if (is_npc())
    return 0;
  else
    return std::max(skill_table[sn].min_mana, 100 /
      (2 + level - skill_table[sn].skill_level[klass]));
}

/*
 * This function is here to aid in debugging.
 * If the last expression in a function is another function call,
 *   gcc likes to generate a JMP instead of a CALL.
 * This is called "tail chaining."
 * It hoses the debugger call stack for that call.
 * So I make this the last call in certain critical functions,
 *   where I really need the call stack to be right for debugging!
 *
 * If you don't understand this, then LEAVE IT ALONE.
 * Don't remove any calls to tail_chain anywhere.
 *
 * -- Furey
 */
void tail_chain (void)
{
  return;
}

/*
 * Read and allocate space for a string from a file.
 */
std::string fread_string (std::ifstream & fp)
{
  std::string str;
  char c;

  /*
   * Skip blanks.
   * Read first char.
   */
  do {
    c = fp.get();
  }
  while (isspace (c));

  if (c == '~')
    return str;

  for (;;) {
    /*
     * Back off the char type lookup,
     *   it was too dirty for portability.
     *   -- Furey
     */
    switch (c) {
    default:
      try {
        str.append(1, c);
      } catch(...) {
        fatal_printf ("Fread_string: Maximum string size exceeded.");
      }
      break;
    case EOF:
      fatal_printf ("Fread_string: EOF");
      break;
    case '\n':
      try {
        str.append("\n\r");
      } catch(...) {
        fatal_printf ("Fread_string: Maximum string size exceeded.");
      }
      break;
    case '\r':
      break;
    case '~':
      return str;
    }
    c = fp.get();
  }
}

/*
 * Read a letter from a file.
 */
char fread_letter (std::ifstream & fp)
{
  char c;

  do {
    c = fp.get();
  }
  while (isspace (c));

  return c;
}

/*
 * Read a number from a file.
 */
int fread_number (std::ifstream & fp)
{
  int number;
  bool sign;
  char c;

  do {
    c = fp.get();
  }
  while (isspace (c));

  number = 0;

  sign = false;
  if (c == '+') {
    c = fp.get();
  } else if (c == '-') {
    sign = true;
    c = fp.get();
  }

  if (!isdigit (c)) {
    fatal_printf ("Fread_number: bad format.");
  }

  while (isdigit (c)) {
    number = number * 10 + c - '0';
    c = fp.get();
  }

  if (sign)
    number = 0 - number;

  if (c == '|')
    number += fread_number (fp);
  else if (c != ' ')
    fp.unget();

  return number;
}

/*
 * Read to end of line (for comments).
 */
void fread_to_eol (std::ifstream & fp)
{
  char c;

  do {
    c = fp.get();
  }
  while (c != '\n' && c != '\r');

  do {
    c = fp.get();
  }
  while (c == '\n' || c == '\r');

  fp.unget();
  return;
}

/*
 * Read one word (into static buffer).
 */
std::string fread_word (std::ifstream & fp)
{
  static char word[MAX_INPUT_LENGTH];
  char *pword;
  char cEnd;

  do {
    cEnd = fp.get();
  }
  while (isspace (cEnd));

  if (cEnd == '\'' || cEnd == '"') {
    pword = word;
  } else {
    word[0] = cEnd;
    pword = word + 1;
    cEnd = ' ';
  }

  for (; pword < word + MAX_INPUT_LENGTH; pword++) {
    *pword = fp.get();
    if (cEnd == ' ' ? isspace (*pword) : *pword == cEnd) {
      if (cEnd == ' ')
        fp.unget();
      *pword = '\0';
      return std::string(word);
    }
  }

  fatal_printf ("Fread_word: word too long.");
  return NULL;
}

/*
 * Append onto an output buffer.
 */
void Descriptor::write_to_buffer (const std::string & txt) {
  /*
   * Initial \r\n if needed.
   */
  if (outbuf.empty() && !fcommand)
    outbuf = "\r\n";

  /*
   * Copy.
   */
  outbuf.append(txt);
  return;
}

/*
 * Lowest level output function.
 * Write a block of text to the file descriptor.
 * If this gives errors on very long blocks (like 'ofind all'),
 *   try lowering the max block size.
 */
bool write_to_descriptor (SOCKET desc, const char *txt, int length)
{
  int iStart;
  int nWrite;
  int nBlock;

  if (length <= 0)
    length = strlen (txt);

  for (iStart = 0; iStart < length; iStart += nWrite) {
    nBlock = std::min (length - iStart, 4096);
    if ((nWrite = send (desc, txt + iStart, nBlock, 0)) == SOCKET_ERROR) {
      perror ("Write_to_descriptor");
      return false;
    }
  }

  return true;
}

/*
 * Return true if an argument is completely numeric.
 */
bool is_number (const std::string & arg)
{
  if (arg.empty())
    return false;

  std::string::const_iterator p = arg.begin();
  if (*p == '+' || *p == '-')
    p++;

  for (; p != arg.end(); p++) {
    if (!isdigit (*p))
      return false;
  }

  return true;
}

/*
 * Given a string like 14.foo, return 14 and 'foo'
 */
int number_argument (const std::string & argument, std::string & arg)
{
  std::string::size_type pos;

  arg.erase();
  if ((pos = argument.find(".")) != std::string::npos) {
    arg = argument.substr(pos+1);
    return atoi (argument.substr(0, pos).c_str());
  }
  arg = argument;
  return 1;
}

/*
 * Pick off one argument from a string and return the rest.
 * Understands quotes.
 */
std::string one_argument (const std::string & argument, std::string & arg_first)
{
  char cEnd;
  std::string::const_iterator argp = argument.begin();

  arg_first.erase();
  while (argp != argument.end() && isspace (*argp))
    argp++;

  cEnd = ' ';
  if (*argp == '\'' || *argp == '"')
    cEnd = *argp++;

  while (argp != argument.end()) {
    if (*argp == cEnd) {
      argp++;
      break;
    }
    arg_first.append(1, (char)tolower(*argp));
    argp++;
  }

  while (argp != argument.end() && isspace (*argp))
    argp++;

  return std::string(argp, argument.end());
}

/*
 * See if a string is one of the names of an object.
 */
/*
 * New is_name sent in by Alander.
 */
bool is_name (const std::string & str, std::string namelist)
{
  std::string name;

  for (;;) {
    namelist = one_argument (namelist, name);
    if (name.empty())
      return false;
    if (!str_cmp (str, name))
      return true;
  }
}

/*
 * Parse a name for acceptability.
 */
bool check_parse_name (const std::string & name)
{
  /*
   * Reserved words.
   */
  if (is_name (name, "all auto immortal self someone"))
    return false;

  /*
   * Length restrictions.
   */
  if (name.size() < 3 || name.size() > 12)
    return false;

  /*
   * Alphanumerics only.
   * Lock out IllIll twits.
   */
  std::string::const_iterator pc;
  bool fIll = true;
  for (pc = name.begin(); pc != name.end(); pc++) {
    if (!isalpha (*pc))
      return false;
    if (tolower (*pc) != 'i' && tolower (*pc) != 'l')
      fIll = false;
  }

  if (fIll)
    return false;

  /*
   * Prevent players from naming themselves after mobs.
   */
  std::map<int,MobPrototype*>::iterator pmob;
  for (pmob = mob_table.begin(); pmob != mob_table.end(); pmob++) {
    if (is_name (name, (*pmob).second->player_name))
      return false;
  }

  return true;
}

/*
 * Write to one char.
 */
void Character::send_to_char (const std::string & txt)
{
  if (txt.empty() || desc == NULL)
    return;
  desc->showstr_head = (char*)malloc(txt.size()+1);
  strncpy (desc->showstr_head, txt.c_str(), txt.size()+1);
  desc->showstr_point = desc->showstr_head;
  desc->show_string ("");

}

/*
 * Append a string to a file.
 */
void Character::append_file (char *file, const std::string & str)
{
  if (is_npc () || str.empty())
    return;

  char hdr[MAX_STRING_LENGTH];
  snprintf(hdr, sizeof hdr, "[%5d]", in_room ? in_room->vnum : 0);

  std::ofstream outfile;

  outfile.open (file, std::ofstream::out | std::ofstream::app | std::ofstream::binary);
  if (outfile.is_open()) {
    outfile << hdr << " " << name << ": " << str << std::endl;
    outfile.close();
  } else {
    perror (file);
    send_to_char ("Could not open the file!\r\n");
  }
  return;
}

/*
 * True if room is private.
 */
bool Room::is_private() {
  int count = people.size();

  if (IS_SET (room_flags, ROOM_PRIVATE) && count >= 2)
    return true;

  if (IS_SET (room_flags, ROOM_SOLITARY) && count >= 1)
    return true;

  return false;
}

/*
 * True if room is dark.
 */
bool Room::is_dark ()
{
  if (light > 0)
    return false;

  if (IS_SET (room_flags, ROOM_DARK))
    return true;

  if (sector_type == SECT_INSIDE || sector_type == SECT_CITY)
    return false;

  if (weather_info.sunlight == SUN_SET || weather_info.sunlight == SUN_DARK)
    return true;

  return false;
}

/*
 * Return ascii name of an item type.
 */
std::string Object::item_type_name ()
{
  switch (item_type) {
  case ITEM_LIGHT:
    return "light";
  case ITEM_SCROLL:
    return "scroll";
  case ITEM_WAND:
    return "wand";
  case ITEM_STAFF:
    return "staff";
  case ITEM_WEAPON:
    return "weapon";
  case ITEM_TREASURE:
    return "treasure";
  case ITEM_ARMOR:
    return "armor";
  case ITEM_POTION:
    return "potion";
  case ITEM_FURNITURE:
    return "furniture";
  case ITEM_TRASH:
    return "trash";
  case ITEM_CONTAINER:
    return "container";
  case ITEM_DRINK_CON:
    return "drink container";
  case ITEM_KEY:
    return "key";
  case ITEM_FOOD:
    return "food";
  case ITEM_MONEY:
    return "money";
  case ITEM_BOAT:
    return "boat";
  case ITEM_CORPSE_NPC:
    return "npc corpse";
  case ITEM_CORPSE_PC:
    return "pc corpse";
  case ITEM_FOUNTAIN:
    return "fountain";
  case ITEM_PILL:
    return "pill";
  }

  bug_printf ("Item_type_name: unknown type %d.", item_type);
  return "(unknown)";
}

/*
 * Return ascii name of an affect location.
 */
std::string affect_loc_name (int location)
{
  switch (location) {
  case APPLY_NONE:
    return "none";
  case APPLY_STR:
    return "strength";
  case APPLY_DEX:
    return "dexterity";
  case APPLY_INT:
    return "intelligence";
  case APPLY_WIS:
    return "wisdom";
  case APPLY_CON:
    return "constitution";
  case APPLY_SEX:
    return "sex";
  case APPLY_CLASS:
    return "class";
  case APPLY_LEVEL:
    return "level";
  case APPLY_AGE:
    return "age";
  case APPLY_MANA:
    return "mana";
  case APPLY_HIT:
    return "hp";
  case APPLY_MOVE:
    return "moves";
  case APPLY_GOLD:
    return "gold";
  case APPLY_EXP:
    return "experience";
  case APPLY_AC:
    return "armor class";
  case APPLY_HITROLL:
    return "hit roll";
  case APPLY_DAMROLL:
    return "damage roll";
  case APPLY_SAVING_PARA:
    return "save vs paralysis";
  case APPLY_SAVING_ROD:
    return "save vs rod";
  case APPLY_SAVING_PETRI:
    return "save vs petrification";
  case APPLY_SAVING_BREATH:
    return "save vs breath";
  case APPLY_SAVING_SPELL:
    return "save vs spell";
  }

  bug_printf ("Affect_location_name: unknown location %d.", location);
  return "(unknown)";
}

/*
 * Return ascii name of an affect bit vector.
 */
std::string affect_bit_name (int vector)
{
  std::string buf;

  if (vector & AFF_BLIND)
    buf.append(" blind");
  if (vector & AFF_INVISIBLE)
    buf.append(" invisible");
  if (vector & AFF_DETECT_EVIL)
    buf.append(" detect_evil");
  if (vector & AFF_DETECT_INVIS)
    buf.append(" detect_invis");
  if (vector & AFF_DETECT_MAGIC)
    buf.append(" detect_magic");
  if (vector & AFF_DETECT_HIDDEN)
    buf.append(" detect_hidden");
  if (vector & AFF_SANCTUARY)
    buf.append(" sanctuary");
  if (vector & AFF_FAERIE_FIRE)
    buf.append(" faerie_fire");
  if (vector & AFF_INFRARED)
    buf.append(" infrared");
  if (vector & AFF_CURSE)
    buf.append(" curse");
  if (vector & AFF_POISON)
    buf.append(" poison");
  if (vector & AFF_PROTECT)
    buf.append(" protect");
  if (vector & AFF_SLEEP)
    buf.append(" sleep");
  if (vector & AFF_SNEAK)
    buf.append(" sneak");
  if (vector & AFF_HIDE)
    buf.append(" hide");
  if (vector & AFF_CHARM)
    buf.append(" charm");
  if (vector & AFF_FLYING)
    buf.append(" flying");
  if (vector & AFF_PASS_DOOR)
    buf.append(" pass_door");
  if (buf.empty())
    buf.append("none");
  else
    buf.erase(0,1);
  return buf;
}

/*
 * Return ascii name of extra flags vector.
 */
std::string extra_bit_name (int extra_flags)
{
  std::string buf;

  if (extra_flags & ITEM_GLOW)
    buf.append(" glow");
  if (extra_flags & ITEM_HUM)
    buf.append(" hum");
  if (extra_flags & ITEM_DARK)
    buf.append(" dark");
  if (extra_flags & ITEM_LOCK)
    buf.append(" lock");
  if (extra_flags & ITEM_EVIL)
    buf.append(" evil");
  if (extra_flags & ITEM_INVIS)
    buf.append(" invis");
  if (extra_flags & ITEM_MAGIC)
    buf.append(" magic");
  if (extra_flags & ITEM_NODROP)
    buf.append(" nodrop");
  if (extra_flags & ITEM_BLESS)
    buf.append(" bless");
  if (extra_flags & ITEM_ANTI_GOOD)
    buf.append(" anti-good");
  if (extra_flags & ITEM_ANTI_EVIL)
    buf.append(" anti-evil");
  if (extra_flags & ITEM_ANTI_NEUTRAL)
    buf.append(" anti-neutral");
  if (extra_flags & ITEM_NOREMOVE)
    buf.append(" noremove");
  if (extra_flags & ITEM_INVENTORY)
    buf.append(" inventory");
  if (buf.empty())
    buf.append("none");
  else
    buf.erase(0,1);
  return buf;
}

/*
 * True if char can see victim.
 */
bool Character::can_see (Character * victim)
{
  if (this == victim)
    return true;

  if (!victim->is_npc ()
    && IS_SET (victim->actflags, PLR_WIZINVIS)
    && get_trust () < victim->get_trust ())
    return false;

  if (!is_npc () && IS_SET (actflags, PLR_HOLYLIGHT))
    return true;

  if (is_affected (AFF_BLIND))
    return false;

  if (in_room->is_dark() && !is_affected (AFF_INFRARED))
    return false;

  if (victim->is_affected (AFF_INVISIBLE)
    && !is_affected (AFF_DETECT_INVIS))
    return false;

  if (victim->is_affected (AFF_HIDE)
    && !is_affected (AFF_DETECT_HIDDEN)
    && victim->fighting == NULL
    && (is_npc () ? !victim->is_npc () : victim->is_npc ()))
    return false;

  return true;
}

/*
 * True if char can see obj.
 */
bool Character::can_see_obj (Object * obj)
{
  if (!is_npc () && IS_SET (actflags, PLR_HOLYLIGHT))
    return true;

  if (obj->item_type == ITEM_POTION)
    return true;

  if (is_affected (AFF_BLIND))
    return false;

  if (obj->item_type == ITEM_LIGHT && obj->value[2] != 0)
    return true;

  if (in_room->is_dark() && !is_affected (AFF_INFRARED))
    return false;

  if (IS_SET (obj->extra_flags, ITEM_INVIS)
    && !is_affected (AFF_DETECT_INVIS))
    return false;

  return true;
}

/*
 * True if char can drop obj.
 */
bool Character::can_drop_obj (Object * obj)
{
  if (!IS_SET (obj->extra_flags, ITEM_NODROP))
    return true;

  if (!is_npc () && level >= LEVEL_IMMORTAL)
    return true;

  return false;
}

/*
 * Lookup a skill by name.
 */
int skill_lookup (const std::string & name)
{
  int sn;

  for (sn = 0; sn < MAX_SKILL; sn++) {
    if (skill_table[sn].name == NULL)
      break;
    if (tolower(name[0]) == tolower(skill_table[sn].name[0])
      && !str_prefix (name, skill_table[sn].name))
      return sn;
  }

  return -1;
}

/*
 * Lookup a skill by slot number.
 * Used for object loading.
 */
int slot_lookup (int slot)
{
  int sn;

  if (slot <= 0)
    return -1;

  for (sn = 0; sn < MAX_SKILL; sn++) {
    if (slot == skill_table[sn].slot)
      return sn;
  }

  if (fBootDb) {
    fatal_printf ("Slot_lookup: bad slot %d.", slot);
  }

  return -1;
}

/*
 * The primary output interface for formatted output.
 */
void Character::act (const std::string & format, const void *arg1, const void *arg2, int type)
{
  static char *const he_she[] = { "it", "he", "she" };
  static char *const him_her[] = { "it", "him", "her" };
  static char *const his_her[] = { "its", "his", "her" };

  Character *vch = (Character *) arg2;
  Object *obj1 = (Object *) arg1;
  Object *obj2 = (Object *) arg2;

  /*
   * Discard null and zero-length messages.
   */
  if (format.empty())
    return;

  CharIter to = in_room->people.begin();
  CharIter tend = in_room->people.end();

  if (type == TO_VICT) {
    if (vch == NULL) {
      bug_printf ("Act: null vch with TO_VICT.");
      return;
    }
    to = vch->in_room->people.begin();
    tend = vch->in_room->people.end();
  }

  for (; to != tend; to++) {
    if (((*to)->desc == NULL
        && ((*to)->is_npc () && !((*to)->pIndexData->progtypes & ACT_PROG)))
      || !(*to)->is_awake ())
      continue;

    if (type == TO_CHAR && *to != this)
      continue;
    if (type == TO_VICT && (*to != vch || *to == this))
      continue;
    if (type == TO_ROOM && *to == this)
      continue;
    if (type == TO_NOTVICT && (*to == this || *to == vch))
      continue;

    std::string buf;

    std::string::const_iterator str = format.begin();
    while (str != format.end()) {
      if (*str != '$') {
        buf.append(1, *str);
        str++;
        continue;
      }
      ++str;

      if (arg2 == NULL && *str >= 'A' && *str <= 'Z') {
        bug_printf ("Act: missing arg2 for code %d.", *str);
        buf.append(" <@@@> ");
      } else {
        switch (*str) {
        default:
          bug_printf ("Act: bad code %d.", *str);
          buf.append(" <@@@> ");
          break;
          /* Thx alex for 't' idea */
        case 't':
          buf.append((char *) arg1);
          break;
        case 'T':
          buf.append((char *) arg2);
          break;
        case 'n':
          buf.append(describe_to(*to));
          break;
        case 'N':
          buf.append(vch->describe_to(*to));
          break;
        case 'e':
          buf.append(he_she[URANGE (0, sex, 2)]);
          break;
        case 'E':
          buf.append(he_she[URANGE (0, vch->sex, 2)]);
          break;
        case 'm':
          buf.append(him_her[URANGE (0, sex, 2)]);
          break;
        case 'M':
          buf.append(him_her[URANGE (0, vch->sex, 2)]);
          break;
        case 's':
          buf.append(his_her[URANGE (0, sex, 2)]);
          break;
        case 'S':
          buf.append(his_her[URANGE (0, vch->sex, 2)]);
          break;

        case 'p':
          buf.append((*to)->can_see_obj(obj1)
            ? obj1->short_descr.c_str() : "something");
          break;

        case 'P':
          buf.append((*to)->can_see_obj(obj2)
            ? obj2->short_descr.c_str() : "something");
          break;

        case 'd':
          if (arg2 == NULL || ((char *) arg2)[0] == '\0') {
            buf.append("door");
          } else {
            std::string fname;
            one_argument ((char *) arg2, fname);
            buf.append(fname);
          }
          break;
        }
      }

      ++str;
    }

    buf.append("\r\n");
    buf[0] = toupper(buf[0]);
    if ((*to)->desc)
      (*to)->desc->write_to_buffer (buf);
    if (MOBtrigger)
      mprog_act_trigger (buf, *to, this, obj1, vch);
    /* Added by Kahn */
  }

  MOBtrigger = true;
  return;
}

bool Object::can_wear (sh_int part) {
  return wear_flags & part;
}

bool Object::is_obj_stat(sh_int stat) {
  return extra_flags & stat;
}

/*
 * Return # of objects which an object counts as.
 * Thanks to Tony Chamberlain for the correct recursive code here.
 */
int Object::get_obj_number ()
{
  int number = 0;

  if (item_type == ITEM_CONTAINER) {
    for (ObjIter o = contains.begin(); o != contains.end(); o++)
      number += (*o)->get_obj_number();
  } else
    number = 1;

  return number;
}

/*
 * Return weight of an object, including weight of contents.
 */
int Object::get_obj_weight ()
{
  int wt = weight;

  for (ObjIter o = contains.begin(); o != contains.end(); o++)
    wt += (*o)->get_obj_weight ();

  return wt;
}

/*
 * Count occurrences of an obj in a list.
 */
int ObjectPrototype::count_obj_list (std::list<Object *> & list)
{
  int nMatch = 0;

  for (ObjIter o = list.begin(); o != list.end(); o++) {
    if ((*o)->pIndexData == this)
      nMatch++;
  }
  return nMatch;
}

/*
 * Move an obj out of a room.
 */
void Object::obj_from_room ()
{
  Room *in_rm = in_room;

  if (in_rm == NULL) {
    bug_printf ("obj_from_room: NULL.");
    return;
  }

  in_rm->contents.erase(find(in_rm->contents.begin(),in_rm->contents.end(),this));
  in_room = NULL;
  return;
}

/*
 * Move an obj into a room.
 */
void Object::obj_to_room (Room * pRoomIndex)
{
  pRoomIndex->contents.push_back(this);
  in_room = pRoomIndex;
  carried_by = NULL;
  in_obj = NULL;
  return;
}

/*
 * Move an object into an object.
 */
void Object::obj_to_obj (Object * obj_to)
{
  obj_to->contains.push_back(this);
  in_obj = obj_to;
  in_room = NULL;
  carried_by = NULL;

  for (; obj_to != NULL; obj_to = obj_to->in_obj) {
    if (obj_to->carried_by != NULL) {
      obj_to->carried_by->carry_number += get_obj_number();
      obj_to->carried_by->carry_weight += get_obj_weight();
    }
  }

  return;
}

/*
 * Move an object out of an object.
 */
void Object::obj_from_obj ()
{
  Object *obj_from = in_obj;

  if (obj_from == NULL) {
    bug_printf ("Obj_from_obj: null obj_from.");
    return;
  }

  obj_from->contains.erase(find(obj_from->contains.begin(), obj_from->contains.end(), this));
  in_obj = NULL;

  for (; obj_from != NULL; obj_from = obj_from->in_obj) {
    if (obj_from->carried_by != NULL) {
      obj_from->carried_by->carry_number -= get_obj_number();
      obj_from->carried_by->carry_weight -= get_obj_weight();
    }
  }

  return;
}

/*
 * Give an obj to a char.
 */
void Object::obj_to_char (Character * ch)
{
  ch->carrying.push_back(this);
  carried_by = ch;
  in_room = NULL;
  in_obj = NULL;
  ch->carry_number += get_obj_number();
  ch->carry_weight += get_obj_weight();
}

/*
 * Find the ac value of an obj, including position effect.
 */
int Object::apply_ac (int iWear)
{
  if (item_type != ITEM_ARMOR)
    return 0;

  switch (iWear) {
  case WEAR_BODY:
    return 3 * value[0];
  case WEAR_HEAD:
    return 2 * value[0];
  case WEAR_LEGS:
    return 2 * value[0];
  case WEAR_FEET:
    return value[0];
  case WEAR_HANDS:
    return value[0];
  case WEAR_ARMS:
    return value[0];
  case WEAR_SHIELD:
    return value[0];
  case WEAR_FINGER_L:
    return value[0];
  case WEAR_FINGER_R:
    return value[0];
  case WEAR_NECK_1:
    return value[0];
  case WEAR_NECK_2:
    return value[0];
  case WEAR_ABOUT:
    return 2 * value[0];
  case WEAR_WAIST:
    return value[0];
  case WEAR_WRIST_L:
    return value[0];
  case WEAR_WRIST_R:
    return value[0];
  case WEAR_HOLD:
    return value[0];
  }

  return 0;
}

int Character::is_npc() {
  return actflags & ACT_IS_NPC;
}

bool Character::is_awake() {
  return position > POS_SLEEPING;
}

bool Character::is_good() {
  return alignment >= 350;
}

bool Character::is_evil() {
  return alignment <= -350;
}

bool Character::is_neutral() {
  return !is_good() && !is_evil();
}

bool Character::is_affected(int flg) {
  return affected_by & flg;
}

int Character::get_ac() {
  if (is_awake())
    return armor + dex_app[get_curr_dex()].defensive;
  else
    return armor;
}

int Character::get_hitroll() {
  return hitroll + str_app[get_curr_str()].tohit;
}

int Character::get_damroll() {
  return damroll + str_app[get_curr_str()].todam;
}

/*
 * Retrieve character's current strength.
 */
int Character::get_curr_str() {
  int max;

  if (is_npc ())
    return 13;

  if (class_table[klass].attr_prime == APPLY_STR)
    max = 25;
  else
    max = 22;

  return URANGE (3, pcdata->perm_str + pcdata->mod_str, max);
}

/*
 * Retrieve character's current intelligence.
 */
int Character::get_curr_int() {
  int max;

  if (is_npc ())
    return 13;

  if (class_table[klass].attr_prime == APPLY_INT)
    max = 25;
  else
    max = 22;

  return URANGE (3, pcdata->perm_int + pcdata->mod_int, max);
}

/*
 * Retrieve character's current wisdom.
 */
int Character::get_curr_wis() {
  int max;

  if (is_npc ())
    return 13;

  if (class_table[klass].attr_prime == APPLY_WIS)
    max = 25;
  else
    max = 22;

  return URANGE (3, pcdata->perm_wis + pcdata->mod_wis, max);
}

/*
 * Retrieve character's current dexterity.
 */
int Character::get_curr_dex() {
  int max;

  if (is_npc ())
    return 13;

  if (class_table[klass].attr_prime == APPLY_DEX)
    max = 25;
  else
    max = 22;

  return URANGE (3, pcdata->perm_dex + pcdata->mod_dex, max);
}

/*
 * Retrieve character's current constitution.
 */
int Character::get_curr_con() {
  int max;

  if (is_npc ())
    return 13;

  if (class_table[klass].attr_prime == APPLY_CON)
    max = 25;
  else
    max = 22;

  return URANGE (3, pcdata->perm_con + pcdata->mod_con, max);
}

/*
 * Retrieve a character's age.
 */
int Character::get_age() {
  return 17 + (played + (int) (current_time - logon)) / 14400;
  /* 12240 assumes 30 second hours, 24 hours a day, 20 day - Kahn */
}

/*
 * Retrieve a character's carry capacity.
 */
int Character::can_carry_n() {
  if (!is_npc () && level >= LEVEL_IMMORTAL)
    return 1000;

  if (is_npc () && IS_SET (actflags, ACT_PET))
    return 0;

  return MAX_WEAR + 2 * get_curr_dex() / 2;
}

/*
 * Retrieve a character's carry capacity.
 */
int Character::can_carry_w() {
  if (!is_npc () && level >= LEVEL_IMMORTAL)
    return 1000000;

  if (is_npc () && IS_SET (actflags, ACT_PET))
    return 0;

  return str_app[get_curr_str()].carry;
}

/*
 * Retrieve a character's trusted level for permission checking.
 */
int Character::get_trust() {
  Character *ch;

  if (desc != NULL && desc->original != NULL)
    ch = desc->original;
  else
    ch = this;

  if (ch->trust != 0)
    return ch->trust;

  if (ch->is_npc () && ch->level >= LEVEL_HERO)
    return LEVEL_HERO - 1;
  else
    return ch->level;
}

bool Character::is_immortal() {
  return get_trust() >= LEVEL_IMMORTAL;
}

bool Character::is_hero() {
  return get_trust() >= LEVEL_HERO;
}

int Character::is_outside() {
  return !(in_room->room_flags & ROOM_INDOORS);
}

void Character::wait_state(int npulse) {
  wait = std::max(wait, npulse);
}

/*
 * Compute a saving throw.
 * Negative apply's make saving throw better.
 */
bool Character::saves_spell (int lvl) {
  int save;

  save = 50 + (level - lvl - saving_throw) * 5;
  save = URANGE (5, save, 95);
  return number_percent () < save;
}

std::string Character::describe_to (Character* looker) {
  if (looker->can_see(this)) {
    if (is_npc())
      return short_descr;
    else
      return name;
  } else {
    return "someone";
  }
}

/*
 * Find a piece of eq on a character.
 */
Object * Character::get_eq_char (int iWear)
{
  for (ObjIter o = carrying.begin(); o != carrying.end(); o++) {
    if ((*o)->wear_loc == iWear)
      return *o;
  }

  return NULL;
}

/*
 * Apply or remove an affect to a character.
 */
void Character::affect_modify (Affect * paf, bool fAdd)
{
  Object *wield;

  int mod = paf->modifier;

  if (fAdd) {
    SET_BIT (affected_by, paf->bitvector);
  } else {
    REMOVE_BIT (affected_by, paf->bitvector);
    mod = 0 - mod;
  }

  if (is_npc ())
    return;

  switch (paf->location) {
  default:
    bug_printf ("Affect_modify: unknown location %d.", paf->location);
    return;

  case APPLY_NONE:
    break;
  case APPLY_STR:
    pcdata->mod_str += mod;
    break;
  case APPLY_DEX:
    pcdata->mod_dex += mod;
    break;
  case APPLY_INT:
    pcdata->mod_int += mod;
    break;
  case APPLY_WIS:
    pcdata->mod_wis += mod;
    break;
  case APPLY_CON:
    pcdata->mod_con += mod;
    break;
  case APPLY_SEX:
    sex += mod;
    break;
  case APPLY_CLASS:
    break;
  case APPLY_LEVEL:
    break;
  case APPLY_AGE:
    break;
  case APPLY_HEIGHT:
    break;
  case APPLY_WEIGHT:
    break;
  case APPLY_MANA:
    max_mana += mod;
    break;
  case APPLY_HIT:
    max_hit += mod;
    break;
  case APPLY_MOVE:
    max_move += mod;
    break;
  case APPLY_GOLD:
    break;
  case APPLY_EXP:
    break;
  case APPLY_AC:
    armor += mod;
    break;
  case APPLY_HITROLL:
    hitroll += mod;
    break;
  case APPLY_DAMROLL:
    damroll += mod;
    break;
  case APPLY_SAVING_PARA:
    saving_throw += mod;
    break;
  case APPLY_SAVING_ROD:
    saving_throw += mod;
    break;
  case APPLY_SAVING_PETRI:
    saving_throw += mod;
    break;
  case APPLY_SAVING_BREATH:
    saving_throw += mod;
    break;
  case APPLY_SAVING_SPELL:
    saving_throw += mod;
    break;
  }

  /*
   * Check for weapon wielding.
   * Guard against recursion (for weapons with affects).
   */
  if ((wield = get_eq_char (WEAR_WIELD)) != NULL
    && wield->get_obj_weight() > str_app[get_curr_str()].wield) {
    static int depth;

    if (depth == 0) {
      depth++;
      act ("You drop $p.", wield, NULL, TO_CHAR);
      act ("$n drops $p.", wield, NULL, TO_ROOM);
      wield->obj_from_char();
      wield->obj_to_room (in_room);
      depth--;
    }
  }

  return;
}

/*
 * Unequip a char with an obj.
 */
void Character::unequip_char (Object * obj)
{
  if (obj->wear_loc == WEAR_NONE) {
    bug_printf ("Unequip_char: already unequipped.");
    return;
  }

  armor += obj->apply_ac (obj->wear_loc);
  obj->wear_loc = -1;

  AffIter paf;
  for (paf = obj->pIndexData->affected.begin(); paf != obj->pIndexData->affected.end(); paf++)
    affect_modify (*paf, false);
  for (paf = obj->affected.begin(); paf != obj->affected.end(); paf++)
    affect_modify (*paf, false);

  if (obj->item_type == ITEM_LIGHT
    && obj->value[2] != 0 && in_room != NULL && in_room->light > 0)
    --in_room->light;

  return;
}

/*
 * Take an obj from its character.
 */
void Object::obj_from_char ()
{
  Character *ch = carried_by;

  if (ch == NULL) {
    bug_printf ("Obj_from_char: null ch.");
    return;
  }

  if (wear_loc != WEAR_NONE)
    ch->unequip_char(this);

  ch->carrying.erase(find(ch->carrying.begin(),ch->carrying.end(), this));

  carried_by = NULL;
  ch->carry_number -= get_obj_number();
  ch->carry_weight -= get_obj_weight();
  return;
}

/*
 * Extract an obj from the world.
 */
void Object::extract_obj ()
{
  Object *obj_content;

  if (in_room != NULL)
    obj_from_room ();
  else if (carried_by != NULL)
    obj_from_char ();
  else if (in_obj != NULL)
    obj_from_obj ();

  ObjIter o, next;
  for (o = contains.begin(); o != contains.end(); o = next) {
    obj_content = *o;
    next = ++o;
    obj_content->extract_obj();
  }

  deepobnext = object_list.erase(find(object_list.begin(), object_list.end(), this));

  AffIter af;
  for (af = affected.begin(); af != affected.end(); af++) {
    delete *af;
  }
  affected.clear();

  std::list<ExtraDescription *>::iterator ed;
  for (ed = extra_descr.begin(); ed != extra_descr.end(); ed++) {
    delete *ed;
  }
  extra_descr.clear();

  --pIndexData->count;
  delete this;
  return;
}

/*
 * Give an affect to a char.
 */
void Character::affect_to_char (Affect * paf)
{
  Affect *paf_new = new Affect();

  *paf_new = *paf;
  affected.push_back(paf_new);

  affect_modify (paf_new, true);
  return;
}

/*
 * Remove an affect from a char.
 */
void Character::affect_remove (Affect * paf)
{
  if (affected.empty()) {
    bug_printf ("Affect_remove: no affect.");
    return;
  }

  affect_modify (paf, false);

  affected.erase(find(affected.begin(), affected.end(), paf));

  delete paf;
  return;
}

/*
 * Strip all affects of a given sn.
 */
void Character::affect_strip (int sn)
{
  Affect *paf;

  AffIter af, next;
  for (af = affected.begin(); af != affected.end(); af = next) {
    paf = *af;
    next = ++af;
    if (paf->type == sn)
      affect_remove (paf);
  }

  return;
}

/*
 * Return true if a char is affected by a spell.
 */
bool Character::has_affect (int sn)
{
  AffIter af;
  for (af = affected.begin(); af != affected.end(); af++) {
    if ((*af)->type == sn)
      return true;
  }

  return false;
}

/*
 * Add or enhance an affect.
 */
void Character::affect_join (Affect * paf)
{
  AffIter af;
  for (af = affected.begin(); af != affected.end(); af++) {
    if ((*af)->type == paf->type) {
      paf->duration += (*af)->duration;
      paf->modifier += (*af)->modifier;
      affect_remove (*af);
      break;
    }
  }

  affect_to_char (paf);
  return;
}

/*
 * Find a char in the room.
 */
Character * Character::get_char_room (const std::string & argument)
{
  std::string arg;
  int number;
  int count;

  number = number_argument (argument, arg);
  count = 0;
  if (!str_cmp (arg, "self"))
    return this;

  CharIter rch;
  for (rch = in_room->people.begin(); rch != in_room->people.end(); rch++) {
    if (!can_see(*rch) || !is_name (arg, (*rch)->name))
      continue;
    if (++count == number)
      return *rch;
  }

  return NULL;
}

/*
 * Find a char in the world.
 */
Character * Character::get_char_world (const std::string & argument)
{
  std::string arg;
  Character *wch;
  int number;
  int count;

  if ((wch = get_char_room (argument)) != NULL)
    return wch;

  number = number_argument (argument, arg);
  count = 0;
  CharIter c;
  for (c = char_list.begin(); c != char_list.end(); c++) {
    if (!can_see(*c) || !is_name (arg, (*c)->name))
      continue;
    if (++count == number)
      return *c;
  }

  return NULL;
}

/*
 * Find some object with a given index data.
 * Used by area-reset 'P' command.
 */
Object * ObjectPrototype::get_obj_type ()
{
  for (ObjIter obj = object_list.begin(); obj != object_list.end(); obj++) {
    if ((*obj)->pIndexData == this)
      return *obj;
  }
  return NULL;
}

/*
 * Find an obj in a list.
 */
Object * Character::get_obj_list (const std::string & argument, std::list<Object *> & list)
{
  std::string arg;
  int number;
  int count;

  number = number_argument (argument, arg);
  count = 0;
  ObjIter obj;
  for (obj = list.begin(); obj != list.end(); obj++) {
    if (can_see_obj(*obj) && is_name (arg, (*obj)->name)) {
      if (++count == number)
        return *obj;
    }
  }

  return NULL;
}

/*
 * Find an obj in player's inventory.
 */
Object * Character::get_obj_carry (const std::string & argument)
{
  std::string arg;
  int number;
  int count;

  number = number_argument (argument, arg);
  count = 0;
  ObjIter o;
  for (o = carrying.begin(); o != carrying.end(); o++) {
    if ((*o)->wear_loc == WEAR_NONE && can_see_obj(*o)
      && is_name (arg, (*o)->name)) {
      if (++count == number)
        return *o;
    }
  }

  return NULL;
}

/*
 * Find an obj in player's equipment.
 */
Object * Character::get_obj_wear (const std::string & argument)
{
  std::string arg;
  int number;
  int count;

  number = number_argument (argument, arg);
  count = 0;
  ObjIter o;
  for (o = carrying.begin(); o != carrying.end(); o++) {
    if ((*o)->wear_loc != WEAR_NONE && can_see_obj(*o)
      && is_name (arg, (*o)->name)) {
      if (++count == number)
        return *o;
    }
  }

  return NULL;
}

/*
 * Find an obj in the room or in inventory.
 */
Object * Character::get_obj_here (const std::string & argument)
{
  Object *obj;

  obj = get_obj_list (argument, in_room->contents);
  if (obj != NULL)
    return obj;

  if ((obj = get_obj_carry (argument)) != NULL)
    return obj;

  if ((obj = get_obj_wear (argument)) != NULL)
    return obj;

  return NULL;
}

/*
 * Find an obj in the world.
 */
Object * Character::get_obj_world (const std::string & argument)
{
  std::string arg;
  Object *obj;

  if ((obj = get_obj_here (argument)) != NULL)
    return obj;

  int number = number_argument (argument, arg);
  int count = 0;
  for (ObjIter o = object_list.begin();
    o != object_list.end(); o++) {
    if (can_see_obj(*o) && is_name (arg, (*o)->name)) {
      if (++count == number)
        return *o;
    }
  }

  return NULL;
}

/*
 * Translates mob virtual number to its mob index struct.
 * Hash table lookup.
 */
MobPrototype *get_mob_index (int vnum)
{
  std::map<int,MobPrototype*>::iterator pMobIndex;

  pMobIndex = mob_table.find(vnum);

  if (pMobIndex != mob_table.end())
      return (*pMobIndex).second;

  if (fBootDb) {
    fatal_printf ("Get_mob_index: bad vnum %d.", vnum);
  }

  return NULL;
}

/*
 * Translates mob virtual number to its obj index struct.
 * Hash table lookup.
 */
ObjectPrototype *get_obj_index (int vnum)
{
  std::map<int,ObjectPrototype*>::iterator pObjIndex;

  pObjIndex = obj_table.find(vnum);

  if (pObjIndex != obj_table.end())
      return (*pObjIndex).second;

  if (fBootDb) {
    fatal_printf ("Get_obj_index: bad vnum %d.", vnum);
  }

  return NULL;
}

/*
 * Translates mob virtual number to its room index struct.
 * Hash table lookup.
 */
Room *get_room_index (int vnum)
{
  std::map<int,Room*>::iterator pRoomIndex;

  pRoomIndex = room_table.find(vnum);

  if (pRoomIndex != room_table.end())
      return (*pRoomIndex).second;

  if (fBootDb) {
    fatal_printf ("Get_room_index: bad vnum %d.", vnum);
  }

  return NULL;
}

/*
 * Write the char.
 */
void Character::fwrite_char (std::ofstream & fp)
{

  fp << "#" << (is_npc () ? "MOB" : "PLAYER") << "\n";

  fp << "Name         " << name << "~\n";
  fp << "ShortDescr   " << short_descr << "~\n";
  fp << "LongDescr    " << long_descr << "~\n";
  fp << "Description  " << description << "~\n";
  fp << "Prompt       " << prompt << "~\n";
  fp << "Sex          " << sex << "\n";
  fp << "Class        " << klass << "\n";
  fp << "Race         " << race << "\n";
  fp << "Level        " << level << "\n";
  fp << "Trust        " << trust << "\n";
  fp << "Wizbit       " << wizbit << "\n";
  fp << "Played       " << played + (int) (current_time - logon) << "\n";
  fp << "Note         " << last_note << "\n";
  fp << "Room         " <<
    ((in_room == get_room_index (ROOM_VNUM_LIMBO)
      && was_in_room != NULL)
    ? was_in_room->vnum : in_room->vnum) << "\n";

  fp << "HpManaMove   " << hit << " " << max_hit << " " <<
       mana << " " << max_mana << " " << move << " " <<
       max_move << "\n";
  fp << "Gold         " << gold << "\n";
  fp << "Exp          " << exp << "\n";
  fp << "Act          " << actflags << "\n";
  fp << "AffectedBy   " << affected_by << "\n";
  /* Bug fix from Alander */
  if (position == POS_FIGHTING)
    fp << "Position     " <<  POS_STANDING<< "\n";
  else
    fp << "Position     " <<  position << "\n";

  fp << "Practice     " << practice << "\n";
  fp << "SavingThrow  " << saving_throw << "\n";
  fp << "Alignment    " << alignment << "\n";
  fp << "Hitroll      " << hitroll << "\n";
  fp << "Damroll      " << damroll << "\n";
  fp << "Armor        " << armor << "\n";
  fp << "Wimpy        " << wimpy << "\n";
  fp << "Deaf         " << deaf << "\n";

  if (is_npc ()) {
    fp << "Vnum         " << pIndexData->vnum << "\n";
  } else {
    fp << "Password     " << pcdata->pwd << "~\n";
    fp << "Bamfin       " << pcdata->bamfin << "~\n";
    fp << "Bamfout      " << pcdata->bamfout << "~\n";
    fp << "Title        " << pcdata->title << "~\n";
    fp << "AttrPerm     " << pcdata->perm_str << " " << pcdata->perm_int <<
      " " << pcdata->perm_wis << " " << pcdata->perm_dex << " " <<
      pcdata->perm_con << "\n";

    fp << "AttrMod      " << pcdata->mod_str << " " << pcdata->mod_int << " "
      << pcdata->mod_wis << " " << pcdata->mod_dex << " " <<
      pcdata->mod_con << "\n";

    fp << "Condition    " << pcdata->condition[0] << " " <<
      pcdata->condition[1] << " " << pcdata->condition[2] << "\n";

    fp << "Pagelen      " << pcdata->pagelen << "\n";

    for (int sn = 0; sn < MAX_SKILL; sn++) {
      if (skill_table[sn].name != NULL && pcdata->learned[sn] > 0) {
        fp << "Skill        " << pcdata->learned[sn] << "'" <<
          skill_table[sn].name << "'\n";
      }
    }
  }

  for (AffIter af = affected.begin(); af != affected.end(); af++) {
    fp << "Affect " << (*af)->type << " " << (*af)->duration << " " <<
      (*af)->modifier << " " << (*af)->location << " " <<
      (*af)->bitvector << "\n";
  }

  fp << "End\n\n";
  return;
}

/*
 * Write an object and its contents.
 */
void Object::fwrite_obj (Character * ch, std::ofstream & fp, int iNest)
{

  /*
   * Castrate storage characters.
   */
  if (ch->level < level || item_type == ITEM_KEY || item_type == ITEM_POTION)
    return;

  fp << "#OBJECT\n";
  fp << "Nest         " << iNest << "\n";
  fp << "Name         " << name << "~\n";
  fp << "ShortDescr   " << short_descr << "~\n";
  fp << "Description  " << description << "~\n";
  fp << "Vnum         " << pIndexData->vnum << "\n";
  fp << "ExtraFlags   " << extra_flags << "\n";
  fp << "WearFlags    " << wear_flags << "\n";
  fp << "WearLoc      " << wear_loc << "\n";
  fp << "ItemType     " << item_type << "\n";
  fp << "Weight       " << weight << "\n";
  fp << "Level        " << level << "\n";
  fp << "Timer        " << timer << "\n";
  fp << "Cost         " << cost << "\n";
  fp << "Values       " << value[0] << " " << value[1] << " " <<
    value[2] << " " << value[3] << "\n";

  switch (item_type) {
  case ITEM_POTION:
  case ITEM_SCROLL:
    if (value[1] > 0) {
      fp << "Spell 1      '" << skill_table[value[1]].name << "'\n";
    }

    if (value[2] > 0) {
      fp << "Spell 2      '" << skill_table[value[2]].name << "'\n";
    }

    if (value[3] > 0) {
      fp << "Spell 3      '" << skill_table[value[3]].name << "'\n";
    }

    break;

  case ITEM_PILL:
  case ITEM_STAFF:
  case ITEM_WAND:
    if (value[3] > 0) {
      fp << "Spell 3      '" << skill_table[value[3]].name << "'\n";
    }

    break;
  }

  AffIter af;
  for (af = affected.begin(); af != affected.end(); af++) {
    fp << "Affect       " << (*af)->type << " " << (*af)->duration << " " <<
      (*af)->modifier << " " << (*af)->location << " " << (*af)->bitvector << "\n";
  }

  std::list<ExtraDescription *>::iterator ed;
  for (ed = extra_descr.begin(); ed != extra_descr.end(); ed++) {
    fp << "ExtraDescr   " << (*ed)->keyword << "~ " <<
      (*ed)->description << "~\n";
  }

  fp << "End\n\n";

  std::list<Object*>::reverse_iterator o;
  for (o = contains.rbegin(); o != contains.rend(); o++)
    (*o)->fwrite_obj (ch, fp, iNest + 1);

  return;
}

/*
 * Save a character and inventory.
 * Would be cool to save NPC's too for quest purposes,
 *   some of the infrastructure is provided.
 */
void Character::save_char_obj ()
{
  char strsave[MAX_INPUT_LENGTH];
  std::ofstream fp;

  if (is_npc () || level < 2)
    return;

  Character * ch = this;
  if (desc != NULL && desc->original != NULL)
    ch = desc->original;

  ch->save_time = current_time;

  /* player files parsed directories by Yaz 4th Realm */
  snprintf (strsave, sizeof strsave, "%s%s", PLAYER_DIR, capitalize(ch->name).c_str());
  fp.open (strsave, std::ofstream::out | std::ofstream::binary);
  if (!fp.is_open()) {
    bug_printf ("Save_char_obj: fopen");
    perror (strsave);
  } else {
    ch->fwrite_char (fp);
    std::list<Object*>::reverse_iterator o;
    for (o = ch->carrying.rbegin(); o != ch->carrying.rend(); o++)
      (*o)->fwrite_obj (ch, fp, 0);
    fp << "#END\n";
  }
  fp.close();
  return;
}

/*
 * Read in a char.
 */
void Character::fread_char (std::ifstream & fp)
{
  std::string word;
  bool fMatch;

  for (;;) {
    word = fp.eof() ? std::string("End") : fread_word (fp);
    fMatch = false;

    switch (toupper (word[0])) {
    case '*':
      fMatch = true;
      fread_to_eol (fp);
      break;

    case 'A':
      KEY ("Act", actflags, fread_number (fp));
      KEY ("AffectedBy", affected_by, fread_number (fp));
      KEY ("Alignment", alignment, fread_number (fp));
      KEY ("Armor", armor, fread_number (fp));

      if (!str_cmp (word, "Affect")) {
        Affect *paf;

        paf = new Affect();

        paf->type = fread_number (fp);
        paf->duration = fread_number (fp);
        paf->modifier = fread_number (fp);
        paf->location = fread_number (fp);
        paf->bitvector = fread_number (fp);
        affected.push_back(paf);
        fMatch = true;
        break;
      }

      if (!str_cmp (word, "AttrMod")) {
        pcdata->mod_str = fread_number (fp);
        pcdata->mod_int = fread_number (fp);
        pcdata->mod_wis = fread_number (fp);
        pcdata->mod_dex = fread_number (fp);
        pcdata->mod_con = fread_number (fp);
        fMatch = true;
        break;
      }

      if (!str_cmp (word, "AttrPerm")) {
        pcdata->perm_str = fread_number (fp);
        pcdata->perm_int = fread_number (fp);
        pcdata->perm_wis = fread_number (fp);
        pcdata->perm_dex = fread_number (fp);
        pcdata->perm_con = fread_number (fp);
        fMatch = true;
        break;
      }
      break;

    case 'B':
      KEY ("Bamfin", pcdata->bamfin, fread_string (fp));
      KEY ("Bamfout", pcdata->bamfout, fread_string (fp));
      break;

    case 'C':
      KEY ("Class", klass, fread_number (fp));

      if (!str_cmp (word, "Condition")) {
        pcdata->condition[0] = fread_number (fp);
        pcdata->condition[1] = fread_number (fp);
        pcdata->condition[2] = fread_number (fp);
        fMatch = true;
        break;
      }
      break;

    case 'D':
      KEY ("Damroll", damroll, fread_number (fp));
      KEY ("Deaf", deaf, fread_number (fp));
      KEY ("Description", description, fread_string (fp));
      break;

    case 'E':
      if (!str_cmp (word, "End"))
        return;
      KEY ("Exp", exp, fread_number (fp));
      break;

    case 'G':
      KEY ("Gold", gold, fread_number (fp));
      break;

    case 'H':
      KEY ("Hitroll", hitroll, fread_number (fp));

      if (!str_cmp (word, "HpManaMove")) {
        hit = fread_number (fp);
        max_hit = fread_number (fp);
        mana = fread_number (fp);
        max_mana = fread_number (fp);
        move = fread_number (fp);
        max_move = fread_number (fp);
        fMatch = true;
        break;
      }
      break;

    case 'L':
      KEY ("Level", level, fread_number (fp));
      KEY ("LongDescr", long_descr, fread_string (fp));
      break;

    case 'N':
      if (!str_cmp (word, "Name")) {
        /*
         * Name already set externally.
         */
        fread_to_eol (fp);
        fMatch = true;
        break;
      }
      KEY ("Note", last_note, fread_number (fp));
      break;

    case 'P':
      KEY ("Pagelen", pcdata->pagelen, fread_number (fp));
      KEY ("Password", pcdata->pwd, fread_string (fp));
      KEY ("Played", played, fread_number (fp));
      KEY ("Position", position, fread_number (fp));
      KEY ("Practice", practice, fread_number (fp));
      KEY ("Prompt", prompt, fread_string (fp));
      break;

    case 'R':
      KEY ("Race", race, fread_number (fp));

      if (!str_cmp (word, "Room")) {
        in_room = get_room_index (fread_number (fp));
        if (in_room == NULL)
          in_room = get_room_index (ROOM_VNUM_LIMBO);
        fMatch = true;
        break;
      }

      break;

    case 'S':
      KEY ("SavingThrow", saving_throw, fread_number (fp));
      KEY ("Sex", sex, fread_number (fp));
      KEY ("ShortDescr", short_descr, fread_string (fp));

      if (!str_cmp (word, "Skill")) {
        int sn;
        int value;

        value = fread_number (fp);
        sn = skill_lookup (fread_word (fp));
        if (sn < 0)
          bug_printf ("Fread_char: unknown skill.");
        else
          pcdata->learned[sn] = value;
        fMatch = true;
      }

      break;

    case 'T':
      KEY ("Trust", trust, fread_number (fp));

      if (!str_cmp (word, "Title")) {
        pcdata->title = fread_string (fp);
        if (isalpha (pcdata->title[0]) || isdigit (pcdata->title[0])) {
          pcdata->title = " " + pcdata->title;
        }
        fMatch = true;
        break;
      }

      break;

    case 'V':
      if (!str_cmp (word, "Vnum")) {
        pIndexData = get_mob_index (fread_number (fp));
        fMatch = true;
        break;
      }
      break;

    case 'W':
      KEY ("Wimpy", wimpy, fread_number (fp));
      KEY ("Wizbit", wizbit, fread_number (fp));
      break;
    }

    /* Make sure old chars have this field - Kahn */
    if (!pcdata->pagelen)
      pcdata->pagelen = 20;
    if (prompt.empty())
      prompt = "<%h %m %mv> ";

    if (!fMatch) {
      bug_printf ("Fread_char: no match.");
      fread_to_eol (fp);
    }
  }
}

bool Object::fread_obj (Character * ch, std::ifstream & fp)
{
  std::string word;
  int iNest = 0;
  bool fMatch;
  bool fNest = false;
  bool fVnum = true;

  for (;;) {
    word = fp.eof() ? std::string("End") : fread_word (fp);
    fMatch = false;

    switch (toupper (word[0])) {
    case '*':
      fMatch = true;
      fread_to_eol (fp);
      break;

    case 'A':
      if (!str_cmp (word, "Affect")) {
        Affect *paf;

        paf = new Affect();

        paf->type = fread_number (fp);
        paf->duration = fread_number (fp);
        paf->modifier = fread_number (fp);
        paf->location = fread_number (fp);
        paf->bitvector = fread_number (fp);
        affected.push_back(paf);
        fMatch = true;
        break;
      }
      break;

    case 'C':
      KEY ("Cost", cost, fread_number (fp));
      break;

    case 'D':
      KEY ("Description", description, fread_string (fp));
      break;

    case 'E':
      KEY ("ExtraFlags", extra_flags, fread_number (fp));

      if (!str_cmp (word, "ExtraDescr")) {
        ExtraDescription *ed;

        ed = new ExtraDescription();

        ed->keyword = fread_string (fp);
        ed->description = fread_string (fp);
        extra_descr.push_back(ed);
        fMatch = true;
      }

      if (!str_cmp (word, "End")) {
        if (!fNest || !fVnum) {
          bug_printf ("Fread_obj: incomplete object.");
          return false;
        } else {
          object_list.push_back(this);
          pIndexData->count++;
          if (iNest == 0 || rgObjNest[iNest] == NULL)
            obj_to_char (ch);
          else
            obj_to_obj (rgObjNest[iNest - 1]);
          return true;
        }
      }
      break;

    case 'I':
      KEY ("ItemType", item_type, fread_number (fp));
      break;

    case 'L':
      KEY ("Level", level, fread_number (fp));
      break;

    case 'N':
      KEY ("Name", name, fread_string (fp));

      if (!str_cmp (word, "Nest")) {
        iNest = fread_number (fp);
        if (iNest < 0 || iNest >= MAX_NEST) {
          bug_printf ("Fread_obj: bad nest %d.", iNest);
        } else {
          rgObjNest[iNest] = this;
          fNest = true;
        }
        fMatch = true;
      }
      break;

    case 'S':
      KEY ("ShortDescr", short_descr, fread_string (fp));

      if (!str_cmp (word, "Spell")) {
        int iValue;
        int sn;

        iValue = fread_number (fp);
        sn = skill_lookup (fread_word (fp));
        if (iValue < 0 || iValue > 3) {
          bug_printf ("Fread_obj: bad iValue %d.", iValue);
        } else if (sn < 0) {
          bug_printf ("Fread_obj: unknown skill.");
        } else {
          value[iValue] = sn;
        }
        fMatch = true;
        break;
      }

      break;

    case 'T':
      KEY ("Timer", timer, fread_number (fp));
      break;

    case 'V':
      if (!str_cmp (word, "Values")) {
        value[0] = fread_number (fp);
        value[1] = fread_number (fp);
        value[2] = fread_number (fp);
        value[3] = fread_number (fp);
        fMatch = true;
        break;
      }

      if (!str_cmp (word, "Vnum")) {
        int vnum;

        vnum = fread_number (fp);
        if ((pIndexData = get_obj_index (vnum)) == NULL)
          bug_printf ("Fread_obj: bad vnum %d.", vnum);
        else
          fVnum = true;
        fMatch = true;
        break;
      }
      break;

    case 'W':
      KEY ("WearFlags", wear_flags, fread_number (fp));
      KEY ("WearLoc", wear_loc, fread_number (fp));
      KEY ("Weight", weight, fread_number (fp));
      break;

    }

    if (!fMatch) {
      bug_printf ("Fread_obj: no match.");
      fread_to_eol (fp);
    }
  }
  return false;
}

/*
 * Load a char and inventory into a new ch structure.
 */
bool Descriptor::load_char_obj (const std::string & name)
{
  Character* ch = new Character();
  ch->pcdata = new PCData();
  character = ch;
  ch->desc = this;
  ch->name = name;
  ch->prompt = "<%hhp %mm %vmv> ";
  ch->last_note = 0;
  ch->actflags = PLR_BLANK | PLR_COMBINE | PLR_PROMPT;
  ch->pcdata->condition[COND_THIRST] = 48;
  ch->pcdata->condition[COND_FULL] = 48;

  bool found = false;

  char strsave[MAX_INPUT_LENGTH];
  std::ifstream fp;

  snprintf (strsave, sizeof strsave, "%s%s", PLAYER_DIR, capitalize (name).c_str());
  fp.open (strsave, std::ifstream::in | std::ifstream::binary);
  if (fp.is_open()) {
    for (int iNest = 0; iNest < MAX_NEST; iNest++)
      rgObjNest[iNest] = NULL;

    found = true;
    for (;;) {
      char letter;
      std::string word;

      letter = fread_letter (fp);
      if (letter == '*') {
        fread_to_eol (fp);
        continue;
      }

      if (letter != '#') {
        bug_printf ("Load_char_obj: # not found.");
        break;
      }

      word = fread_word (fp);
      if (!str_cmp (word, "PLAYER"))
        ch->fread_char (fp);
      else if (!str_cmp (word, "OBJECT")) {
        Object* obj = new Object;
        if (!obj->fread_obj (ch, fp)) {
          delete obj;
          bug_printf ("fread_obj: bad object.");
        }
      } else if (!str_cmp (word, "END"))
        break;
      else {
        bug_printf ("Load_char_obj: bad section.");
        break;
      }
    }
    fp.close();
  }

  return found;
}

/*
 * Equip a char with an obj.
 */
void Character::equip_char (Object * obj, int iWear)
{

  if (get_eq_char (iWear) != NULL) {
    bug_printf ("Equip_char: already equipped (%d).", iWear);
    return;
  }

  if ((obj->is_obj_stat(ITEM_ANTI_EVIL) && is_evil ())
    || (obj->is_obj_stat(ITEM_ANTI_GOOD) && is_good ())
    || (obj->is_obj_stat(ITEM_ANTI_NEUTRAL) && is_neutral ())) {
    /*
     * Thanks to Morgenes for the bug fix here!
     */
    act ("You are zapped by $p and drop it.", obj, NULL, TO_CHAR);
    act ("$n is zapped by $p and drops it.", obj, NULL, TO_ROOM);
    obj->obj_from_char();
    obj->obj_to_room (in_room);
    return;
  }

  armor -= obj->apply_ac (iWear);
  obj->wear_loc = iWear;

  AffIter af;
  for (af = obj->pIndexData->affected.begin(); af != obj->pIndexData->affected.end(); af++)
    affect_modify (*af, true);
  for (af = obj->affected.begin(); af != obj->affected.end(); af++)
    affect_modify (*af, true);

  if (obj->item_type == ITEM_LIGHT
    && obj->value[2] != 0 && in_room != NULL)
    ++in_room->light;

  return;
}

/*
 * Move a char out of a room.
 */
void Character::char_from_room ()
{
  Object *obj;

  if (in_room == NULL) {
    bug_printf ("Char_from_room: NULL.");
    return;
  }

  if (!is_npc ())
    --in_room->area->nplayer;

  if ((obj = get_eq_char (WEAR_LIGHT)) != NULL
    && obj->item_type == ITEM_LIGHT
    && obj->value[2] != 0 && in_room->light > 0)
    --in_room->light;

  deeprmnext = in_room->people.erase(
    find(in_room->people.begin(), in_room->people.end(), this));
  in_room = NULL;
  return;
}

/*
 * Move a char into a room.
 */
void Character::char_to_room (Room * pRoomIndex)
{
  Object *obj;

  if (pRoomIndex == NULL) {
    bug_printf ("Char_to_room: NULL.");
    return;
  }

  in_room = pRoomIndex;
  pRoomIndex->people.push_back(this);

  if (!is_npc ())
    ++in_room->area->nplayer;

  if ((obj = get_eq_char (WEAR_LIGHT)) != NULL
    && obj->item_type == ITEM_LIGHT && obj->value[2] != 0)
    ++in_room->light;

  return;
}

void Character::set_title (const std::string & title)
{
  if (is_npc ()) {
    bug_printf ("Set_title: NPC.");
    return;
  }

  if (isalpha (title[0]) || isdigit (title[0])) {
    pcdata->title = " " + title;
  } else {
    pcdata->title = title;
  }

  return;
}

bool Character::is_switched ()
{
  if (!is_npc () || desc == NULL)
    return false;
  return true;
}

bool Character::mp_commands ()
{                               /* Can MOBProged mobs
                                   use mpcommands? true if yes.
                                   - Kahn */
  if (is_switched())
    return false;

  if (is_npc ()
    && pIndexData->progtypes && !is_affected (AFF_CHARM))
    return true;

  return false;

}

/*
 * Advancement stuff.
 */
void Character::advance_level ()
{
  char buf[MAX_STRING_LENGTH];
  int add_hp, add_mana, add_move, add_prac;

  snprintf (buf, sizeof buf, "the %s",
    title_table[klass][level][sex == SEX_FEMALE ? 1 : 0]);
  set_title(buf);

  add_hp = con_app[get_curr_con()].hitp +
    number_range (class_table[klass].hp_min, class_table[klass].hp_max);
  add_mana = class_table[klass].fMana ? number_range (2,
    (2 * get_curr_int() + get_curr_wis()) / 8)
    : 0;
  add_move = number_range (5, (get_curr_con() + get_curr_dex()) / 4);
  add_prac = wis_app[get_curr_wis()].practice;

  add_hp = std::max (1, add_hp);
  add_mana = std::max (0, add_mana);
  add_move = std::max (10, add_move);

  max_hit += add_hp;
  max_mana += add_mana;
  max_move += add_move;
  practice += add_prac;

  if (!is_npc ())
    REMOVE_BIT (actflags, PLR_BOUGHT_PET);

  snprintf (buf, sizeof buf,
    "Your gain is: %d/%d hp, %d/%d m, %d/%d mv %d/%d prac.\r\n",
    add_hp, max_hit, add_mana, max_mana, add_move, max_move, add_prac,
    practice);
  send_to_char (buf);
  return;
}

void Character::gain_exp(int gain)
{
  if (is_npc () || level >= LEVEL_HERO)
    return;

  exp = std::max (1000, exp + gain);
  while (level < LEVEL_HERO && exp >= 1000 * (level + 1)) {
    send_to_char ("You raise a level!!  ");
    level += 1;
    advance_level();
  }

  return;
}

/*
 * Regeneration stuff.
 */
int Character::hit_gain ()
{
  int gain;

  if (is_npc ()) {
    gain = level * 3 / 2;
  } else {
    gain = std::min (5, level);

    switch (position) {
    case POS_SLEEPING:
      gain += get_curr_con();
      break;
    case POS_RESTING:
      gain += get_curr_con() / 2;
      break;
    }

    if (pcdata->condition[COND_FULL] == 0)
      gain /= 2;

    if (pcdata->condition[COND_THIRST] == 0)
      gain /= 2;

  }

  if (is_affected (AFF_POISON))
    gain /= 4;

  return std::min (gain, max_hit - hit);
}

int Character::mana_gain ()
{
  int gain;

  if (is_npc ()) {
    gain = level;
  } else {
    gain = std::min (5, level / 2);

    switch (position) {
    case POS_SLEEPING:
      gain += get_curr_int() * 2;
      break;
    case POS_RESTING:
      gain += get_curr_int();
      break;
    }

    if (pcdata->condition[COND_FULL] == 0)
      gain /= 2;

    if (pcdata->condition[COND_THIRST] == 0)
      gain /= 2;

  }

  if (is_affected (AFF_POISON))
    gain /= 4;

  return std::min (gain, max_mana - mana);
}

int Character::move_gain ()
{
  int gain;

  if (is_npc ()) {
    gain = level;
  } else {
    gain = std::max (15, 2 * level);

    switch (position) {
    case POS_SLEEPING:
      gain += get_curr_dex();
      break;
    case POS_RESTING:
      gain += get_curr_dex() / 2;
      break;
    }

    if (pcdata->condition[COND_FULL] == 0)
      gain /= 2;

    if (pcdata->condition[COND_THIRST] == 0)
      gain /= 2;
  }

  if (is_affected (AFF_POISON))
    gain /= 4;

  return std::min (gain, max_move - move);
}

void Character::gain_condition (int iCond, int value)
{
  if (value == 0 || is_npc () || level >= LEVEL_HERO)
    return;

  int condition = pcdata->condition[iCond];
  pcdata->condition[iCond] = URANGE (0, condition + value, 48);

  if (pcdata->condition[iCond] == 0) {
    switch (iCond) {
    case COND_FULL:
      send_to_char ("You are hungry.\r\n");
      break;

    case COND_THIRST:
      send_to_char ("You are thirsty.\r\n");
      break;

    case COND_DRUNK:
      if (condition != 0)
        send_to_char ("You are sober.\r\n");
      break;
    }
  }

  return;
}

void Character::add_follower (Character * master)
{

  if (master != NULL) {
    bug_printf ("Add_follower: non-null master.");
    return;
  }

  master = master;
  leader = NULL;

  if (master->can_see(this))
    act ("$n now follows you.", NULL, master, TO_VICT);

  act ("You now follow $N.", NULL, master, TO_CHAR);

  return;
}

void Character::stop_follower()
{

  if (master == NULL) {
    bug_printf ("Stop_follower: null master.");
    return;
  }

  if (is_affected (AFF_CHARM)) {
    REMOVE_BIT (affected_by, AFF_CHARM);
    affect_strip (gsn_charm_person);
  }

  if (master->can_see(this))
    act ("$n stops following you.", NULL, master, TO_VICT);
  act ("You stop following $N.", NULL, master, TO_CHAR);

  master = NULL;
  leader = NULL;
  return;
}

void Character::die_follower ()
{
  if (master != NULL)
    stop_follower();

  leader = NULL;

  for (CharIter c = char_list.begin(); c != char_list.end(); c++) {
    if ((*c)->master == this)
      (*c)->stop_follower();
    if ((*c)->leader == this)
      (*c)->leader = *c;
  }

  return;
}

/*
 * Set position of a victim.
 */
void Character::update_pos ()
{
  if (hit > 0) {
    if (position <= POS_STUNNED)
      position = POS_STANDING;
    return;
  }

  if (is_npc () || hit <= -11) {
    position = POS_DEAD;
    return;
  }

  if (hit <= -6)
    position = POS_MORTAL;
  else if (hit <= -3)
    position = POS_INCAP;
  else
    position = POS_STUNNED;

  return;
}

/*
 * Start fights.
 */
void Character::set_fighting (Character * victim)
{
  if (fighting != NULL) {
    bug_printf ("Set_fighting: already fighting");
    return;
  }

  if (is_affected (AFF_SLEEP))
    affect_strip (gsn_sleep);

  fighting = victim;
  position = POS_FIGHTING;

  return;
}

/*
 * Stop fights.
 */
void Character::stop_fighting (bool fBoth)
{
  CharIter c;
  for (c = char_list.begin(); c != char_list.end(); c++) {
    if (*c == this || (fBoth && (*c)->fighting == this)) {
      (*c)->fighting = NULL;
      (*c)->position = POS_STANDING;
      (*c)->update_pos();
    }
  }

  return;
}

bool Character::check_blind ()
{
  if (!is_npc () && IS_SET (actflags, PLR_HOLYLIGHT))
    return true;

  if (is_affected (AFF_BLIND)) {
    send_to_char ("You can't see a thing!\r\n");
    return false;
  }

  return true;
}

int Character::find_door (const std::string & arg)
{
  Exit *pexit;
  int door;

  if (!str_cmp (arg, "n") || !str_cmp (arg, "north"))
    door = 0;
  else if (!str_cmp (arg, "e") || !str_cmp (arg, "east"))
    door = 1;
  else if (!str_cmp (arg, "s") || !str_cmp (arg, "south"))
    door = 2;
  else if (!str_cmp (arg, "w") || !str_cmp (arg, "west"))
    door = 3;
  else if (!str_cmp (arg, "u") || !str_cmp (arg, "up"))
    door = 4;
  else if (!str_cmp (arg, "d") || !str_cmp (arg, "down"))
    door = 5;
  else {
    for (door = 0; door <= 5; door++) {
      if ((pexit = in_room->exit[door]) != NULL
        && IS_SET (pexit->exit_info, EX_ISDOOR)
        && !pexit->keyword.empty() && is_name (arg, pexit->keyword))
        return door;
    }
    act ("I see no $T here.", NULL, arg.c_str(), TO_CHAR);
    return -1;
  }

  if ((pexit = in_room->exit[door]) == NULL) {
    act ("I see no door $T here.", NULL, arg.c_str(), TO_CHAR);
    return -1;
  }

  if (!IS_SET (pexit->exit_info, EX_ISDOOR)) {
    send_to_char ("You can't do that.\r\n");
    return -1;
  }

  return door;
}

bool Character::has_key (int key)
{
  ObjIter o;
  for (o = carrying.begin(); o != carrying.end(); o++) {
    if ((*o)->pIndexData->vnum == key)
      return true;
  }

  return false;
}

void Character::get_obj (Object * obj, Object * container)
{
  if (!obj->can_wear(ITEM_TAKE)) {
    send_to_char ("You can't take that.\r\n");
    return;
  }

  if (carry_number + obj->get_obj_number() > can_carry_n()) {
    act ("$d: you can't carry that many items.",
      NULL, obj->name.c_str(), TO_CHAR);
    return;
  }

  if (carry_weight + obj->get_obj_weight() > can_carry_w()) {
    act ("$d: you can't carry that much weight.",
      NULL, obj->name.c_str(), TO_CHAR);
    return;
  }

  if (container != NULL) {
    act ("You get $p from $P.", obj, container, TO_CHAR);
    act ("$n gets $p from $P.", obj, container, TO_ROOM);
    obj->obj_from_obj ();
  } else {
    act ("You get $p.", obj, container, TO_CHAR);
    act ("$n gets $p.", obj, container, TO_ROOM);
    obj->obj_from_room ();
  }

  if (obj->item_type == ITEM_MONEY) {
    gold += obj->value[0];
    obj->extract_obj ();
  } else {
    obj->obj_to_char (this);
  }

  return;
}

/*
 * Extract a char from the world.
 */
void Character::extract_char (bool fPull)
{
  Object *obj;

  if (in_room == NULL) {
    bug_printf ("Extract_char: NULL.");
    return;
  }

  if (fPull)
    die_follower();

  stop_fighting (true);

  ObjIter o, onext;
  for (o = carrying.begin(); o != carrying.end(); o = onext) {
    obj = *o;
    onext = ++o;
    obj->extract_obj();
  }

  char_from_room ();

  if (!fPull) {
    char_to_room(get_room_index (ROOM_VNUM_ALTAR));
    return;
  }

  if (is_npc ())
    --pIndexData->count;

  if (desc != NULL && desc->original != NULL)
    do_return ("");

  CharIter c;
  for (c = char_list.begin(); c != char_list.end(); c++) {
    if ((*c)->reply == this)
      (*c)->reply = NULL;
  }

  deepchnext = char_list.erase(find(char_list.begin(), char_list.end(), this));

  if (desc)
    desc->character = NULL;
  delete this;
  return;
}

/*
 * Get an extra description from a list.
 */
std::string get_extra_descr (const std::string & name, std::list<ExtraDescription *> & ed)
{
  std::list<ExtraDescription *>::iterator e;
  for (e = ed.begin(); e != ed.end(); e++) {
    if (is_name (name, (*e)->keyword))
      return (*e)->description;
  }
  return "";
}

/*
 * Look for link-dead player to reconnect.
 */
bool Descriptor::check_reconnect (const std::string & name, bool fConn)
{
  Object *obj;

  CharIter c;
  for (c = char_list.begin(); c != char_list.end(); c++) {
    if (!(*c)->is_npc ()
      && (!fConn || (*c)->desc == NULL)
      && !str_cmp (character->name, (*c)->name)) {
      if (fConn == false) {
        character->pcdata->pwd = (*c)->pcdata->pwd;
      } else {
        delete character;
        character = *c;
        (*c)->desc = this;
        (*c)->timer = 0;
        (*c)->send_to_char ("Reconnecting.\r\n");
        (*c)->act ("$n has reconnected.", NULL, NULL, TO_ROOM);
        log_printf ("%s@%s reconnected.", (*c)->name.c_str(), host.c_str());
        connected = CON_PLAYING;

        /*
         * Contributed by Gene Choi
         */
        if ((obj = (*c)->get_eq_char (WEAR_LIGHT)) != NULL
          && obj->item_type == ITEM_LIGHT
          && obj->value[2] != 0 && (*c)->in_room != NULL)
          ++(*c)->in_room->light;
      }
      return true;
    }
  }

  return false;
}

/*
 * Check if already playing.
 */
bool Descriptor::check_playing (const std::string & name)
{
  DescIter dold;

  for (dold = descriptor_list.begin(); dold != descriptor_list.end(); dold++) {
    if (*dold != this
      && (*dold)->character != NULL
      && (*dold)->connected != CON_GET_NAME
      && (*dold)->connected != CON_GET_OLD_PASSWORD
      && !str_cmp (name, (*dold)->original
        ? (*dold)->original->name : (*dold)->character->name)) {
      write_to_buffer ("Already playing.\r\nName: ");
      connected = CON_GET_NAME;
      if (character != NULL) {
        delete character;
        character = NULL;
      }
      return true;
    }
  }

  return false;
}

void Character::stop_idling ()
{
  if (desc == NULL || desc->connected != CON_PLAYING
    || was_in_room == NULL || in_room != get_room_index (ROOM_VNUM_LIMBO))
    return;

  timer = 0;
  char_from_room();
  char_to_room(was_in_room);
  was_in_room = NULL;
  act ("$n has returned from the void.", NULL, NULL, TO_ROOM);
  return;
}

/*
 * Given a name, return the appropriate spec fun.
 */
SPEC_FUN *spec_lookup (const std::string & name)
{
  if (!str_cmp (name, "spec_breath_any"))
    return spec_breath_any;
  if (!str_cmp (name, "spec_breath_acid"))
    return spec_breath_acid;
  if (!str_cmp (name, "spec_breath_fire"))
    return spec_breath_fire;
  if (!str_cmp (name, "spec_breath_frost"))
    return spec_breath_frost;
  if (!str_cmp (name, "spec_breath_gas"))
    return spec_breath_gas;
  if (!str_cmp (name, "spec_breath_lightning"))
    return spec_breath_lightning;
  if (!str_cmp (name, "spec_cast_adept"))
    return spec_cast_adept;
  if (!str_cmp (name, "spec_cast_cleric"))
    return spec_cast_cleric;
  if (!str_cmp (name, "spec_cast_judge"))
    return spec_cast_judge;
  if (!str_cmp (name, "spec_cast_mage"))
    return spec_cast_mage;
  if (!str_cmp (name, "spec_cast_undead"))
    return spec_cast_undead;
  if (!str_cmp (name, "spec_executioner"))
    return spec_executioner;
  if (!str_cmp (name, "spec_fido"))
    return spec_fido;
  if (!str_cmp (name, "spec_guard"))
    return spec_guard;
  if (!str_cmp (name, "spec_janitor"))
    return spec_janitor;
  if (!str_cmp (name, "spec_mayor"))
    return spec_mayor;
  if (!str_cmp (name, "spec_poison"))
    return spec_poison;
  if (!str_cmp (name, "spec_thief"))
    return spec_thief;
  return 0;
}

/*
 * Snarf an 'area' header line.
 */
void load_area (std::ifstream & fp)
{
  Area *pArea;

  pArea = new Area();
  pArea->name = fread_string (fp);
  pArea->age = 15;
  pArea->nplayer = 0;
  area_list.push_back(pArea);
  area_last = pArea;
  return;
}

/*
 * Snarf a help section.
 */
void load_helps (std::ifstream & fp)
{
  Help *pHelp;

  for (;;) {
    pHelp = new Help();
    pHelp->level = fread_number (fp);
    pHelp->keyword = fread_string (fp);
    if (pHelp->keyword[0] == '$')
      break;
    pHelp->text = fread_string (fp);

    if (!str_cmp (pHelp->keyword, "greeting"))
      help_greeting = pHelp->text;

    help_list.push_back(pHelp);
  }

  return;
}

/*
 * MOBprogram code block
*/
/* the functions */

/* This routine transfers between alpha and numeric forms of the
 *  mob_prog bitvector types. This allows the use of the words in the
 *  mob/script files.
 */
int mprog_name_to_type (const std::string & name)
{
  if (!str_cmp (name, "in_file_prog"))
    return IN_FILE_PROG;
  if (!str_cmp (name, "act_prog"))
    return ACT_PROG;
  if (!str_cmp (name, "speech_prog"))
    return SPEECH_PROG;
  if (!str_cmp (name, "rand_prog"))
    return RAND_PROG;
  if (!str_cmp (name, "fight_prog"))
    return FIGHT_PROG;
  if (!str_cmp (name, "hitprcnt_prog"))
    return HITPRCNT_PROG;
  if (!str_cmp (name, "death_prog"))
    return DEATH_PROG;
  if (!str_cmp (name, "entry_prog"))
    return ENTRY_PROG;
  if (!str_cmp (name, "greet_prog"))
    return GREET_PROG;
  if (!str_cmp (name, "all_greet_prog"))
    return ALL_GREET_PROG;
  if (!str_cmp (name, "give_prog"))
    return GIVE_PROG;
  if (!str_cmp (name, "bribe_prog"))
    return BRIBE_PROG;
  return (ERROR_PROG);
}

/* This routine reads in scripts of MOBprograms from a file */
MobProgram *mprog_file_read (const std::string & f, MobProgram *mprg, MobPrototype *pMobIndex)
{
  MobProgram *mprg2;
  std::ifstream progfile;
  char letter;
  bool done = false;
  char MOBProgfile[MAX_INPUT_LENGTH];

  snprintf (MOBProgfile, sizeof MOBProgfile, "%s%s", MOB_DIR, f.c_str());
  progfile.open (MOBProgfile, std::ifstream::in | std::ifstream::binary);
  if (!progfile.is_open()) {
    fatal_printf ("Mob:%d couldnt open mobprog file", pMobIndex->vnum);
  }
  mprg2 = mprg;
  switch (letter = fread_letter (progfile)) {
  case '>':
    break;
  case '|':
    fatal_printf ("empty mobprog file.");
    break;
  default:
    fatal_printf ("in mobprog file syntax error.");
    break;
  }
  while (!done) {
    mprg2->type = mprog_name_to_type (fread_word (progfile));
    switch (mprg2->type) {
    case ERROR_PROG:
      fatal_printf ("mobprog file type error");
      break;
    case IN_FILE_PROG:
      fatal_printf ("mprog file contains a call to file.");
      break;
    default:
      pMobIndex->progtypes = pMobIndex->progtypes | mprg2->type;
      mprg2->arglist = fread_string (progfile);
      mprg2->comlist = fread_string (progfile);
      switch (letter = fread_letter (progfile)) {
      case '>':
        mprg2->next = new MobProgram();
        mprg2 = mprg2->next;
        mprg2->next = NULL;
        break;
      case '|':
        done = true;
        break;
      default:
        fatal_printf ("in mobprog file syntax error.");
        break;
      }
      break;
    }
  }
  progfile.close();
  return mprg2;
}

/* This procedure is responsible for reading any in_file MOBprograms.
 */
void mprog_read_programs (std::ifstream & fp, MobPrototype *pMobIndex)
{
  MobProgram *mprg;
  bool done = false;
  char letter;
  if ((letter = fread_letter (fp)) != '>') {
    fatal_printf ("Load_mobiles: vnum %d MOBPROG char", pMobIndex->vnum);
  }
  pMobIndex->mobprogs = new MobProgram();
  mprg = pMobIndex->mobprogs;
  while (!done) {
    mprg->type = mprog_name_to_type (fread_word (fp));
    switch (mprg->type) {
    case ERROR_PROG:
      fatal_printf ("Load_mobiles: vnum %d MOBPROG type.", pMobIndex->vnum);
      break;
    case IN_FILE_PROG:
      mprg = mprog_file_read (fread_string (fp), mprg, pMobIndex);
      fread_to_eol (fp);
      switch (letter = fread_letter (fp)) {
      case '>':
        mprg->next = new MobProgram();
        mprg = mprg->next;
        mprg->next = NULL;
        break;
      case '|':
        mprg->next = NULL;
        fread_to_eol (fp);
        done = true;
        break;
      default:
        fatal_printf ("Load_mobiles: vnum %d bad MOBPROG.", pMobIndex->vnum);
        break;
      }
      break;
    default:
      pMobIndex->progtypes = pMobIndex->progtypes | mprg->type;
      mprg->arglist = fread_string (fp);
      fread_to_eol (fp);
      mprg->comlist = fread_string (fp);
      fread_to_eol (fp);
      switch (letter = fread_letter (fp)) {
      case '>':
        mprg->next = new MobProgram();
        mprg = mprg->next;
        mprg->next = NULL;
        break;
      case '|':
        mprg->next = NULL;
        fread_to_eol (fp);
        done = true;
        break;
      default:
        fatal_printf ("Load_mobiles: vnum %d bad MOBPROG.", pMobIndex->vnum);
        break;
      }
      break;
    }
  }
}

/*
 * Snarf a mob section.
 */
void load_mobiles (std::ifstream & fp)
{
  MobPrototype *pMobIndex;

  for (;;) {
    sh_int vnum;
    char letter;

    letter = fread_letter (fp);
    if (letter != '#') {
      fatal_printf ("Load_mobiles: # not found.");
    }

    vnum = fread_number (fp);
    if (vnum == 0)
      break;

    fBootDb = false;
    if (get_mob_index (vnum) != NULL) {
      fatal_printf ("Load_mobiles: vnum %d duplicated.", vnum);
    }
    fBootDb = true;

    pMobIndex = new MobPrototype();
    pMobIndex->vnum = vnum;
    pMobIndex->player_name = fread_string (fp);
    pMobIndex->short_descr = fread_string (fp);
    pMobIndex->long_descr = fread_string (fp);
    pMobIndex->description = fread_string (fp);

    pMobIndex->long_descr[0] = toupper (pMobIndex->long_descr[0]);
    pMobIndex->description[0] = toupper (pMobIndex->description[0]);

    pMobIndex->actflags = fread_number (fp) | ACT_IS_NPC;
    pMobIndex->affected_by = fread_number (fp);
    pMobIndex->pShop = NULL;
    pMobIndex->alignment = fread_number (fp);
    letter = fread_letter (fp);
    pMobIndex->level = number_fuzzy (fread_number (fp));
    pMobIndex->sex = fread_number (fp);

    if (letter != 'S') {
      fatal_printf ("Load_mobiles: vnum %d non-S.", vnum);
    }

    letter = fread_letter (fp);
    if (letter == '>') {
      fp.unget();
      mprog_read_programs (fp, pMobIndex);
    } else
      fp.unget();
    mob_table.insert (std::map<int, MobPrototype*>::value_type (vnum, pMobIndex));
    kill_table[URANGE (0, pMobIndex->level, MAX_LEVEL - 1)].number++;
  }

  return;
}

/*
 * Snarf an obj section.
 */
void load_objects (std::ifstream & fp)
{
  ObjectPrototype *pObjIndex;

  for (;;) {
    sh_int vnum;
    char letter;

    letter = fread_letter (fp);
    if (letter != '#') {
      fatal_printf ("Load_objects: # not found.");
    }

    vnum = fread_number (fp);
    if (vnum == 0)
      break;

    fBootDb = false;
    if (get_obj_index (vnum) != NULL) {
      fatal_printf ("Load_objects: vnum %d duplicated.", vnum);
    }
    fBootDb = true;

    pObjIndex = new ObjectPrototype();
    pObjIndex->vnum = vnum;
    pObjIndex->name = fread_string (fp);
    pObjIndex->short_descr = fread_string (fp);
    pObjIndex->description = fread_string (fp);
    /* Action description */ fread_string (fp);

    pObjIndex->short_descr[0] = tolower (pObjIndex->short_descr[0]);
    pObjIndex->description[0] = toupper (pObjIndex->description[0]);

    pObjIndex->item_type = fread_number (fp);
    pObjIndex->extra_flags = fread_number (fp);
    pObjIndex->wear_flags = fread_number (fp);
    pObjIndex->value[0] = fread_number (fp);
    pObjIndex->value[1] = fread_number (fp);
    pObjIndex->value[2] = fread_number (fp);
    pObjIndex->value[3] = fread_number (fp);
    pObjIndex->weight = fread_number (fp);
    pObjIndex->cost = fread_number (fp);        /* Unused */
    /* Cost per day */ fread_number (fp);

    if (pObjIndex->item_type == ITEM_POTION)
      SET_BIT (pObjIndex->extra_flags, ITEM_NODROP);

    for (;;) {
      char letter;

      letter = fread_letter (fp);

      if (letter == 'A') {
        Affect* paf = new Affect();
        paf->type = -1;
        paf->duration = -1;
        paf->location = fread_number (fp);
        paf->modifier = fread_number (fp);
        paf->bitvector = 0;
        pObjIndex->affected.push_back(paf);
      } else if (letter == 'E') {
        ExtraDescription* ed = new ExtraDescription();
        ed->keyword = fread_string (fp);
        ed->description = fread_string (fp);
        pObjIndex->extra_descr.push_back(ed);
      } else {
        fp.unget();
        break;
      }
    }

    // Translate spell "slot numbers" to internal "skill numbers."
    switch (pObjIndex->item_type) {
    case ITEM_PILL:
    case ITEM_POTION:
    case ITEM_SCROLL:
      pObjIndex->value[1] = slot_lookup (pObjIndex->value[1]);
      pObjIndex->value[2] = slot_lookup (pObjIndex->value[2]);
      pObjIndex->value[3] = slot_lookup (pObjIndex->value[3]);
      break;

    case ITEM_STAFF:
    case ITEM_WAND:
      pObjIndex->value[3] = slot_lookup (pObjIndex->value[3]);
      break;
    }

    obj_table.insert (std::map<int, ObjectPrototype*>::value_type (vnum, pObjIndex));
  }

  return;
}

/*
 * Snarf a reset section.
 */
void load_resets (std::ifstream & fp)
{
  Reset *pReset;

  if (area_last == NULL) {
    fatal_printf ("Load_resets: no #AREA seen yet.");
  }

  for (;;) {
    Room *pRoomIndex;
    Exit *pexit;
    char letter;

    if ((letter = fread_letter (fp)) == 'S')
      break;

    if (letter == '*') {
      fread_to_eol (fp);
      continue;
    }

    pReset = new Reset();
    pReset->command = letter;
    /* if_flag */ fread_number (fp);
    pReset->arg1 = fread_number (fp);
    pReset->arg2 = fread_number (fp);
    pReset->arg3 = (letter == 'G' || letter == 'R')
      ? 0 : fread_number (fp);
    fread_to_eol (fp);

    /*
     * Validate parameters.
     * We're calling the index functions for the side effect.
     */
    switch (letter) {
    default:
      fatal_printf ("Load_resets: bad command '%c'.", letter);
      break;

    case 'M':
      get_mob_index (pReset->arg1);
      get_room_index (pReset->arg3);
      break;

    case 'O':
      get_obj_index (pReset->arg1);
      get_room_index (pReset->arg3);
      break;

    case 'P':
      get_obj_index (pReset->arg1);
      get_obj_index (pReset->arg3);
      break;

    case 'G':
    case 'E':
      get_obj_index (pReset->arg1);
      break;

    case 'D':
      pRoomIndex = get_room_index (pReset->arg1);

      if (pReset->arg2 < 0
        || pReset->arg2 > 5
        || (pexit = pRoomIndex->exit[pReset->arg2]) == NULL
        || !IS_SET (pexit->exit_info, EX_ISDOOR)) {
        fatal_printf ("Load_resets: 'D': exit %d not door.", pReset->arg2);
      }

      if (pReset->arg3 < 0 || pReset->arg3 > 2) {
        fatal_printf ("Load_resets: 'D': bad 'locks': %d.", pReset->arg3);
      }

      break;

    case 'R':
      pRoomIndex = get_room_index (pReset->arg1);

      if (pReset->arg2 < 0 || pReset->arg2 > 6) {
        fatal_printf ("Load_resets: 'R': bad exit %d.", pReset->arg2);
      }

      break;
    }

    area_last->reset_list.push_back(pReset);
  }

  return;
}

/*
 * Snarf a room section.
 */
void load_rooms (std::ifstream & fp)
{
  Room *pRoomIndex;

  if (area_last == NULL) {
    fatal_printf ("Load_resets: no #AREA seen yet.");
  }

  for (;;) {
    sh_int vnum;
    char letter;
    int door;

    letter = fread_letter (fp);
    if (letter != '#') {
      fatal_printf ("Load_rooms: # not found.");
    }

    vnum = fread_number (fp);
    if (vnum == 0)
      break;

    fBootDb = false;
    if (get_room_index (vnum) != NULL) {
      fatal_printf ("Load_rooms: vnum %d duplicated.", vnum);
    }
    fBootDb = true;

    pRoomIndex = new Room();
    pRoomIndex->area = area_last;
    pRoomIndex->vnum = vnum;
    pRoomIndex->name = fread_string (fp);
    pRoomIndex->description = fread_string (fp);
    /* Area number */ fread_number (fp);
    pRoomIndex->room_flags = fread_number (fp);
    pRoomIndex->sector_type = fread_number (fp);
    pRoomIndex->light = 0;
    for (door = 0; door <= 5; door++)
      pRoomIndex->exit[door] = NULL;

    for (;;) {
      letter = fread_letter (fp);

      if (letter == 'S')
        break;

      if (letter == 'D') {
        Exit *pexit;
        int locks;

        door = fread_number (fp);
        if (door < 0 || door > 5) {
          fatal_printf ("Fread_rooms: vnum %d has bad door number.", vnum);
        }

        pexit = new Exit();
        pexit->description = fread_string (fp);
        pexit->keyword = fread_string (fp);
        pexit->exit_info = 0;
        locks = fread_number (fp);
        pexit->key = fread_number (fp);
        pexit->vnum = fread_number (fp);

        switch (locks) {
        case 1:
          pexit->exit_info = EX_ISDOOR;
          break;
        case 2:
          pexit->exit_info = EX_ISDOOR | EX_PICKPROOF;
          break;
        }

        pRoomIndex->exit[door] = pexit;
      } else if (letter == 'E') {
        ExtraDescription *ed;

        ed = new ExtraDescription();
        ed->keyword = fread_string (fp);
        ed->description = fread_string (fp);
        pRoomIndex->extra_descr.push_back(ed);
      } else {
        fatal_printf ("Load_rooms: vnum %d has flag not 'DES'.", vnum);
      }
    }

    room_table.insert (std::map<int, Room*>::value_type (vnum, pRoomIndex));
  }

  return;
}

/*
 * Snarf a shop section.
 */
void load_shops (std::ifstream & fp)
{
  Shop *pShop;

  for (;;) {
    MobPrototype *pMobIndex;
    int iTrade;

    pShop = new Shop();
    pShop->keeper = fread_number (fp);
    if (pShop->keeper == 0)
      break;
    for (iTrade = 0; iTrade < MAX_TRADE; iTrade++)
      pShop->buy_type[iTrade] = fread_number (fp);
    pShop->profit_buy = fread_number (fp);
    pShop->profit_sell = fread_number (fp);
    pShop->open_hour = fread_number (fp);
    pShop->close_hour = fread_number (fp);
    fread_to_eol (fp);
    pMobIndex = get_mob_index (pShop->keeper);
    pMobIndex->pShop = pShop;

    shop_list.push_back(pShop);
  }

  return;
}

/*
 * Snarf spec proc declarations.
 */
void load_specials (std::ifstream & fp)
{
  for (;;) {
    MobPrototype *pMobIndex;
    char letter;

    switch (letter = fread_letter (fp)) {
    default:
      fatal_printf ("Load_specials: letter '%c' not *MS.", letter);

    case 'S':
      return;

    case '*':
      break;

    case 'M':
      pMobIndex = get_mob_index (fread_number (fp));
      pMobIndex->spec_fun = spec_lookup (fread_word (fp));
      if (pMobIndex->spec_fun == 0) {
        fatal_printf ("Load_specials: 'M': vnum %d.", pMobIndex->vnum);
      }
      break;
    }

    fread_to_eol (fp);
  }
}

/*
 * Snarf notes file.
 */
void load_notes (void)
{
  std::ifstream fp;

  fp.open (NOTE_FILE, std::ifstream::in | std::ifstream::binary);
  if (!fp.is_open())
    return;

  for (;;) {
    Note *pnote;
    char letter;

    do {
      letter = fp.get();
      if (fp.eof()) {
        fp.close();
        return;
      }
    } while (isspace (letter));
    fp.unget();

    pnote = new Note();

    if (str_cmp (fread_word (fp), "sender"))
      break;
    pnote->sender = fread_string (fp);

    if (str_cmp (fread_word (fp), "date"))
      break;
    pnote->date = fread_string (fp);

    if (str_cmp (fread_word (fp), "stamp"))
      break;
    pnote->date_stamp = fread_number (fp);

    if (str_cmp (fread_word (fp), "to"))
      break;
    pnote->to_list = fread_string (fp);

    if (str_cmp (fread_word (fp), "subject"))
      break;
    pnote->subject = fread_string (fp);

    if (str_cmp (fread_word (fp), "text"))
      break;
    pnote->text = fread_string (fp);

    note_list.push_back(pnote);
  }

  strArea = NOTE_FILE;
  fpArea = &fp;
  fatal_printf ("Load_notes: bad key word.");
  return;
}

/*
 * Translate all room exits from virtual to real.
 * Has to be done after all rooms are read in.
 * Check for bad reverse exits.
 */
void fix_exits (void)
{
  Room *to_room;
  Exit *pexit;
  Exit *pexit_rev;
  int door;

  std::map<int,Room*>::iterator proom;
  for (proom = room_table.begin(); proom != room_table.end(); proom++) {
    bool fexit;

    fexit = false;
    for (door = 0; door <= 5; door++) {
      if ((pexit = (*proom).second->exit[door]) != NULL) {
        fexit = true;
        if (pexit->vnum <= 0)
          pexit->to_room = NULL;
        else
          pexit->to_room = get_room_index (pexit->vnum);
      }
    }

    if (!fexit)
      SET_BIT ((*proom).second->room_flags, ROOM_NO_MOB);
  }

  for (proom = room_table.begin(); proom != room_table.end(); proom++) {
    for (door = 0; door <= 5; door++) {
      if ((pexit = (*proom).second->exit[door]) != NULL
        && (to_room = pexit->to_room) != NULL
        && (pexit_rev = to_room->exit[rev_dir[door]]) != NULL
        && pexit_rev->to_room != (*proom).second) {
        bug_printf ("Fix_exits: %d:%d -> %d:%d -> %d.",
          (*proom).second->vnum, door,
          to_room->vnum, rev_dir[door], (pexit_rev->to_room == NULL)
          ? 0 : pexit_rev->to_room->vnum);
      }
    }
  }

  return;
}

/*
 * Remove an object.
 */
bool Character::remove_obj (int iWear, bool fReplace)
{
  Object *obj;

  if ((obj = get_eq_char (iWear)) == NULL)
    return true;

  if (!fReplace)
    return false;

  if (IS_SET (obj->extra_flags, ITEM_NOREMOVE)) {
    act ("You can't remove $p.", obj, NULL, TO_CHAR);
    return false;
  }

  unequip_char(obj);
  act ("$n stops using $p.", obj, NULL, TO_ROOM);
  act ("You stop using $p.", obj, NULL, TO_CHAR);
  return true;
}

/*
 * Wear one object.
 * Optional replacement of existing objects.
 * Big repetitive code, ick.
 */
void Character::wear_obj (Object * obj, bool fReplace)
{
  char buf[MAX_STRING_LENGTH];

  if (level < obj->level) {
    snprintf (buf, sizeof buf, "You must be level %d to use this object.\r\n", obj->level);
    send_to_char (buf);
    act ("$n tries to use $p, but is too inexperienced.",
      obj, NULL, TO_ROOM);
    return;
  }

  if (obj->item_type == ITEM_LIGHT) {
    if (!remove_obj (WEAR_LIGHT, fReplace))
      return;
    act ("$n lights $p and holds it.", obj, NULL, TO_ROOM);
    act ("You light $p and hold it.", obj, NULL, TO_CHAR);
    equip_char (obj, WEAR_LIGHT);
    return;
  }

  if (obj->can_wear(ITEM_WEAR_FINGER)) {
    if (get_eq_char (WEAR_FINGER_L) != NULL
      && get_eq_char (WEAR_FINGER_R) != NULL
      && !remove_obj (WEAR_FINGER_L, fReplace)
      && !remove_obj (WEAR_FINGER_R, fReplace))
      return;

    if (get_eq_char (WEAR_FINGER_L) == NULL) {
      act ("$n wears $p on $s left finger.", obj, NULL, TO_ROOM);
      act ("You wear $p on your left finger.", obj, NULL, TO_CHAR);
      equip_char (obj, WEAR_FINGER_L);
      return;
    }

    if (get_eq_char (WEAR_FINGER_R) == NULL) {
      act ("$n wears $p on $s right finger.", obj, NULL, TO_ROOM);
      act ("You wear $p on your right finger.", obj, NULL, TO_CHAR);
      equip_char (obj, WEAR_FINGER_R);
      return;
    }

    bug_printf ("Wear_obj: no free finger.");
    send_to_char ("You already wear two rings.\r\n");
    return;
  }

  if (obj->can_wear(ITEM_WEAR_NECK)) {
    if (get_eq_char (WEAR_NECK_1) != NULL
      && get_eq_char (WEAR_NECK_2) != NULL
      && !remove_obj (WEAR_NECK_1, fReplace)
      && !remove_obj (WEAR_NECK_2, fReplace))
      return;

    if (get_eq_char (WEAR_NECK_1) == NULL) {
      act ("$n wears $p around $s neck.", obj, NULL, TO_ROOM);
      act ("You wear $p around your neck.", obj, NULL, TO_CHAR);
      equip_char (obj, WEAR_NECK_1);
      return;
    }

    if (get_eq_char (WEAR_NECK_2) == NULL) {
      act ("$n wears $p around $s neck.", obj, NULL, TO_ROOM);
      act ("You wear $p around your neck.", obj, NULL, TO_CHAR);
      equip_char (obj, WEAR_NECK_2);
      return;
    }

    bug_printf ("Wear_obj: no free neck.");
    send_to_char ("You already wear two neck items.\r\n");
    return;
  }

  if (obj->can_wear(ITEM_WEAR_BODY)) {
    if (!remove_obj (WEAR_BODY, fReplace))
      return;
    act ("$n wears $p on $s body.", obj, NULL, TO_ROOM);
    act ("You wear $p on your body.", obj, NULL, TO_CHAR);
    equip_char (obj, WEAR_BODY);
    return;
  }

  if (obj->can_wear(ITEM_WEAR_HEAD)) {
    if (!remove_obj (WEAR_HEAD, fReplace))
      return;
    act ("$n wears $p on $s head.", obj, NULL, TO_ROOM);
    act ("You wear $p on your head.", obj, NULL, TO_CHAR);
    equip_char (obj, WEAR_HEAD);
    return;
  }

  if (obj->can_wear(ITEM_WEAR_LEGS)) {
    if (!remove_obj (WEAR_LEGS, fReplace))
      return;
    act ("$n wears $p on $s legs.", obj, NULL, TO_ROOM);
    act ("You wear $p on your legs.", obj, NULL, TO_CHAR);
    equip_char (obj, WEAR_LEGS);
    return;
  }

  if (obj->can_wear(ITEM_WEAR_FEET)) {
    if (!remove_obj (WEAR_FEET, fReplace))
      return;
    act ("$n wears $p on $s feet.", obj, NULL, TO_ROOM);
    act ("You wear $p on your feet.", obj, NULL, TO_CHAR);
    equip_char (obj, WEAR_FEET);
    return;
  }

  if (obj->can_wear(ITEM_WEAR_HANDS)) {
    if (!remove_obj (WEAR_HANDS, fReplace))
      return;
    act ("$n wears $p on $s hands.", obj, NULL, TO_ROOM);
    act ("You wear $p on your hands.", obj, NULL, TO_CHAR);
    equip_char (obj, WEAR_HANDS);
    return;
  }

  if (obj->can_wear(ITEM_WEAR_ARMS)) {
    if (!remove_obj (WEAR_ARMS, fReplace))
      return;
    act ("$n wears $p on $s arms.", obj, NULL, TO_ROOM);
    act ("You wear $p on your arms.", obj, NULL, TO_CHAR);
    equip_char (obj, WEAR_ARMS);
    return;
  }

  if (obj->can_wear(ITEM_WEAR_ABOUT)) {
    if (!remove_obj (WEAR_ABOUT, fReplace))
      return;
    act ("$n wears $p about $s body.", obj, NULL, TO_ROOM);
    act ("You wear $p about your body.", obj, NULL, TO_CHAR);
    equip_char (obj, WEAR_ABOUT);
    return;
  }

  if (obj->can_wear(ITEM_WEAR_WAIST)) {
    if (!remove_obj (WEAR_WAIST, fReplace))
      return;
    act ("$n wears $p about $s waist.", obj, NULL, TO_ROOM);
    act ("You wear $p about your waist.", obj, NULL, TO_CHAR);
    equip_char (obj, WEAR_WAIST);
    return;
  }

  if (obj->can_wear(ITEM_WEAR_WRIST)) {
    if (get_eq_char (WEAR_WRIST_L) != NULL
      && get_eq_char (WEAR_WRIST_R) != NULL
      && !remove_obj (WEAR_WRIST_L, fReplace)
      && !remove_obj (WEAR_WRIST_R, fReplace))
      return;

    if (get_eq_char (WEAR_WRIST_L) == NULL) {
      act ("$n wears $p around $s left wrist.", obj, NULL, TO_ROOM);
      act ("You wear $p around your left wrist.", obj, NULL, TO_CHAR);
      equip_char (obj, WEAR_WRIST_L);
      return;
    }

    if (get_eq_char (WEAR_WRIST_R) == NULL) {
      act ("$n wears $p around $s right wrist.", obj, NULL, TO_ROOM);
      act ("You wear $p around your right wrist.", obj, NULL, TO_CHAR);
      equip_char (obj, WEAR_WRIST_R);
      return;
    }

    bug_printf ("Wear_obj: no free wrist.");
    send_to_char ("You already wear two wrist items.\r\n");
    return;
  }

  if (obj->can_wear( ITEM_WEAR_SHIELD)) {
    if (!remove_obj (WEAR_SHIELD, fReplace))
      return;
    act ("$n wears $p as a shield.", obj, NULL, TO_ROOM);
    act ("You wear $p as a shield.", obj, NULL, TO_CHAR);
    equip_char (obj, WEAR_SHIELD);
    return;
  }

  if (obj->can_wear(ITEM_WIELD)) {
    if (!remove_obj (WEAR_WIELD, fReplace))
      return;

    if (obj->get_obj_weight() > str_app[get_curr_str()].wield) {
      send_to_char ("It is too heavy for you to wield.\r\n");
      return;
    }

    act ("$n wields $p.", obj, NULL, TO_ROOM);
    act ("You wield $p.", obj, NULL, TO_CHAR);
    equip_char (obj, WEAR_WIELD);
    return;
  }

  if (obj->can_wear(ITEM_HOLD)) {
    if (!remove_obj (WEAR_HOLD, fReplace))
      return;
    act ("$n holds $p in $s hands.", obj, NULL, TO_ROOM);
    act ("You hold $p in your hands.", obj, NULL, TO_CHAR);
    equip_char (obj, WEAR_HOLD);
    return;
  }

  if (fReplace)
    send_to_char ("You can't wear, wield, or hold that.\r\n");

  return;
}

/*
 * Create an instance of a mobile.
 */
Character * MobPrototype::create_mobile ()
{
  Character *mob;

  if (this == NULL) {
    fatal_printf ("Create_mobile: NULL this.");
  }

  mob = new Character();

  mob->pIndexData = this;

  mob->name = player_name;
  mob->short_descr = short_descr;
  mob->long_descr = long_descr;
  mob->description = description;
  mob->spec_fun = spec_fun;
  mob->prompt = "<%h %m %v>";

  mob->level = number_fuzzy (level);
  mob->actflags = actflags;
  mob->affected_by = affected_by;
  mob->alignment = alignment;
  mob->sex = sex;

  mob->armor = interpolate (mob->level, 100, -100);

  mob->max_hit = mob->level * 8 + number_range (mob->level * mob->level / 4,
    mob->level * mob->level);
  mob->hit = mob->max_hit;

  /*
   * Insert in list.
   */
  char_list.push_back(mob);
  count++;
  return mob;
}

/*
 * Create an instance of an object.
 */
Object * ObjectPrototype::create_object (int lvl)
{
  Object *obj;

  if (this == NULL) {
    fatal_printf ("Create_object: NULL this.");
  }

  obj = new Object();

  obj->pIndexData = this;
  obj->in_room = NULL;
  obj->level = lvl;
  obj->wear_loc = -1;

  obj->name = name;
  obj->short_descr = short_descr;
  obj->description = description;
  obj->item_type = item_type;
  obj->extra_flags = extra_flags;
  obj->wear_flags = wear_flags;
  obj->value[0] = value[0];
  obj->value[1] = value[1];
  obj->value[2] = value[2];
  obj->value[3] = value[3];
  obj->weight = weight;
  obj->cost = number_fuzzy (10)
    * number_fuzzy (lvl) * number_fuzzy (lvl);

  /*
   * Mess with object properties.
   */
  switch (obj->item_type) {
  default:
    bug_printf ("Read_object: vnum %d bad type.", vnum);
    break;

  case ITEM_LIGHT:
  case ITEM_TREASURE:
  case ITEM_FURNITURE:
  case ITEM_TRASH:
  case ITEM_CONTAINER:
  case ITEM_DRINK_CON:
  case ITEM_KEY:
  case ITEM_FOOD:
  case ITEM_BOAT:
  case ITEM_CORPSE_NPC:
  case ITEM_CORPSE_PC:
  case ITEM_FOUNTAIN:
    break;

  case ITEM_SCROLL:
    obj->value[0] = number_fuzzy (obj->value[0]);
    break;

  case ITEM_WAND:
  case ITEM_STAFF:
    obj->value[0] = number_fuzzy (obj->value[0]);
    obj->value[1] = number_fuzzy (obj->value[1]);
    obj->value[2] = obj->value[1];
    break;

  case ITEM_WEAPON:
    obj->value[1] = number_fuzzy (number_fuzzy (1 * lvl / 4 + 2));
    obj->value[2] = number_fuzzy (number_fuzzy (3 * lvl / 4 + 6));
    break;

  case ITEM_ARMOR:
    obj->value[0] = number_fuzzy (lvl / 4 + 2);
    break;

  case ITEM_POTION:
  case ITEM_PILL:
    obj->value[0] = number_fuzzy (number_fuzzy (obj->value[0]));
    break;

  case ITEM_MONEY:
    obj->value[0] = obj->cost;
    break;
  }

  object_list.push_back(obj);
  count++;

  return obj;
}

/*
 * Create a 'money' obj.
 */
Object *create_money (int amount)
{
  char buf[MAX_STRING_LENGTH];
  Object *obj;

  if (amount <= 0) {
    bug_printf ("Create_money: zero or negative money %d.", amount);
    amount = 1;
  }

  if (amount == 1) {
    obj = get_obj_index(OBJ_VNUM_MONEY_ONE)->create_object(0);
  } else {
    obj = get_obj_index(OBJ_VNUM_MONEY_SOME)->create_object(0);
    snprintf (buf, sizeof buf, obj->short_descr.c_str(), amount);
    obj->short_descr = buf;
    obj->value[0] = amount;
  }

  return obj;
}

/*
 * It is very important that this be an equivalence relation:
 * (1) A ~ A
 * (2) if A ~ B then B ~ A
 * (3) if A ~ B  and B ~ C, then A ~ C
 */
bool is_same_group (Character * ach, Character * bch)
{
  if (ach->leader != NULL)
    ach = ach->leader;
  if (bch->leader != NULL)
    bch = bch->leader;
  return ach == bch;
}

std::string Object::format_obj_to_char (Character * ch, bool fShort)
{
  std::string buf;

  if (is_obj_stat(ITEM_INVIS))
    buf.append("(Invis) ");
  if (ch->is_affected (AFF_DETECT_EVIL) && is_obj_stat(ITEM_EVIL))
    buf.append("(Red Aura) ");
  if (ch->is_affected (AFF_DETECT_MAGIC) && is_obj_stat(ITEM_MAGIC))
    buf.append("(Magical) ");
  if (is_obj_stat(ITEM_GLOW))
    buf.append("(Glowing) ");
  if (is_obj_stat(ITEM_HUM))
    buf.append("(Humming) ");

  if (fShort) {
    if (!short_descr.empty())
      buf.append(short_descr);
  } else {
    if (!description.empty())
      buf.append(description);
  }

  return buf;
}

/*
 * Show a list to a character.
 * Can coalesce duplicated items.
 */
void Character::show_list_to_char (std::list<Object *> & list, bool fShort,
  bool fShowNothing)
{
  char buf[MAX_STRING_LENGTH];
  int nShow;
  int iShow;
  int count;
  bool fCombine;

  if (desc == NULL)
    return;

  /*
   * Alloc space for output lines.
   */
  std::string * prgpstrShow = new std::string[list.size()];
  int * prgnShow = new int[list.size()];
  nShow = 0;

  /*
   * Format the list of objects.
   */
  ObjIter obj;
  for (obj = list.begin(); obj != list.end(); obj++) {
    if ((*obj)->wear_loc == WEAR_NONE && can_see_obj(*obj)) {
      std::string pstrShow = (*obj)->format_obj_to_char (this, fShort);
      fCombine = false;

      if (is_npc () || IS_SET (actflags, PLR_COMBINE)) {
        /*
         * Look for duplicates, case sensitive.
         * Matches tend to be near end so run loop backwords.
         */
        for (iShow = nShow - 1; iShow >= 0; iShow--) {
          if (!strcmp (prgpstrShow[iShow].c_str(), pstrShow.c_str())) {
            prgnShow[iShow]++;
            fCombine = true;
            break;
          }
        }
      }

      /*
       * Couldn't combine, or didn't want to.
       */
      if (!fCombine) {
        prgpstrShow[nShow] = pstrShow;
        prgnShow[nShow] = 1;
        nShow++;
      }
    }
  }

  /*
   * Output the formatted list.
   */
  for (iShow = 0; iShow < nShow; iShow++) {
    if (is_npc () || IS_SET (actflags, PLR_COMBINE)) {
      if (prgnShow[iShow] != 1) {
        snprintf (buf, sizeof buf, "(%2d) ", prgnShow[iShow]);
        send_to_char (buf);
      } else {
        send_to_char ("     ");
      }
    }
    send_to_char (prgpstrShow[iShow]);
    send_to_char ("\r\n");
  }

  if (fShowNothing && nShow == 0) {
    if (is_npc () || IS_SET (actflags, PLR_COMBINE))
      send_to_char ("     ");
    send_to_char ("Nothing.\r\n");
  }

  /*
   * Clean up.
   */
  delete [] prgnShow;
  delete [] prgpstrShow;

  return;
}

void Character::show_char_to_char_0 (Character * victim)
{
  std::string buf;

  if (victim->is_affected (AFF_INVISIBLE))
    buf.append("(Invis) ");
  if (victim->is_affected (AFF_HIDE))
    buf.append("(Hide) ");
  if (victim->is_affected (AFF_CHARM))
    buf.append("(Charmed) ");
  if (victim->is_affected (AFF_PASS_DOOR))
    buf.append("(Translucent) ");
  if (victim->is_affected (AFF_FAERIE_FIRE))
    buf.append("(Pink Aura) ");
  if (victim->is_evil () && is_affected (AFF_DETECT_EVIL))
    buf.append("(Red Aura) ");
  if (victim->is_affected (AFF_SANCTUARY))
    buf.append("(White Aura) ");
  if (!victim->is_npc () && IS_SET (victim->actflags, PLR_KILLER))
    buf.append("(KILLER) ");
  if (!victim->is_npc () && IS_SET (victim->actflags, PLR_THIEF))
    buf.append("(THIEF) ");

  if (victim->position == POS_STANDING && !victim->long_descr.empty()) {
    buf.append(victim->long_descr);
    send_to_char (buf);
    return;
  }

  buf.append(victim->describe_to(this));
  if (!victim->is_npc () && !IS_SET (actflags, PLR_BRIEF))
    buf.append(victim->pcdata->title);

  switch (victim->position) {
  case POS_DEAD:
    buf.append(" is DEAD!!");
    break;
  case POS_MORTAL:
    buf.append(" is mortally wounded.");
    break;
  case POS_INCAP:
    buf.append(" is incapacitated.");
    break;
  case POS_STUNNED:
    buf.append(" is lying here stunned.");
    break;
  case POS_SLEEPING:
    buf.append(" is sleeping here.");
    break;
  case POS_RESTING:
    buf.append(" is resting here.");
    break;
  case POS_STANDING:
    buf.append(" is here.");
    break;
  case POS_FIGHTING:
    buf.append(" is here, fighting ");
    if (victim->fighting == NULL)
      buf.append("thin air??");
    else if (victim->fighting == this)
      buf.append("YOU!");
    else if (victim->in_room == victim->fighting->in_room) {
      buf.append(victim->fighting->describe_to(this));
      buf.append(".");
    } else
      buf.append("somone who left??");
    break;
  }

  buf.append("\r\n");
  buf[0] = toupper(buf[0]);
  send_to_char (buf);
  return;
}

void Character::show_char_to_char_1 (Character * victim)
{
  std::string buf;
  Object *obj;
  int iWear;
  int percent;
  bool found;

  if (victim->can_see(this)) {
    act ("$n looks at you.", NULL, victim, TO_VICT);
    act ("$n looks at $N.", NULL, victim, TO_NOTVICT);
  }

  if (victim->description[0] != '\0') {
    send_to_char (victim->description);
  } else {
    act ("You see nothing special about $M.", NULL, victim, TO_CHAR);
  }

  if (victim->max_hit > 0)
    percent = (100 * victim->hit) / victim->max_hit;
  else
    percent = -1;

  buf = victim->describe_to(this);

  if (percent >= 100)
    buf.append(" is in perfect health.\r\n");
  else if (percent >= 90)
    buf.append(" is slightly scratched.\r\n");
  else if (percent >= 80)
    buf.append(" has a few bruises.\r\n");
  else if (percent >= 70)
    buf.append(" has some cuts.\r\n");
  else if (percent >= 60)
    buf.append(" has several wounds.\r\n");
  else if (percent >= 50)
    buf.append(" has many nasty wounds.\r\n");
  else if (percent >= 40)
    buf.append(" is bleeding freely.\r\n");
  else if (percent >= 30)
    buf.append(" is covered in blood.\r\n");
  else if (percent >= 20)
    buf.append(" is leaking guts.\r\n");
  else if (percent >= 10)
    buf.append(" is almost dead.\r\n");
  else
    buf.append(" is DYING.\r\n");

  buf[0] = toupper (buf[0]);
  send_to_char (buf);

  found = false;
  for (iWear = 0; iWear < MAX_WEAR; iWear++) {
    if ((obj = victim->get_eq_char (iWear)) != NULL && can_see_obj(obj)) {
      if (!found) {
        send_to_char ("\r\n");
        act ("$N is using:", NULL, victim, TO_CHAR);
        found = true;
      }
      send_to_char (where_name[iWear]);
      send_to_char (obj->format_obj_to_char (this, true));
      send_to_char ("\r\n");
    }
  }

  if (victim != this && !is_npc ()
    && number_percent () < pcdata->learned[gsn_peek]) {
    send_to_char ("\r\nYou peek at the inventory:\r\n");
    show_list_to_char (victim->carrying, true, true);
  }

  return;
}

void Character::show_char_to_char (std::list<Character *> & list)
{
  CharIter rch;

  for (rch = list.begin(); rch != list.end(); rch++) {
    if (*rch == this)
      continue;

    if (!(*rch)->is_npc ()
      && IS_SET ((*rch)->actflags, PLR_WIZINVIS)
      && get_trust () < (*rch)->get_trust ())
      continue;

    if (can_see(*rch)) {
      show_char_to_char_0 (*rch);
    } else if (in_room->is_dark()
      && (*rch)->is_affected (AFF_INFRARED)) {
      send_to_char ("You see glowing red eyes watching YOU!\r\n");
    }
  }

  return;
}

void Character::move_char (int door)
{
  Character *fch;
  Room *in_rm;
  Room *to_room;
  Exit *pexit;

  if (door < 0 || door > 5) {
    bug_printf ("Do_move: bad door %d.", door);
    return;
  }

  in_rm = in_room;
  if ((pexit = in_rm->exit[door]) == NULL
    || (to_room = pexit->to_room) == NULL) {
    send_to_char ("Alas, you cannot go that way.\r\n");
    return;
  }

  if (IS_SET (pexit->exit_info, EX_CLOSED)
    && !is_affected (AFF_PASS_DOOR)) {
    act ("The $d is closed.", NULL, pexit->keyword.c_str(), TO_CHAR);
    return;
  }

  if (is_affected (AFF_CHARM)
    && master != NULL && in_rm == master->in_room) {
    send_to_char ("What?  And leave your beloved master?\r\n");
    return;
  }

  if (to_room->is_private()) {
    send_to_char ("That room is private right now.\r\n");
    return;
  }

  if (!is_npc ()) {
    int iClass;
    int mv;

    for (iClass = 0; iClass < CLASS_MAX; iClass++) {
      if (iClass != klass && to_room->vnum == class_table[iClass].guild) {
        send_to_char ("You aren't allowed in there.\r\n");
        return;
      }
    }

    if (in_rm->sector_type == SECT_AIR || to_room->sector_type == SECT_AIR) {
      if (!is_affected (AFF_FLYING)) {
        send_to_char ("You can't fly.\r\n");
        return;
      }
    }

    if (in_rm->sector_type == SECT_WATER_NOSWIM
      || to_room->sector_type == SECT_WATER_NOSWIM) {
      /*
       * Look for a boat.
       */
      bool found = false;

      /*
       * Suggestion for flying above water by Sludge
       */
      if (is_affected (AFF_FLYING))
        found = true;

      for (ObjIter o = carrying.begin(); o != carrying.end(); o++) {
        if ((*o)->item_type == ITEM_BOAT) {
          found = true;
          break;
        }
      }
      if (!found) {
        send_to_char ("You need a boat to go there.\r\n");
        return;
      }
    }

    mv = movement_loss[std::min (SECT_MAX - 1, in_rm->sector_type)]
      + movement_loss[std::min (SECT_MAX - 1, to_room->sector_type)];

    if (move < mv) {
      send_to_char ("You are too exhausted.\r\n");
      return;
    }

    wait_state (1);
    move -= mv;
  }

  if (!is_affected (AFF_SNEAK)
    && (is_npc () || !IS_SET (actflags, PLR_WIZINVIS)))
    act ("$n leaves $T.", NULL, dir_name[door].c_str(), TO_ROOM);

  char_from_room();
  char_to_room(to_room);
  if (!is_affected (AFF_SNEAK)
    && (is_npc () || !IS_SET (actflags, PLR_WIZINVIS)))
    act ("$n has arrived.", NULL, NULL, TO_ROOM);

  do_look ("auto");

  CharIter rch, next;
  for (rch = in_rm->people.begin(); rch != in_rm->people.end(); rch = next) {
    fch = *rch;
    next = ++rch;
    if (fch->master == this && fch->position == POS_STANDING) {
      fch->act ("You follow $N.", NULL, this, TO_CHAR);
      fch->move_char (door);
    }
  }

  if (this)
    mprog_entry_trigger (this);
  if (this)
    mprog_greet_trigger (this);
  return;
}

bool is_note_to (Character * ch, Note * pnote)
{
  if (!str_cmp (ch->name, pnote->sender))
    return true;

  if (is_name ("all", pnote->to_list))
    return true;

  if (ch->is_hero() && is_name ("immortal", pnote->to_list))
    return true;

  if (is_name (ch->name, pnote->to_list))
    return true;

  return false;
}

void note_attach (Character * ch)
{
  Note *pnote;

  if (ch->pnote != NULL)
    return;

  pnote = new Note();

  pnote->sender = ch->name;
  ch->pnote = pnote;
  return;
}

void note_remove (Character * ch, Note * pnote)
{
  std::string to_new, to_one, to_list;

  /*
   * Build a new to_list.
   * Strip out this recipient.
   */
  to_list = pnote->to_list;
  while (!to_list.empty()) {
    to_list = one_argument (to_list, to_one);
    if (!to_list.empty() && str_cmp (ch->name, to_one)) {
      to_new.append(" ");
      to_new.append(to_one);
    }
  }

  /*
   * Just a simple recipient removal?
   */
  if (str_cmp (ch->name, pnote->sender) && !to_new.empty()) {
    pnote->to_list = to_new.substr(1);
    return;
  }

  /*
   * Remove note from linked list.
   */
  note_list.erase(find(note_list.begin(),note_list.end(),pnote));
  delete pnote;

  /*
   * Rewrite entire list.
   */
  std::ofstream notefile;

  notefile.open (NOTE_FILE, std::ofstream::out | std::ofstream::binary);
  if (!notefile.is_open()) {
    perror (NOTE_FILE);
  } else {
    for (std::list<Note*>::iterator p = note_list.begin();
      p != note_list.end(); p++) {
      notefile << "Sender  " << (*p)->sender << "~\n";
      notefile << "Date    " << (*p)->date << "~\n";
      notefile << "Stamp   " << (*p)->date_stamp << "\n";
      notefile << "To      " << (*p)->to_list << "~\n";
      notefile << "Subject " << (*p)->subject << "~\n";
      notefile << "Text\n" << (*p)->text << "~\n\n";
    }
    notefile.close();
  }
  return;
}

bool Character::check_social (const std::string & command, const std::string & argument)
{
  std::string arg;
  Character *victim;
  int cmd;
  bool found = false;
  char *sql = sqlite3_mprintf(
    "SELECT name, char_no_arg, others_no_arg, char_found, others_found, vict_found, char_auto, others_auto FROM socials WHERE NAME LIKE '%q%%'",
    command.c_str());
  sqlite3_stmt *stmt = NULL;

  if (sqlite3_prepare(database, sql, -1, &stmt, 0) != SQLITE_OK) {
    bug_printf("Could not prepare statement: %s", sqlite3_errmsg(database));
    sqlite3_free(sql);
    return false;
  }

  if (sqlite3_step(stmt) == SQLITE_ROW) {
    found = true;
  }

  if (!found) {
    sqlite3_finalize(stmt);
    sqlite3_free(sql);
    return false;
  }

  if (!is_npc () && IS_SET (actflags, PLR_NO_EMOTE)) {
    send_to_char ("You are anti-social!\r\n");
    sqlite3_finalize(stmt);
    sqlite3_free(sql);
    return true;
  }

  switch (position) {
  case POS_DEAD:
    send_to_char ("Lie still; you are DEAD.\r\n");
    sqlite3_finalize(stmt);
    sqlite3_free(sql);
    return true;

  case POS_INCAP:
  case POS_MORTAL:
    send_to_char ("You are hurt far too bad for that.\r\n");
    sqlite3_finalize(stmt);
    sqlite3_free(sql);
    return true;

  case POS_STUNNED:
    send_to_char ("You are too stunned to do that.\r\n");
    sqlite3_finalize(stmt);
    sqlite3_free(sql);
    return true;

  case POS_SLEEPING:
    /*
     * I just know this is the path to a 12" 'if' statement.  :(
     * But two players asked for it already!  -- Furey
     */
    if (!str_cmp ((const char*)sqlite3_column_text( stmt, 0 ), "snore"))
      break;
    send_to_char ("In your dreams, or what?\r\n");
    sqlite3_finalize(stmt);
    sqlite3_free(sql);
    return true;

  }

  one_argument (argument, arg);
  victim = NULL;
  if (arg.empty()) {
    act ((const char*)sqlite3_column_text( stmt, 2 ), NULL, victim, TO_ROOM);
    act ((const char*)sqlite3_column_text( stmt, 1 ), NULL, victim, TO_CHAR);
  } else if ((victim = get_char_room (arg)) == NULL) {
    send_to_char ("They aren't here.\r\n");
  } else if (victim == this) {
    act ((const char*)sqlite3_column_text( stmt, 7 ), NULL, victim, TO_ROOM);
    act ((const char*)sqlite3_column_text( stmt, 6 ), NULL, victim, TO_CHAR);
  } else {
    act ((const char*)sqlite3_column_text( stmt, 4 ), NULL, victim, TO_NOTVICT);
    act ((const char*)sqlite3_column_text( stmt, 3 ), NULL, victim, TO_CHAR);
    act ((const char*)sqlite3_column_text( stmt, 5 ), NULL, victim, TO_VICT);

    if (!is_npc () && victim->is_npc ()
      && !victim->is_affected (AFF_CHARM)
      && victim->is_awake ()) {
      switch (number_range (0, 15)) {
      case 0:
        multi_hit (victim, this, TYPE_UNDEFINED);
        break;

      case 1:
      case 2:
      case 3:
      case 4:
      case 5:
      case 6:
      case 7:
      case 8:
        victim->act ((const char*)sqlite3_column_text( stmt, 4 ), NULL, this, TO_NOTVICT);
        victim->act ((const char*)sqlite3_column_text( stmt, 3 ), NULL, this, TO_CHAR);
        victim->act ((const char*)sqlite3_column_text( stmt, 5 ), NULL, this, TO_VICT);
        break;

      case 9:
      case 10:
      case 11:
      case 12:
        victim->act ("$n slaps $N.", NULL, this, TO_NOTVICT);
        victim->act ("You slap $N.", NULL, this, TO_CHAR);
        victim->act ("$n slaps you.", NULL, this, TO_VICT);
        break;
      }
    }
  }

  sqlite3_finalize(stmt);
  sqlite3_free(sql);
  return true;
}

/*
 * The main entry point for executing commands.
 * Can be recursively called from 'at', 'order', 'force'.
 */
void Character::interpret (std::string argument)
{
  std::string command;
  int cmd;
  bool found;

  if (desc != NULL)
    desc->incomm.erase();
  /*
   * Strip leading spaces.
   */
  argument.erase(0, argument.find_first_not_of(" "));
  if (argument.empty())
    return;

  /*
   * No hiding.
   */
  REMOVE_BIT (affected_by, AFF_HIDE);

  /*
   * Implement freeze command.
   */
  if (!is_npc () && IS_SET (actflags, PLR_FREEZE)) {
    send_to_char ("You're totally frozen!\r\n");
    return;
  }

  /*
   * Grab the command word.
   * Special parsing so ' can be a command,
   *   also no spaces needed after punctuation.
   */
  if (!isalpha (argument[0]) && !isdigit (argument[0])) {
    command.assign(argument, 0, 1);
    argument.erase(0, 1);
    argument.erase(0, argument.find_first_not_of(" "));
  } else {
    argument = one_argument(argument, command);
  }

  /*
   * Look for command in command table.
   */
  found = false;
  int trst = get_trust ();
  for (cmd = 0; cmd_table[cmd].name[0] != '\0'; cmd++) {
    if (command[0] == cmd_table[cmd].name[0]
      && !str_prefix (command, cmd_table[cmd].name)
      && (cmd_table[cmd].level <= trst || mp_commands())) {
      found = true;
      break;
    }
  }

  if (!found) {
    /*
     * Look for command in socials table.
     */
    if (!check_social (command, argument))
      send_to_char ("Huh?\r\n");
    return;
  }

  /*
   * Character not in position for command?
   */
  if (position < cmd_table[cmd].position) {
    switch (position) {
    case POS_DEAD:
      send_to_char ("Lie still; you are DEAD.\r\n");
      break;

    case POS_MORTAL:
    case POS_INCAP:
      send_to_char ("You are hurt far too bad for that.\r\n");
      break;

    case POS_STUNNED:
      send_to_char ("You are too stunned to do that.\r\n");
      break;

    case POS_SLEEPING:
      send_to_char ("In your dreams, or what?\r\n");
      break;

    case POS_RESTING:
      send_to_char ("Nah... You feel too relaxed...\r\n");
      break;

    case POS_FIGHTING:
      send_to_char ("No way!  You are still fighting!\r\n");
      break;

    }
    return;
  }

  /*
   * Dispatch the command.
   */
  (this->*(cmd_table[cmd].do_fun)) (argument);


  tail_chain ();
  return;
}

/* This routine handles the variables for command expansion.
 * If you want to add any go right ahead, it should be fairly
 * clear how it is done and they are quite easy to do, so you
 * can be as creative as you want. The only catch is to check
 * that your variables exist before you use them. At the moment,
 * using $t when the secondary target refers to an object
 * i.e. >prog_act drops~<nl>if ispc($t)<nl>sigh<nl>endif<nl>~<nl>
 * probably makes the mud crash (vice versa as well) The cure
 * would be to change act() so that vo becomes vict & v_obj.
 * but this would require a lot of small changes all over the code.
 */
void mprog_translate (char ch, std::string & t, Character * mob, Character * actor,
  Object * obj, void *vo, Character * rndm)
{
  static char *he_she[] = { "it", "he", "she" };
  static char *him_her[] = { "it", "him", "her" };
  static char *his_her[] = { "its", "his", "her" };
  Character *vict = (Character *) vo;
  Object *v_obj = (Object *) vo;

  t.erase();
  switch (ch) {
  case 'i':
    one_argument (mob->name, t);
    break;

  case 'I':
    t = mob->short_descr;
    break;

  case 'n':
    if (actor && mob->can_see(actor)) {
      one_argument (actor->name, t);
      if (!actor->is_npc ())
        t[0] = toupper(t[0]);
    }
    break;

  case 'N':
    if (actor) {
      if (mob->can_see(actor)) {
        if (actor->is_npc ())
          t = actor->short_descr;
        else
          t = actor->name + " " + actor->pcdata->title;
      } else {
        t = "someone";
      }
    }
    break;

  case 't':
    if (vict && mob->can_see(vict)) {
      one_argument (vict->name, t);
      if (!vict->is_npc ())
        t[0] = toupper(t[0]);
    }
    break;

  case 'T':
    if (vict) {
      if (mob->can_see(vict)) {
        if (vict->is_npc ())
          t = vict->short_descr;
        else
          t = vict->name + " " + vict->pcdata->title;
      } else {
        t = "someone";
      }
    }
    break;

  case 'r':
    if (rndm && mob->can_see(rndm)) {
      one_argument (rndm->name, t);
      if (!rndm->is_npc ())
        t[0] = toupper(t[0]);
    }
    break;

  case 'R':
    if (rndm) {
      if (mob->can_see(rndm)) {
        if (rndm->is_npc ())
          t = rndm->short_descr;
        else
          t = rndm->name + " " + rndm->pcdata->title;
      } else {
        t = "someone";
      }
    }
    break;

  case 'e':
    if (actor) {
      if (mob->can_see(actor))
        t = he_she[actor->sex];
      else
        t = "someone";
    }
    break;

  case 'm':
    if (actor) {
      if (mob->can_see(actor))
        t = him_her[actor->sex];
      else
        t = "someone";
    }
    break;

  case 's':
    if (actor) {
      if (mob->can_see(actor))
        t = his_her[actor->sex];
      else
        t = "someone's";
    }
    break;

  case 'E':
    if (vict) {
      if (mob->can_see(vict))
        t = he_she[vict->sex];
      else
        t = "someone";
    }
    break;

  case 'M':
    if (vict) {
      if (mob->can_see(vict))
        t = him_her[vict->sex];
      else
        t = "someone";
    }
    break;

  case 'S':
    if (vict) {
      if (mob->can_see(vict))
        t = his_her[vict->sex];
      else
        t = "someone's";
    }
    break;

  case 'j':
    t = he_she[mob->sex];
    break;

  case 'k':
    t = him_her[mob->sex];
    break;

  case 'l':
    t = his_her[mob->sex];
    break;

  case 'J':
    if (rndm) {
      if (mob->can_see(rndm))
        t = he_she[rndm->sex];
      else
        t = "someone";
    }
    break;

  case 'K':
    if (rndm) {
      if (mob->can_see(rndm))
        t = him_her[rndm->sex];
      else
        t = "someone";
    }
    break;

  case 'L':
    if (rndm) {
      if (mob->can_see(rndm))
        t = his_her[rndm->sex];
      else
        t = "someone's";
    }
    break;

  case 'o':
    if (obj) {
      if (mob->can_see_obj(obj))
        one_argument (obj->name, t);
      else
        t = "something";
    }
    break;

  case 'O':
    if (obj) {
      if (mob->can_see_obj(obj))
        t = obj->short_descr;
      else
        t = "something";
    }
    break;

  case 'p':
    if (v_obj) {
      if (mob->can_see_obj(v_obj))
        one_argument (v_obj->name, t);
      else
        t = "something";
    }
    break;

  case 'P':
    if (v_obj) {
      if (mob->can_see_obj(v_obj))
        t = v_obj->short_descr;
      else
        t = "something";
    }
    break;

  case 'a':
    if (obj)
      switch (obj->name[0]) {
      case 'a':
      case 'e':
      case 'i':
      case 'o':
      case 'u':
        t = "an";
        break;
      default:
        t = "a";
      }
    break;

  case 'A':
    if (v_obj)
      switch (v_obj->name[0]) {
      case 'a':
      case 'e':
      case 'i':
      case 'o':
      case 'u':
        t = "an";
        break;
      default:
        t = "a";
      }
    break;

  case '$':
    t = "$";
    break;

  default:
    bug_printf ("Mob: %d bad $var", mob->pIndexData->vnum);
    break;
  }

  return;

}

/* This procedure simply copies the cmnd to a buffer while expanding
 * any variables by calling the translate procedure.  The observant
 * code scrutinizer will notice that this is taken from act()
 */
void mprog_process_cmnd (const std::string & cmnd, Character * mob,
  Character * actor, Object * obj, void *vo, Character * rndm)
{
  std::string buf;
  std::string tmp;
  std::string::const_iterator str;
  str = cmnd.begin();

  while (str != cmnd.end()) {
    if (*str != '$') {
      buf.append(1, *str);
      str++;
      continue;
    }
    str++;
    mprog_translate (*str, tmp, mob, actor, obj, vo, rndm);
    buf.append(tmp);
    str++;
  }
  mob->interpret (buf);

  return;

}

/* Used to get sequential lines of a multi line string (separated by "\r\n")
 * Thus its like one_argument(), but a trifle different. It is destructive
 * to the multi line string argument, and thus clist must not be shared.
 */
std::string mprog_next_command (std::string & clist, std::string & cmd)
{
  std::string::iterator pointer = clist.begin();

  while (*pointer != '\n' && *pointer != '\r' && pointer != clist.end())
    pointer++;
  cmd.assign(clist.begin(), pointer);
  while ((*pointer == '\n' || *pointer == '\r') && pointer != clist.end())
    pointer++;
  return std::string(pointer, clist.end());
}

/* These two functions do the basic evaluation of ifcheck operators.
 *  It is important to note that the string operations are not what
 *  you probably expect.  Equality is exact and division is substring.
 *  remember that lhs has been stripped of leading space, but can
 *  still have trailing spaces so be careful when editing since:
 *  "guard" and "guard " are not equal.
 */
bool mprog_seval (const std::string & lhs, const std::string & opr, const std::string & rhs)
{

  if (!str_cmp (opr, "=="))
    return (bool) (!str_cmp (lhs, rhs));
  if (!str_cmp (opr, "!="))
    return (bool) (str_cmp (lhs, rhs));
  if (!str_cmp (opr, "/"))
    return (bool) (!str_infix (rhs, lhs));
  if (!str_cmp (opr, "!/"))
    return (bool) (str_infix (rhs, lhs));

  bug_printf ("Improper MOBprog operator");
  return 0;

}

bool mprog_veval (int lhs, const std::string & opr, int rhs)
{

  if (!str_cmp (opr, "=="))
    return (lhs == rhs);
  if (!str_cmp (opr, "!="))
    return (lhs != rhs);
  if (!str_cmp (opr, ">"))
    return (lhs > rhs);
  if (!str_cmp (opr, "<"))
    return (lhs < rhs);
  if (!str_cmp (opr, ">="))
    return (lhs <= rhs);
  if (!str_cmp (opr, ">="))
    return (lhs >= rhs);
  if (!str_cmp (opr, "&"))
    return (lhs & rhs);
  if (!str_cmp (opr, "|"))
    return (lhs | rhs);

  bug_printf ("Improper MOBprog operator\r\n");
  return 0;

}

/* This function performs the evaluation of the if checks.  It is
 * here that you can add any ifchecks which you so desire. Hopefully
 * it is clear from what follows how one would go about adding your
 * own. The syntax for an if check is: ifchck ( arg ) [opr val]
 * where the parenthesis are required and the opr and val fields are
 * optional but if one is there then both must be. The spaces are all
 * optional. The evaluation of the opr expressions is farmed out
 * to reduce the redundancy of the mammoth if statement list.
 * If there are errors, then return -1 otherwise return boolean 1,0
 */
bool mprog_do_ifchck (const std::string & ifchck, Character * mob,
  Character * actor, Object * obj, void *vo, Character * rndm)
{

  char buf[MAX_INPUT_LENGTH];
  char arg[MAX_INPUT_LENGTH];
  char opr[MAX_INPUT_LENGTH];
  char val[MAX_INPUT_LENGTH];
  Character *vict = (Character *) vo;
  Object *v_obj = (Object *) vo;
  char *bufpt = buf;
  char *argpt = arg;
  char *oprpt = opr;
  char *valpt = val;
  std::string::const_iterator point = ifchck.begin();
  int lhsvl;
  int rhsvl;

  if (ifchck.empty()) {
    bug_printf ("Mob: %d null ifchck", mob->pIndexData->vnum);
    return -1;
  }
  /* skip leading spaces */
  while (*point == ' ')
    point++;

  /* get whatever comes before the left paren.. ignore spaces */
  while (*point != '(')
    if (point == ifchck.end()) {
      bug_printf ("Mob: %d ifchck syntax error", mob->pIndexData->vnum);
      return -1;
    } else if (*point == ' ')
      point++;
    else
      *bufpt++ = *point++;

  *bufpt = '\0';
  point++;

  /* get whatever is in between the parens.. ignore spaces */
  while (*point != ')')
    if (point == ifchck.end()) {
      bug_printf ("Mob: %d ifchck syntax error", mob->pIndexData->vnum);
      return -1;
    } else if (*point == ' ')
      point++;
    else
      *argpt++ = *point++;

  *argpt = '\0';
  point++;

  /* check to see if there is an operator */
  while (*point == ' ')
    point++;
  if (point == ifchck.end()) {
    *opr = '\0';
    *val = '\0';
  } else {                      /* there should be an operator and value, so get them */

    while ((*point != ' ') && (!isalnum (*point)))
      if (point == ifchck.end()) {
        bug_printf ("Mob: %d ifchck operator without value", mob->pIndexData->vnum);
        return -1;
      } else
        *oprpt++ = *point++;

    *oprpt = '\0';

    /* finished with operator, skip spaces and then get the value */
    while (*point == ' ')
      point++;
    for (;;) {
      if ((*point != ' ') && (point == ifchck.end()))
        break;
      else
        *valpt++ = *point++;
    }

    *valpt = '\0';
  }
  bufpt = buf;
  argpt = arg;
  oprpt = opr;
  valpt = val;

  /* Ok... now buf contains the ifchck, arg contains the inside of the
   *  parentheses, opr contains an operator if one is present, and val
   *  has the value if an operator was present.
   *  So.. basically use if statements and run over all known ifchecks
   *  Once inside, use the argument and expand the lhs. Then if need be
   *  send the lhs,opr,rhs off to be evaluated.
   */

  if (!str_cmp (buf, "rand")) {
    return (number_percent () <= atoi (arg));
  }

  if (!str_cmp (buf, "ispc")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'i':
      return 0;
    case 'n':
      if (actor)
        return (!actor->is_npc ());
      else
        return -1;
    case 't':
      if (vict)
        return (!vict->is_npc ());
      else
        return -1;
    case 'r':
      if (rndm)
        return (!rndm->is_npc ());
      else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'ispc'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "isnpc")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'i':
      return 1;
    case 'n':
      if (actor)
        return actor->is_npc ();
      else
        return -1;
    case 't':
      if (vict)
        return vict->is_npc ();
      else
        return -1;
    case 'r':
      if (rndm)
        return rndm->is_npc ();
      else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'isnpc'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "isgood")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'i':
      return mob->is_good ();
    case 'n':
      if (actor)
        return actor->is_good ();
      else
        return -1;
    case 't':
      if (vict)
        return vict->is_good ();
      else
        return -1;
    case 'r':
      if (rndm)
        return rndm->is_good ();
      else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'isgood'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "isfight")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'i':
      return (mob->fighting) ? 1 : 0;
    case 'n':
      if (actor)
        return (actor->fighting) ? 1 : 0;
      else
        return -1;
    case 't':
      if (vict)
        return (vict->fighting) ? 1 : 0;
      else
        return -1;
    case 'r':
      if (rndm)
        return (rndm->fighting) ? 1 : 0;
      else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'isfight'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "isimmort")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'i':
      return (mob->get_trust () > LEVEL_IMMORTAL);
    case 'n':
      if (actor)
        return (actor->get_trust () > LEVEL_IMMORTAL);
      else
        return -1;
    case 't':
      if (vict)
        return (vict->get_trust () > LEVEL_IMMORTAL);
      else
        return -1;
    case 'r':
      if (rndm)
        return (rndm->get_trust () > LEVEL_IMMORTAL);
      else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'isimmort'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "ischarmed")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'i':
      return mob->is_affected (AFF_CHARM);
    case 'n':
      if (actor)
        return actor->is_affected (AFF_CHARM);
      else
        return -1;
    case 't':
      if (vict)
        return vict->is_affected (AFF_CHARM);
      else
        return -1;
    case 'r':
      if (rndm)
        return rndm->is_affected (AFF_CHARM);
      else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'ischarmed'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "isfollow")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'i':
      return (mob->master != NULL && mob->master->in_room == mob->in_room);
    case 'n':
      if (actor)
        return (actor->master != NULL
          && actor->master->in_room == actor->in_room);
      else
        return -1;
    case 't':
      if (vict)
        return (vict->master != NULL
          && vict->master->in_room == vict->in_room);
      else
        return -1;
    case 'r':
      if (rndm)
        return (rndm->master != NULL
          && rndm->master->in_room == rndm->in_room);
      else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'isfollow'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "isaffected")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'i':
      return (mob->affected_by & atoi (arg));
    case 'n':
      if (actor)
        return (actor->affected_by & atoi (arg));
      else
        return -1;
    case 't':
      if (vict)
        return (vict->affected_by & atoi (arg));
      else
        return -1;
    case 'r':
      if (rndm)
        return (rndm->affected_by & atoi (arg));
      else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'isaffected'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "hitprcnt")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'i':
      lhsvl = mob->hit / mob->max_hit;
      rhsvl = atoi (val);
      return mprog_veval (lhsvl, opr, rhsvl);
    case 'n':
      if (actor) {
        lhsvl = actor->hit / actor->max_hit;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    case 't':
      if (vict) {
        lhsvl = vict->hit / vict->max_hit;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    case 'r':
      if (rndm) {
        lhsvl = rndm->hit / rndm->max_hit;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'hitprcnt'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "inroom")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'i':
      lhsvl = mob->in_room->vnum;
      rhsvl = atoi (val);
      return mprog_veval (lhsvl, opr, rhsvl);
    case 'n':
      if (actor) {
        lhsvl = actor->in_room->vnum;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    case 't':
      if (vict) {
        lhsvl = vict->in_room->vnum;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    case 'r':
      if (rndm) {
        lhsvl = rndm->in_room->vnum;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'inroom'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "sex")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'i':
      lhsvl = mob->sex;
      rhsvl = atoi (val);
      return mprog_veval (lhsvl, opr, rhsvl);
    case 'n':
      if (actor) {
        lhsvl = actor->sex;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    case 't':
      if (vict) {
        lhsvl = vict->sex;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    case 'r':
      if (rndm) {
        lhsvl = rndm->sex;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'sex'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "position")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'i':
      lhsvl = mob->position;
      rhsvl = atoi (val);
      return mprog_veval (lhsvl, opr, rhsvl);
    case 'n':
      if (actor) {
        lhsvl = actor->position;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    case 't':
      if (vict) {
        lhsvl = vict->position;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    case 'r':
      if (rndm) {
        lhsvl = rndm->position;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'position'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "level")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'i':
      lhsvl = mob->get_trust ();
      rhsvl = atoi (val);
      return mprog_veval (lhsvl, opr, rhsvl);
    case 'n':
      if (actor) {
        lhsvl = actor->get_trust ();
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    case 't':
      if (vict) {
        lhsvl = vict->get_trust ();
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    case 'r':
      if (rndm) {
        lhsvl = rndm->get_trust ();
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'level'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "class")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'i':
      lhsvl = mob->klass;
      rhsvl = atoi (val);
      return mprog_veval (lhsvl, opr, rhsvl);
    case 'n':
      if (actor) {
        lhsvl = actor->klass;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    case 't':
      if (vict) {
        lhsvl = vict->klass;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    case 'r':
      if (rndm) {
        lhsvl = rndm->klass;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'class'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "goldamt")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'i':
      lhsvl = mob->gold;
      rhsvl = atoi (val);
      return mprog_veval (lhsvl, opr, rhsvl);
    case 'n':
      if (actor) {
        lhsvl = actor->gold;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    case 't':
      if (vict) {
        lhsvl = vict->gold;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    case 'r':
      if (rndm) {
        lhsvl = rndm->gold;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'goldamt'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "objtype")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'o':
      if (obj) {
        lhsvl = obj->item_type;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    case 'p':
      if (v_obj) {
        lhsvl = v_obj->item_type;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'objtype'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "objval0")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'o':
      if (obj) {
        lhsvl = obj->value[0];
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    case 'p':
      if (v_obj) {
        lhsvl = v_obj->value[0];
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'objval0'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "objval1")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'o':
      if (obj) {
        lhsvl = obj->value[1];
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    case 'p':
      if (v_obj) {
        lhsvl = v_obj->value[1];
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'objval1'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "objval2")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'o':
      if (obj) {
        lhsvl = obj->value[2];
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    case 'p':
      if (v_obj) {
        lhsvl = v_obj->value[2];
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'objval2'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "objval3")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'o':
      if (obj) {
        lhsvl = obj->value[3];
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    case 'p':
      if (v_obj) {
        lhsvl = v_obj->value[3];
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'objval3'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "number")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'i':
      lhsvl = mob->gold;
      rhsvl = atoi (val);
      return mprog_veval (lhsvl, opr, rhsvl);
    case 'n':
      if (actor) {
        if (actor->is_npc ()) {
          lhsvl = actor->pIndexData->vnum;
          rhsvl = atoi (val);
          return mprog_veval (lhsvl, opr, rhsvl);
          }
      } else
        return -1;
    case 't':
      if (vict) {
        if (actor->is_npc ()) {
          lhsvl = vict->pIndexData->vnum;
          rhsvl = atoi (val);
          return mprog_veval (lhsvl, opr, rhsvl);
          }
      } else
        return -1;
    case 'r':
      if (rndm) {
        if (actor->is_npc ()) {
          lhsvl = rndm->pIndexData->vnum;
          rhsvl = atoi (val);
          return mprog_veval (lhsvl, opr, rhsvl);
          }
      } else
        return -1;
    case 'o':
      if (obj) {
        lhsvl = obj->pIndexData->vnum;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    case 'p':
      if (v_obj) {
        lhsvl = v_obj->pIndexData->vnum;
        rhsvl = atoi (val);
        return mprog_veval (lhsvl, opr, rhsvl);
      } else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'number'", mob->pIndexData->vnum);
      return -1;
    }
  }

  if (!str_cmp (buf, "name")) {
    switch (arg[1]) {           /* arg should be "$*" so just get the letter */
    case 'i':
      return mprog_seval (mob->name, opr, val);
    case 'n':
      if (actor)
        return mprog_seval (actor->name, opr, val);
      else
        return -1;
    case 't':
      if (vict)
        return mprog_seval (vict->name, opr, val);
      else
        return -1;
    case 'r':
      if (rndm)
        return mprog_seval (rndm->name, opr, val);
      else
        return -1;
    case 'o':
      if (obj)
        return mprog_seval (obj->name, opr, val);
      else
        return -1;
    case 'p':
      if (v_obj)
        return mprog_seval (v_obj->name, opr, val);
      else
        return -1;
    default:
      bug_printf ("Mob: %d bad argument to 'name'", mob->pIndexData->vnum);
      return -1;
    }
  }

  /* Ok... all the ifchcks are done, so if we didnt find ours then something
   * odd happened.  So report the bug and abort the MOBprogram (return error)
   */
  bug_printf ("Mob: %d unknown ifchck", mob->pIndexData->vnum);
  return -1;

}

/* Quite a long and arduous function, this guy handles the control
 * flow part of MOBprograms.  Basicially once the driver sees an
 * 'if' attention shifts to here.  While many syntax errors are
 * caught, some will still get through due to the handling of break
 * and errors in the same fashion.  The desire to break out of the
 * recursion without catastrophe in the event of a mis-parse was
 * believed to be high. Thus, if an error is found, it is bugged and
 * the parser acts as though a break were issued and just bails out
 * at that point. I havent tested all the possibilites, so I'm speaking
 * in theory, but it is 'guaranteed' to work on syntactically correct
 * MOBprograms, so if the mud crashes here, check the mob carefully!
 */
std::string mprog_process_if (const std::string & ifchck, std::string & com_list,
  Character * mob, Character * actor, Object * obj, void *vo, Character * rndm)
{
  std::string buf;
  std::string morebuf;
  std::string cmnd;
  bool loopdone = false;
  bool flag = false;
  int legal;

  /* check for trueness of the ifcheck */
  if ((legal = mprog_do_ifchck (ifchck, mob, actor, obj, vo, rndm))) {
    if (legal == 1)
      flag = true;
    else
      return "";
  }

  while (loopdone == false) {   /*scan over any existing or statements */
    com_list = mprog_next_command (com_list, cmnd);
    cmnd.erase(0, cmnd.find_first_not_of(" "));
    if (cmnd.empty()) {
      bug_printf ("Mob: %d no commands after IF/OR", mob->pIndexData->vnum);
      return "";
    }
    morebuf = one_argument (cmnd, buf);
    if (!str_cmp (buf, "or")) {
      if ((legal = mprog_do_ifchck (morebuf, mob, actor, obj, vo, rndm))) {
        if (legal == 1)
          flag = true;
        else
          return "";
      }
    } else
      loopdone = true;
  }

  if (flag)
    for (;;) {                  /*ifcheck was true, do commands but ignore else to endif */
      if (!str_cmp (buf, "if")) {
        com_list =
          mprog_process_if (morebuf, com_list, mob, actor, obj, vo, rndm);
        cmnd.erase(0, cmnd.find_first_not_of(" "));
        if (com_list.empty())
          return "";
        com_list = mprog_next_command (com_list, cmnd);
        morebuf = one_argument (cmnd, buf);
        continue;
      }
      if (!str_cmp (buf, "break"))
        return "";
      if (!str_cmp (buf, "endif"))
        return com_list;
      if (!str_cmp (buf, "else")) {
        while (str_cmp (buf, "endif")) {
          com_list = mprog_next_command (com_list, cmnd);
          cmnd.erase(0, cmnd.find_first_not_of(" "));
          if (cmnd.empty()) {
            bug_printf ("Mob: %d missing endif after else", mob->pIndexData->vnum);
            return "";
          }
          morebuf = one_argument (cmnd, buf);
        }
        return com_list;
      }
      mprog_process_cmnd (cmnd, mob, actor, obj, vo, rndm);
      com_list = mprog_next_command (com_list, cmnd);
      cmnd.erase(0, cmnd.find_first_not_of(" "));
      if (cmnd.empty()) {
        bug_printf ("Mob: %d missing else or endif", mob->pIndexData->vnum);
        return "";
      }
      morebuf = one_argument (cmnd, buf);
  } else {                      /*false ifcheck, find else and do existing commands or quit at endif */

    while ((str_cmp (buf, "else")) && (str_cmp (buf, "endif"))) {
      com_list = mprog_next_command (com_list, cmnd);
      cmnd.erase(0, cmnd.find_first_not_of(" "));
      if (cmnd.empty()) {
        bug_printf ("Mob: %d missing an else or endif", mob->pIndexData->vnum);
        return "";
      }
      morebuf = one_argument (cmnd, buf);
    }

    /* found either an else or an endif.. act accordingly */
    if (!str_cmp (buf, "endif"))
      return com_list;
    com_list = mprog_next_command (com_list, cmnd);
    cmnd.erase(0, cmnd.find_first_not_of(" "));
    if (cmnd.empty()) {
      bug_printf ("Mob: %d missing endif", mob->pIndexData->vnum);
      return "";
    }
    morebuf = one_argument (cmnd, buf);

    for (;;) {                  /*process the post-else commands until an endif is found. */
      if (!str_cmp (buf, "if")) {
        com_list = mprog_process_if (morebuf, com_list, mob, actor,
          obj, vo, rndm);
        cmnd.erase(0, cmnd.find_first_not_of(" "));
        if (com_list.empty())
          return "";
        com_list = mprog_next_command (com_list, cmnd);
        morebuf = one_argument (cmnd, buf);
        continue;
      }
      if (!str_cmp (buf, "else")) {
        bug_printf ("Mob: %d found else in an else section", mob->pIndexData->vnum);
        return "";
      }
      if (!str_cmp (buf, "break"))
        return "";
      if (!str_cmp (buf, "endif"))
        return com_list;
      mprog_process_cmnd (cmnd, mob, actor, obj, vo, rndm);
      com_list = mprog_next_command (com_list, cmnd);
      cmnd.erase(0, cmnd.find_first_not_of(" "));
      if (cmnd.empty()) {
        bug_printf ("Mob:%d missing endif in else section", mob->pIndexData->vnum);
        return "";
      }
      morebuf = one_argument (cmnd, buf);
    }
  }
}

/* The main focus of the MOBprograms.  This routine is called
 *  whenever a trigger is successful.  It is responsible for parsing
 *  the command list and figuring out what to do. However, like all
 *  complex procedures, everything is farmed out to the other guys.
 */
void mprog_driver (const std::string & com_list, Character * mob,
  Character * actor, Object * obj, void *vo)
{

  std::string tmpcmndlst;
  std::string buf;
  std::string morebuf;
  std::string command_list;
  std::string cmnd;
  Character *rndm = NULL;
  int count = 0;

  if (mob->is_affected (AFF_CHARM))
      return;

  /* get a random visable mortal player who is in the room with the mob */
  CharIter vch;
  for (vch = mob->in_room->people.begin(); vch != mob->in_room->people.end(); vch++)
    if (!(*vch)->is_npc ()
      && (*vch)->level < LEVEL_IMMORTAL && mob->can_see(*vch)) {
      if (number_range (0, count) == 0)
        rndm = *vch;
      count++;
    }

  tmpcmndlst = com_list;
  command_list = tmpcmndlst;
  command_list = mprog_next_command (command_list, cmnd);
  while (!cmnd.empty()) {
    morebuf = one_argument (cmnd, buf);
    if (!str_cmp (buf, "if"))
      command_list = mprog_process_if (morebuf, command_list, mob,
        actor, obj, vo, rndm);
    else
      mprog_process_cmnd (cmnd, mob, actor, obj, vo, rndm);
    command_list = mprog_next_command (command_list, cmnd);
  }

  return;

}

/* The next two routines are the basic trigger types. Either trigger
 *  on a certain percent, or trigger on a keyword or word phrase.
 *  To see how this works, look at the various trigger routines..
 */
void mprog_wordlist_check (const std::string & arg, Character * mob,
  Character * actor, Object * obj, void *vo, int type)
{
  std::string list;
  std::string dupl;
  std::string word;
  MobProgram *mprg;

  std::string::size_type start = 0;
  std::string::size_type end = 0;

  unsigned int i;

  for (mprg = mob->pIndexData->mobprogs; mprg != NULL; mprg = mprg->next)
    if (mprg->type & type) {
      list = mprg->arglist;
      for (i = 0; i < list.size(); i++)
        list[i] = tolower (list[i]);
      dupl = arg;
      for (i = 0; i < dupl.size(); i++)
        dupl[i] = tolower (dupl[i]);

      if (list.substr(0,2) == "p ") {
        list = list.substr(2);
        while ((start = dupl.find(list)) != std::string::npos)
          if ((start == 0 || dupl[start - 1] == ' ')
            && (dupl[end = start + list.size()] == ' '
              || dupl[end] == '\n' || dupl[end] == '\r' || dupl[end] == '\0')) {
            mprog_driver (mprg->comlist, mob, actor, obj, vo);
            break;
          } else
            dupl = dupl.substr(start + 1);
      } else {
        list = one_argument (list, word);
        for (; !word.empty(); list = one_argument (list, word))
          while ((start = dupl.find(word)) != std::string::npos)
            if ((start == 0 || dupl[start - 1] == ' ')
              && (dupl[end = start + word.size()] == ' '
              || dupl[end] == '\n' || dupl[end] == '\r' || dupl[end] == '\0')) {
              mprog_driver (mprg->comlist, mob, actor, obj, vo);
              break;
            } else
              dupl = dupl.substr(start + 1);
      }
    }

  return;
}

/*
 * Reset one area.
 */
void reset_area (Area * pArea)
{
  Reset *pReset;
  Character *mob;
  bool last;
  int level;

  mob = NULL;
  last = true;
  level = 0;
  std::list<Reset*>::iterator rst;
  for (rst = pArea->reset_list.begin(); rst != pArea->reset_list.end(); rst++) {
    pReset = *rst;
    Room *pRoomIndex;
    MobPrototype *pMobIndex;
    ObjectPrototype *pObjIndex;
    ObjectPrototype *pObjToIndex;
    Exit *pexit;
    Object *obj;
    Object *obj_to;

    switch (pReset->command) {
    default:
      bug_printf ("Reset_area: bad command %c.", pReset->command);
      break;

    case 'M':
      if ((pMobIndex = get_mob_index (pReset->arg1)) == NULL) {
        bug_printf ("Reset_area: 'M': bad vnum %d.", pReset->arg1);
        continue;
      }

      if ((pRoomIndex = get_room_index (pReset->arg3)) == NULL) {
        bug_printf ("Reset_area: 'R': bad vnum %d.", pReset->arg3);
        continue;
      }

      level = URANGE (0, pMobIndex->level - 2, LEVEL_HERO);
      if (pMobIndex->count >= pReset->arg2) {
        last = false;
        break;
      }

      mob = pMobIndex->create_mobile ();

      /*
       * Check for pet shop.
       */
      {
        Room *pRoomIndexPrev;
        pRoomIndexPrev = get_room_index (pRoomIndex->vnum - 1);
        if (pRoomIndexPrev != NULL
          && IS_SET (pRoomIndexPrev->room_flags, ROOM_PET_SHOP))
          SET_BIT (mob->actflags, ACT_PET);
      }

      if (pRoomIndex->is_dark())
        SET_BIT (mob->affected_by, AFF_INFRARED);

      mob->char_to_room(pRoomIndex);
      level = URANGE (0, mob->level - 2, LEVEL_HERO);
      last = true;
      break;

    case 'O':
      if ((pObjIndex = get_obj_index (pReset->arg1)) == NULL) {
        bug_printf ("Reset_area: 'O': bad vnum %d.", pReset->arg1);
        continue;
      }

      if ((pRoomIndex = get_room_index (pReset->arg3)) == NULL) {
        bug_printf ("Reset_area: 'R': bad vnum %d.", pReset->arg3);
        continue;
      }

      if (pArea->nplayer > 0
        || pObjIndex->count_obj_list (pRoomIndex->contents) > 0) {
        last = false;
        break;
      }

      obj = pObjIndex->create_object(number_fuzzy (level));
      obj->cost = 0;
      obj->obj_to_room (pRoomIndex);
      last = true;
      break;

    case 'P':
      if ((pObjIndex = get_obj_index (pReset->arg1)) == NULL) {
        bug_printf ("Reset_area: 'P': bad vnum %d.", pReset->arg1);
        continue;
      }

      if ((pObjToIndex = get_obj_index (pReset->arg3)) == NULL) {
        bug_printf ("Reset_area: 'P': bad vnum %d.", pReset->arg3);
        continue;
      }

      if (pArea->nplayer > 0
        || (obj_to = pObjToIndex->get_obj_type()) == NULL
        || pObjIndex->count_obj_list (obj_to->contains) > 0) {
        last = false;
        break;
      }

      obj = pObjIndex->create_object (number_fuzzy (obj_to->level));
      obj->obj_to_obj (obj_to);
      last = true;
      break;

    case 'G':
    case 'E':
      if ((pObjIndex = get_obj_index (pReset->arg1)) == NULL) {
        bug_printf ("Reset_area: 'E' or 'G': bad vnum %d.", pReset->arg1);
        continue;
      }

      if (!last)
        break;

      if (mob == NULL) {
        bug_printf ("Reset_area: 'E' or 'G': null mob for vnum %d.", pReset->arg1);
        last = false;
        break;
      }

      if (mob->pIndexData->pShop != NULL) {
        int olevel;

        switch (pObjIndex->item_type) {
        default:
          olevel = 0;
          break;
        case ITEM_PILL:
          olevel = number_range (0, 10);
          break;
        case ITEM_POTION:
          olevel = number_range (0, 10);
          break;
        case ITEM_SCROLL:
          olevel = number_range (5, 15);
          break;
        case ITEM_WAND:
          olevel = number_range (10, 20);
          break;
        case ITEM_STAFF:
          olevel = number_range (15, 25);
          break;
        case ITEM_ARMOR:
          olevel = number_range (5, 15);
          break;
        case ITEM_WEAPON:
          olevel = number_range (5, 15);
          break;
        }

        obj = pObjIndex->create_object (olevel);
        SET_BIT (obj->extra_flags, ITEM_INVENTORY);
      } else {
        obj = pObjIndex->create_object (number_fuzzy (level));
      }
      obj->obj_to_char (mob);
      if (pReset->command == 'E')
        mob->equip_char (obj, pReset->arg3);
      last = true;
      break;

    case 'D':
      if ((pRoomIndex = get_room_index (pReset->arg1)) == NULL) {
        bug_printf ("Reset_area: 'D': bad vnum %d.", pReset->arg1);
        continue;
      }

      if ((pexit = pRoomIndex->exit[pReset->arg2]) == NULL)
        break;

      switch (pReset->arg3) {
      case 0:
        REMOVE_BIT (pexit->exit_info, EX_CLOSED);
        REMOVE_BIT (pexit->exit_info, EX_LOCKED);
        break;

      case 1:
        SET_BIT (pexit->exit_info, EX_CLOSED);
        REMOVE_BIT (pexit->exit_info, EX_LOCKED);
        break;

      case 2:
        SET_BIT (pexit->exit_info, EX_CLOSED);
        SET_BIT (pexit->exit_info, EX_LOCKED);
        break;
      }

      last = true;
      break;

    case 'R':
      if ((pRoomIndex = get_room_index (pReset->arg1)) == NULL) {
        bug_printf ("Reset_area: 'R': bad vnum %d.", pReset->arg1);
        continue;
      }

      {
        int d0;
        int d1;

        for (d0 = 0; d0 < pReset->arg2 - 1; d0++) {
          d1 = number_range (d0, pReset->arg2 - 1);
          pexit = pRoomIndex->exit[d0];
          pRoomIndex->exit[d0] = pRoomIndex->exit[d1];
          pRoomIndex->exit[d1] = pexit;
        }
      }
      break;
    }
  }

  return;
}

/*
 * Repopulate areas periodically.
 */
void area_update (void)
{
  Area *pArea;

  std::list<Area*>::iterator a;
  for (a = area_list.begin(); a != area_list.end(); a++) {
    pArea = *a;

    if (++pArea->age < 3)
      continue;

    /*
     * Check for PC's.
     */
    if (pArea->nplayer > 0 && pArea->age == 15 - 1) {
      CharIter c;
      for (c = char_list.begin(); c != char_list.end(); c++) {
        if (!(*c)->is_npc ()
          && (*c)->is_awake ()
          && (*c)->in_room != NULL && (*c)->in_room->area == pArea) {
          (*c)->send_to_char ("You hear the patter of little feet.\r\n");
        }
      }
    }

    /*
     * Check age and reset.
     * Note: Mud School resets every 3 minutes (not 15).
     */
    if (pArea->nplayer == 0 || pArea->age >= 15) {
      Room *pRoomIndex;

      reset_area (pArea);
      pArea->age = number_range (0, 3);
      pRoomIndex = get_room_index (ROOM_VNUM_SCHOOL);
      if (pRoomIndex != NULL && pArea == pRoomIndex->area)
        pArea->age = 15 - 3;
    }
  }

  return;
}

/*
 * Mob autonomous action.
 * This function takes 25% to 35% of ALL Merc cpu time.
 * -- Furey
 */
void mobile_update (void)
{
  Character *ch;
  Exit *pexit;
  int door;
try {
  /* Examine all mobs. */
  CharIter c;
  for (c = char_list.begin(); c != char_list.end(); c = deepchnext) {
    ch = *c;
    deepchnext = ++c;

    if (!ch->is_npc () || ch->in_room == NULL || ch->is_affected (AFF_CHARM))
      continue;

    /* Examine call for special procedure */
    if (ch->spec_fun != 0) {
      if ((*ch->spec_fun) (ch))
        continue;
    }

    /* That's all for sleeping / busy monster */
    if (ch->position < POS_STANDING)
      continue;

    /* MOBprogram random trigger */
    if (ch->in_room->area->nplayer > 0) {
      mprog_random_trigger (ch);
      /* If ch dies or changes
         position due to it's random
         trigger continue - Kahn */
      if (ch->position < POS_STANDING)
        continue;
    }

    /* Scavenge */
    if (IS_SET (ch->actflags, ACT_SCAVENGER)
      && !ch->in_room->contents.empty() && number_percent() <= 25) {
      Object *obj_best;
      int max;

      max = 1;
      obj_best = 0;
      ObjIter obj;
      for (obj = ch->in_room->contents.begin(); obj != ch->in_room->contents.end(); obj++) {
        if ((*obj)->can_wear(ITEM_TAKE) && (*obj)->cost > max) {
          obj_best = *obj;
          max = (*obj)->cost;
        }
      }

      if (obj_best) {
        obj_best->obj_from_room ();
        obj_best->obj_to_char (ch);
        ch->act ("$n gets $p.", obj_best, NULL, TO_ROOM);
      }
    }

    /* Wander */
    if (!IS_SET (ch->actflags, ACT_SENTINEL)
      && (door = number_range (0, 31)) <= 5
      && (pexit = ch->in_room->exit[door]) != NULL
      && pexit->to_room != NULL && !IS_SET (pexit->exit_info, EX_CLOSED)
      && !IS_SET (pexit->to_room->room_flags, ROOM_NO_MOB)
      && (!IS_SET (ch->actflags, ACT_STAY_AREA)
        || pexit->to_room->area == ch->in_room->area)) {
      ch->move_char (door);
      /* If ch changes position due
         to it's or someother mob's
         movement via MOBProgs,
         continue - Kahn */
      if (ch->position < POS_STANDING)
        continue;
    }

    /* Flee */
    if (ch->hit < (ch->max_hit / 2)
      && (door = number_range (0, 7)) <= 5
      && (pexit = ch->in_room->exit[door]) != NULL
      && pexit->to_room != NULL && !IS_SET (pexit->exit_info, EX_CLOSED)
      && !IS_SET (pexit->to_room->room_flags, ROOM_NO_MOB)) {
      bool found;

      found = false;
      CharIter rch;
      for (rch = pexit->to_room->people.begin(); rch != pexit->to_room->people.end(); rch++) {
        if (!(*rch)->is_npc ()) {
          found = true;
          break;
        }
      }
      if (!found)
        ch->move_char (door);
    }

  }

} catch (...) {
  fatal_printf("mobile_update() exception");
}
  return;
}

/*
 * Update the weather.
 */
void weather_update (void)
{
  std::string buf;
  int diff;

  switch (++time_info.hour) {
  case 5:
    weather_info.sunlight = SUN_LIGHT;
    buf.append("The day has begun.\r\n");
    break;

  case 6:
    weather_info.sunlight = SUN_RISE;
    buf.append("The sun rises in the east.\r\n");
    break;

  case 19:
    weather_info.sunlight = SUN_SET;
    buf.append("The sun slowly disappears in the west.\r\n");
    break;

  case 20:
    weather_info.sunlight = SUN_DARK;
    buf.append("The night has begun.\r\n");
    break;

  case 24:
    time_info.hour = 0;
    time_info.day++;
    break;
  }

  if (time_info.day >= 35) {
    time_info.day = 0;
    time_info.month++;
  }

  if (time_info.month >= 17) {
    time_info.month = 0;
    time_info.year++;
  }

  /*
   * Weather change.
   */
  if (time_info.month >= 9 && time_info.month <= 16)
    diff = weather_info.mmhg > 985 ? -2 : 2;
  else
    diff = weather_info.mmhg > 1015 ? -2 : 2;

  weather_info.change += diff * dice (1, 4) + dice (2, 6) - dice (2, 6);
  weather_info.change = std::max (weather_info.change, -12);
  weather_info.change = std::min (weather_info.change, 12);

  weather_info.mmhg += weather_info.change;
  weather_info.mmhg = std::max (weather_info.mmhg, 960);
  weather_info.mmhg = std::min (weather_info.mmhg, 1040);

  switch (weather_info.sky) {
  default:
    bug_printf ("Weather_update: bad sky %d.", weather_info.sky);
    weather_info.sky = SKY_CLOUDLESS;
    break;

  case SKY_CLOUDLESS:
    if (weather_info.mmhg < 990
      || (weather_info.mmhg < 1010 && number_percent() <= 25)) {
      buf.append("The sky is getting cloudy.\r\n");
      weather_info.sky = SKY_CLOUDY;
    }
    break;

  case SKY_CLOUDY:
    if (weather_info.mmhg < 970
      || (weather_info.mmhg < 990 && number_percent() <= 25)) {
      buf.append("It starts to rain.\r\n");
      weather_info.sky = SKY_RAINING;
    }

    if (weather_info.mmhg > 1030 && number_percent() <= 25) {
      buf.append("The clouds disappear.\r\n");
      weather_info.sky = SKY_CLOUDLESS;
    }
    break;

  case SKY_RAINING:
    if (weather_info.mmhg < 970 && number_percent() <= 25) {
      buf.append("Lightning flashes in the sky.\r\n");
      weather_info.sky = SKY_LIGHTNING;
    }

    if (weather_info.mmhg > 1030
      || (weather_info.mmhg > 1010 && number_percent() <= 25)) {
      buf.append("The rain stopped.\r\n");
      weather_info.sky = SKY_CLOUDY;
    }
    break;

  case SKY_LIGHTNING:
    if (weather_info.mmhg > 1010
      || (weather_info.mmhg > 990 && number_percent() <= 25)) {
      buf.append("The lightning has stopped.\r\n");
      weather_info.sky = SKY_RAINING;
      break;
    }
    break;
  }

  if (!buf.empty()) {
    for (DescIter d = descriptor_list.begin();
      d != descriptor_list.end(); d++) {
      if ((*d)->connected == CON_PLAYING && (*d)->character->is_outside()
        && (*d)->character->is_awake ())
        (*d)->character->send_to_char (buf);
    }
  }

  return;
}

/*
 * Update all chars, including mobs.
 * This function is performance sensitive.
 */
void char_update (void)
{
  Character *ch;
  Character *ch_save;
  Character *ch_quit;
  time_t save_time;

try {
  save_time = current_time;
  ch_save = NULL;
  ch_quit = NULL;
  CharIter c;
  for (c = char_list.begin(); c != char_list.end(); c = deepchnext) {
    Affect *paf;
    ch = *c;
    deepchnext = ++c;

    /*
     * Find dude with oldest save time.
     */
    if (!ch->is_npc ()
      && (ch->desc == NULL || ch->desc->connected == CON_PLAYING)
      && ch->level >= 2 && ch->save_time < save_time) {
      ch_save = ch;
      save_time = ch->save_time;
    }

    if (ch->position >= POS_STUNNED) {
      if (ch->hit < ch->max_hit)
        ch->hit += ch->hit_gain();

      if (ch->mana < ch->max_mana)
        ch->mana += ch->mana_gain ();

      if (ch->move < ch->max_move)
        ch->move += ch->move_gain();
    }

    if (ch->position == POS_STUNNED)
      ch->update_pos();

    if (!ch->is_npc () && ch->level < LEVEL_IMMORTAL) {
      Object *obj;

      if ((obj = ch->get_eq_char (WEAR_LIGHT)) != NULL
        && obj->item_type == ITEM_LIGHT && obj->value[2] > 0) {
        if (--obj->value[2] == 0 && ch->in_room != NULL) {
          --ch->in_room->light;
          ch->act ("$p goes out.", obj, NULL, TO_ROOM);
          ch->act ("$p goes out.", obj, NULL, TO_CHAR);
          obj->extract_obj ();
        }
      }

      if (++ch->timer >= 12) {
        if (ch->was_in_room == NULL && ch->in_room != NULL) {
          ch->was_in_room = ch->in_room;
          if (ch->fighting != NULL)
            ch->stop_fighting (true);
          ch->act ("$n disappears into the void.", NULL, NULL, TO_ROOM);
          ch->send_to_char ("You disappear into the void.\r\n");
          ch->save_char_obj();
          ch->char_from_room();
          ch->char_to_room(get_room_index (ROOM_VNUM_LIMBO));
        }
      }

      if (ch->timer > 30)
        ch_quit = ch;

      ch->gain_condition (COND_DRUNK, -1);
      ch->gain_condition (COND_FULL, -1);
      ch->gain_condition (COND_THIRST, -1);
    }

    AffIter af, next;
    for (af = ch->affected.begin(); af != ch->affected.end(); af = next) {
      paf = *af;
      next = ++af;
      if (paf->duration > 0)
        paf->duration--;
      else if (paf->duration < 0);
      else {
        if (next == ch->affected.end()
          || (*next)->type != paf->type || (*next)->duration > 0) {
          if (paf->type > 0 && skill_table[paf->type].msg_off[0] != '\0') {
            ch->send_to_char (skill_table[paf->type].msg_off);
            ch->send_to_char ("\r\n");
          }
        }

        ch->affect_remove (paf);
      }
    }

    /*
     * Careful with the damages here,
     *   MUST NOT refer to ch after damage taken,
     *   as it may be lethal damage (on NPC).
     */
    if (ch->is_affected (AFF_POISON)) {
      ch->act ("$n shivers and suffers.", NULL, NULL, TO_ROOM);
      ch->send_to_char ("You shiver and suffer.\r\n");
      damage (ch, ch, 2, gsn_poison);
    } else if (ch->position == POS_INCAP) {
      damage (ch, ch, 1, TYPE_UNDEFINED);
    } else if (ch->position == POS_MORTAL) {
      damage (ch, ch, 2, TYPE_UNDEFINED);
    }
  }

  /*
   * Autosave and autoquit.
   * Check that these chars still exist.
   */
  if (ch_save != NULL || ch_quit != NULL) {
    CharIter cnext;
    for (c = char_list.begin(); c != char_list.end(); c = cnext) {
      ch = *c;
      cnext = ++c;
      if (ch == ch_save)
        ch->save_char_obj();
      if (ch == ch_quit)
        ch->do_quit ("");
    }
  }
} catch (...) {
  fatal_printf("char_update() exception");
}

  return;
}

/*
 * Update all objs.
 * This function is performance sensitive.
 */
void obj_update (void)
{
  Object *obj;
  ObjIter o;

try {
  for (o = object_list.begin(); o != object_list.end(); o = deepobnext) {
    char *message;
    obj = *o;
    deepobnext = ++o;

    if (obj->timer <= 0 || --obj->timer > 0)
      continue;

    switch (obj->item_type) {
    default:
      message = "$p vanishes.";
      break;
    case ITEM_FOUNTAIN:
      message = "$p dries up.";
      break;
    case ITEM_CORPSE_NPC:
      message = "$p decays into dust.";
      break;
    case ITEM_CORPSE_PC:
      message = "$p decays into dust.";
      break;
    case ITEM_FOOD:
      message = "$p decomposes.";
      break;
    }

    if (obj->carried_by != NULL) {
      obj->carried_by->act (message, obj, NULL, TO_CHAR);
    } else if (obj->in_room != NULL && !obj->in_room->people.empty()) {
      Character *rch = obj->in_room->people.front();
      rch->act (message, obj, NULL, TO_ROOM);
      rch->act (message, obj, NULL, TO_CHAR);
    }

    obj->extract_obj ();
  }
} catch (...) {
  fatal_printf("obj_update() exception");
}

  return;
}

/*
 * Aggress.
 *
 * for each mortal PC
 *     for each mob in room
 *         aggress on some random PC
 *
 * This function takes 25% to 35% of ALL Merc cpu time.
 * Unfortunately, checking on each PC move is too tricky,
 *   because we don't the mob to just attack the first PC
 *   who leads the party into the room.
 *
 * -- Furey
 */
void aggr_update (void)
{
  Character *wch;
  Character *ch;
  Character *vch;
  Character *victim;

try {
  CharIter c;
  for (c = char_list.begin(); c != char_list.end(); c = deepchnext) {
    wch = *c;
    deepchnext = ++c;

    /* MOBProgram ACT_PROG trigger */
    if (wch->is_npc () && wch->mpactnum > 0 && wch->in_room->area->nplayer > 0) {
      MobProgramActList *tmp_act, *tmp2_act;
      for (tmp_act = wch->mpact; tmp_act != NULL; tmp_act = tmp_act->next) {
        mprog_wordlist_check (tmp_act->buf, wch, tmp_act->ch,
          tmp_act->obj, tmp_act->vo, ACT_PROG);
      }
      for (tmp_act = wch->mpact; tmp_act != NULL; tmp_act = tmp2_act) {
        tmp2_act = tmp_act->next;
        delete tmp_act;
      }
      wch->mpactnum = 0;
      wch->mpact = NULL;
    }

    if (wch->is_npc ()
      || wch->level >= LEVEL_IMMORTAL || wch->in_room == NULL)
      continue;

    Room* rlist = wch->in_room;

    CharIter rch, rcnext;
    for (rch = rlist->people.begin(); rch != rlist->people.end(); rch = deeprmnext) {
      ch = *rch;
      deeprmnext = ++rch;
      int count;

      if (!ch->is_npc ()
        || !IS_SET (ch->actflags, ACT_AGGRESSIVE)
        || ch->fighting != NULL || ch->is_affected (AFF_CHARM)
        || !ch->is_awake ()
        || (IS_SET (ch->actflags, ACT_WIMPY) && wch->is_awake ())
        || !ch->can_see(wch))
        continue;

      /*
       * Ok we have a 'wch' player character and a 'ch' npc aggressor.
       * Now make the aggressor fight a RANDOM pc victim in the room,
       *   giving each 'vch' an equal chance of selection.
       */
      count = 0;
      victim = NULL;
      for (CharIter vc = rlist->people.begin(); vc != rlist->people.end(); vc++) {
        if (!(*vc)->is_npc () && (*vc)->level < LEVEL_IMMORTAL
          && (!IS_SET (ch->actflags, ACT_WIMPY) || !(*vc)->is_awake ())
          && ch->can_see(*vc)) {
          if (number_range (0, count) == 0)
            victim = *vc;
          count++;
        }
      }

      if (victim == NULL) {
        bug_printf ("Aggr_update: null victim.", count);
        continue;
      }

      multi_hit (ch, victim, TYPE_UNDEFINED);
    }
  }

} catch (...) {
  fatal_printf("aggr_update() exception");
}

  return;
}

/*
 * Control the fights going on.
 * Called periodically by update_handler.
 */
void violence_update (void)
{
  Character *ch;
  Character *victim;
  Character *rch;

try {

  CharIter c;
  for (c = char_list.begin(); c != char_list.end(); c = deepchnext) {
    ch = *c;
    deepchnext = ++c;

    victim = ch->fighting;
    if (victim == NULL || ch->in_room == NULL)
      continue;

    if (ch->is_awake () && ch->in_room == victim->in_room)
      multi_hit (ch, victim, TYPE_UNDEFINED);
    else
      ch->stop_fighting (false);

    victim = ch->fighting;
    if (victim == NULL)
      continue;

    mprog_hitprcnt_trigger (ch, victim);
    mprog_fight_trigger (ch, victim);

    /*
     * Fun for the whole family!
     */

    if (ch == NULL || ch->in_room == NULL)
      continue;
    victim = ch->fighting;
    if (victim == NULL)
      continue;
    Room * rlist = ch->in_room;

    CharIter rc, rnext;
    for (rc = rlist->people.begin(); rc != rlist->people.end(); rc = deeprmnext) {
      rch = *rc;
      deeprmnext = ++rc;

      if (rch->fighting == NULL && rch->is_awake ()) {
        /*
         * PC's auto-assist others in their group.
         */
        if (!ch->is_npc () || ch->is_affected (AFF_CHARM)) {
          if ((!rch->is_npc () || rch->is_affected (AFF_CHARM))
            && is_same_group (ch, rch))
            multi_hit (rch, victim, TYPE_UNDEFINED);
          continue;
        }

        /*
         * NPC's assist NPC's of same type or 12.5% chance regardless.
         */
        if (rch->is_npc () && !rch->is_affected (AFF_CHARM)) {
          if (rch->pIndexData == ch->pIndexData || number_range (0, 7) == 0) {
            Character *target;
            int number;

            target = NULL;
            number = 0;
            CharIter vch;
            for (vch = rlist->people.begin(); vch != rlist->people.end(); vch++) {
              if (rch->can_see(*vch)
                && is_same_group (*vch, victim)
                && number_range (0, number) == 0) {
                target = *vch;
                number++;
              }
            }

            if (target != NULL) {
              if ((((target->level - rch->level <= 4)
                    && (target->level - rch->level >= -4))
                  && !(rch->is_good () && target->is_good ()))
                || (rch->is_evil () || target->is_evil ()))
                multi_hit (rch, target, TYPE_UNDEFINED);
            }
          }
        }
      }
    }
  }

} catch (...) {
  fatal_printf("violence_update() exception");
}

  return;
}

/*
 * Handle all kinds of updates.
 * Called once per pulse from game loop.
 * Random times to defeat tick-timing clients and players.
 */
void update_handler (void)
{
  static int pulse_area;
  static int pulse_mobile;
  static int pulse_violence;
  static int pulse_point;

try {
  if (--pulse_area <= 0) {
    pulse_area = number_range (PULSE_AREA / 2, 3 * PULSE_AREA / 2);
    area_update ();
  }

  if (--pulse_violence <= 0) {
    pulse_violence = PULSE_VIOLENCE;
    violence_update ();
  }

  if (--pulse_mobile <= 0) {
    pulse_mobile = PULSE_MOBILE;
    mobile_update ();
  }

  if (--pulse_point <= 0) {
    pulse_point = number_range (PULSE_TICK / 2, 3 * PULSE_TICK / 2);
    weather_update ();
    char_update ();
    obj_update ();
  }

  aggr_update ();
  tail_chain ();
} catch (...) {
  fatal_printf("update_handler() exception");
}
  return;
}

/*
 * Shopping commands.
 */
Character *find_keeper (Character * ch)
{
  char buf[MAX_STRING_LENGTH];
  Shop *pShop;

  pShop = NULL;
  CharIter keeper;
  for (keeper = ch->in_room->people.begin(); keeper != ch->in_room->people.end(); keeper++) {
    if ((*keeper)->is_npc () && (pShop = (*keeper)->pIndexData->pShop) != NULL)
      break;
  }

  if (pShop == NULL) {
    ch->send_to_char ("You can't do that here.\r\n");
    return NULL;
  }

  /*
   * Undesirables.
   */
  if (!ch->is_npc () && IS_SET (ch->actflags, PLR_KILLER)) {
    (*keeper)->do_say ("Killers are not welcome!");
    snprintf (buf, sizeof buf, "%s the KILLER is over here!\r\n", ch->name.c_str());
    (*keeper)->do_shout (buf);
    return NULL;
  }

  if (!ch->is_npc () && IS_SET (ch->actflags, PLR_THIEF)) {
    (*keeper)->do_say ("Thieves are not welcome!");
    snprintf (buf, sizeof buf, "%s the THIEF is over here!\r\n", ch->name.c_str());
    (*keeper)->do_shout (buf);
    return NULL;
  }

  /*
   * Shop hours.
   */
  if (time_info.hour < pShop->open_hour) {
    (*keeper)->do_say ("Sorry, come back later.");
    return NULL;
  }

  if (time_info.hour > pShop->close_hour) {
    (*keeper)->do_say ("Sorry, come back tomorrow.");
    return NULL;
  }

  /*
   * Invisible or hidden people.
   */
  if (!(*keeper)->can_see(ch)) {
    (*keeper)->do_say ("I don't trade with folks I can't see.");
    return NULL;
  }

  return *keeper;
}

int get_cost (Character * keeper, Object * obj, bool fBuy)
{
  Shop *pShop;
  int cost;

  if (obj == NULL || (pShop = keeper->pIndexData->pShop) == NULL)
    return 0;

  if (fBuy) {
    cost = obj->cost * pShop->profit_buy / 100;
  } else {
    int itype;

    cost = 0;
    for (itype = 0; itype < MAX_TRADE; itype++) {
      if (obj->item_type == pShop->buy_type[itype]) {
        cost = obj->cost * pShop->profit_sell / 100;
        break;
      }
    }

    ObjIter o;
    for (o = keeper->carrying.begin(); o != keeper->carrying.end(); o++) {
      if (obj->pIndexData == (*o)->pIndexData)
        cost /= 2;
    }
  }

  if (obj->item_type == ITEM_STAFF || obj->item_type == ITEM_WAND)
    cost = cost * obj->value[2] / obj->value[1];

  return cost;
}

/*
 * Generic channel function.
 */
void talk_channel (Character * ch, const std::string & argument, int channel,
  const char *verb)
{
  char buf[MAX_STRING_LENGTH];
  int position;

  if (argument.empty()) {
    snprintf (buf, sizeof buf, "%s what?\r\n", verb);
    buf[0] = toupper (buf[0]);
    return;
  }

  if (!ch->is_npc () && IS_SET (ch->actflags, PLR_SILENCE)) {
    snprintf (buf, sizeof buf, "You can't %s.\r\n", verb);
    ch->send_to_char (buf);
    return;
  }

  REMOVE_BIT (ch->deaf, channel);

  switch (channel) {
  default:
    snprintf (buf, sizeof buf, "You %s '%s'.\r\n", verb, argument.c_str());
    ch->send_to_char (buf);
    snprintf (buf, sizeof buf, "$n %ss '$t'.", verb);
    break;

  case CHANNEL_IMMTALK:
    snprintf (buf, sizeof buf, "$n: $t.");
    position = ch->position;
    ch->position = POS_STANDING;
    ch->act (buf, argument.c_str(), NULL, TO_CHAR);
    ch->position = position;
    break;
  }

  for (DescIter d = descriptor_list.begin();
    d != descriptor_list.end(); d++) {
    Character *och;
    Character *vch;

    och = (*d)->original ? (*d)->original : (*d)->character;
    vch = (*d)->character;

    if ((*d)->connected == CON_PLAYING
      && vch != ch && !IS_SET (och->deaf, channel)) {
      if (channel == CHANNEL_IMMTALK && !och->is_hero())
        continue;
      if (channel == CHANNEL_YELL && vch->in_room->area != ch->in_room->area)
        continue;

      position = vch->position;
      if (channel != CHANNEL_SHOUT && channel != CHANNEL_YELL)
        vch->position = POS_STANDING;
      ch->act (buf, argument.c_str(), vch, TO_VICT);
      vch->position = position;
    }
  }

  return;
}

Room *find_location (Character * ch, const std::string & arg)
{
  Character *victim;
  Object *obj;

  if (is_number (arg))
    return get_room_index (atoi (arg.c_str()));

  if ((victim = ch->get_char_world (arg)) != NULL)
    return victim->in_room;

  if ((obj = ch->get_obj_world (arg)) != NULL)
    return obj->in_room;

  return NULL;
}

bool is_safe (Character * ch, Character * victim)
{
  if (ch->is_npc () || victim->is_npc ())
    return false;

  if (ch->get_age() < 21) {
    ch->send_to_char ("You aren't old enough.\r\n");
    return true;
  }

  if (IS_SET (victim->actflags, PLR_KILLER))
    return false;

  if (ch->level >= victim->level) {
    ch->send_to_char ("You may not attack a lower level player.\r\n");
    return true;
  }

  return false;
}

/*
 * See if an attack justifies a KILLER flag.
 */
void check_killer (Character * ch, Character * victim)
{
  /*
   * Follow charm thread to responsible character.
   * Attacking someone's charmed char is hostile!
   */
  while (victim->is_affected (AFF_CHARM) && victim->master != NULL)
    victim = victim->master;

  /*
   * NPC's are fair game.
   * So are killers and thieves.
   */
  if (victim->is_npc ()
    || IS_SET (victim->actflags, PLR_KILLER)
    || IS_SET (victim->actflags, PLR_THIEF))
    return;

  /*
   * Charm-o-rama.
   */
  if (IS_SET (ch->affected_by, AFF_CHARM)) {
    if (ch->master == NULL) {
      bug_printf ("Check_killer: %s bad AFF_CHARM",
        ch->is_npc () ? ch->short_descr.c_str() : ch->name.c_str());
      ch->affect_strip (gsn_charm_person);
      REMOVE_BIT (ch->affected_by, AFF_CHARM);
      return;
    }

    ch->master->send_to_char ("*** You are now a KILLER!! ***\r\n");
    SET_BIT (ch->master->actflags, PLR_KILLER);
    ch->stop_follower();
    return;
  }

  /*
   * NPC's are cool of course (as long as not charmed).
   * Hitting yourself is cool too (bleeding).
   * So is being immortal (Alander's idea).
   * And current killers stay as they are.
   */
  if (ch->is_npc ()
    || ch == victim
    || ch->level >= LEVEL_IMMORTAL || IS_SET (ch->actflags, PLR_KILLER))
    return;

  ch->send_to_char ("*** You are now a KILLER!! ***\r\n");
  SET_BIT (ch->actflags, PLR_KILLER);
  ch->save_char_obj();
  return;
}

/*
 * Check for parry.
 */
bool check_parry (Character * ch, Character * victim)
{
  int chance;

  if (!victim->is_awake ())
    return false;

  if (victim->is_npc ()) {
    /* Tuan was here.  :) */
    chance = std::min (60, 2 * victim->level);
  } else {
    if (victim->get_eq_char (WEAR_WIELD) == NULL)
      return false;
    chance = victim->pcdata->learned[gsn_parry] / 2;
  }

  if (number_percent () >= chance + victim->level - ch->level)
    return false;

  ch->act ("You parry $n's attack.", NULL, victim, TO_VICT);
  ch->act ("$N parries your attack.", NULL, victim, TO_CHAR);
  return true;
}

/*
 * Check for dodge.
 */
bool check_dodge (Character * ch, Character * victim)
{
  int chance;

  if (!victim->is_awake ())
    return false;

  if (victim->is_npc ())
    /* Tuan was here.  :) */
    chance = std::min (60, 2 * victim->level);
  else
    chance = victim->pcdata->learned[gsn_dodge] / 2;

  if (number_percent () >= chance + victim->level - ch->level)
    return false;

  ch->act ("You dodge $n's attack.", NULL, victim, TO_VICT);
  ch->act ("$N dodges your attack.", NULL, victim, TO_CHAR);
  return true;
}

/*
 * Make a corpse out of a character.
 */
void make_corpse (Character * ch)
{
  char buf[MAX_STRING_LENGTH];
  Object *corpse;
  Object *obj;
  std::string name;

  if (ch->is_npc ()) {
    name = ch->short_descr;
    corpse = get_obj_index(OBJ_VNUM_CORPSE_NPC)->create_object(0);
    corpse->timer = number_range (2, 4);
    if (ch->gold > 0) {
      create_money(ch->gold)->obj_to_obj(corpse);
      ch->gold = 0;
    }
  } else {
    name = ch->name;
    corpse = get_obj_index (OBJ_VNUM_CORPSE_PC)->create_object(0);
    corpse->timer = number_range (25, 40);
  }

  snprintf (buf, sizeof buf, corpse->short_descr.c_str(), name.c_str());
  corpse->short_descr = buf;

  snprintf (buf, sizeof buf, corpse->description.c_str(), name.c_str());
  corpse->description = buf;

  ObjIter o, onext;
  for (o = ch->carrying.begin(); o != ch->carrying.end(); o = onext) {
    obj = *o;
    onext = ++o;
    obj->obj_from_char();
    if (IS_SET (obj->extra_flags, ITEM_INVENTORY))
      obj->extract_obj ();
    else
      obj->obj_to_obj(corpse);
  }

  corpse->obj_to_room (ch->in_room);
  return;
}

/*
 * Improved Death_cry contributed by Diavolo.
 */
void death_cry (Character * ch)
{
  Room *was_in_room;
  char *msg;
  int door;
  int vnum;

  vnum = 0;
  switch (number_range (0, 15)) {
  default:
    msg = "You hear $n's death cry.";
    break;
  case 0:
    msg = "$n hits the ground ... DEAD.";
    break;
  case 1:
    msg = "$n splatters blood on your armor.";
    break;
  case 2:
    msg = "You smell $n's sphincter releasing in death.";
    vnum = OBJ_VNUM_FINAL_TURD;
    break;
  case 3:
    msg = "$n's severed head plops on the ground.";
    vnum = OBJ_VNUM_SEVERED_HEAD;
    break;
  case 4:
    msg = "$n's heart is torn from $s chest.";
    vnum = OBJ_VNUM_TORN_HEART;
    break;
  case 5:
    msg = "$n's arm is sliced from $s dead body.";
    vnum = OBJ_VNUM_SLICED_ARM;
    break;
  case 6:
    msg = "$n's leg is sliced from $s dead body.";
    vnum = OBJ_VNUM_SLICED_LEG;
    break;
  }

  ch->act (msg, NULL, NULL, TO_ROOM);

  if (vnum != 0) {
    char buf[MAX_STRING_LENGTH];
    Object *obj;
    std::string name;

    name = ch->is_npc () ? ch->short_descr : ch->name;
    obj = get_obj_index(vnum)->create_object(0);
    obj->timer = number_range (4, 7);

    snprintf (buf, sizeof buf, obj->short_descr.c_str(), name.c_str());
    obj->short_descr = buf;

    snprintf (buf, sizeof buf, obj->description.c_str(), name.c_str());
    obj->description = buf;

    obj->obj_to_room (ch->in_room);
  }

  if (ch->is_npc ())
    msg = "You hear something's death cry.";
  else
    msg = "You hear someone's death cry.";

  was_in_room = ch->in_room;
  for (door = 0; door <= 5; door++) {
    Exit *pexit;

    if ((pexit = was_in_room->exit[door]) != NULL
      && pexit->to_room != NULL && pexit->to_room != was_in_room) {
      ch->in_room = pexit->to_room;
      ch->act (msg, NULL, NULL, TO_ROOM);
    }
  }
  ch->in_room = was_in_room;

  return;
}

void raw_kill (Character * victim)
{
  victim->stop_fighting(true);
  mprog_death_trigger (victim);
  make_corpse (victim);

  if (victim->is_npc ()) {
    victim->pIndexData->killed++;
    kill_table[URANGE (0, victim->level, MAX_LEVEL - 1)].killed++;
    victim->extract_char (true);
    victim = NULL;
    return;
  }

  victim->extract_char (false);
  while (victim->affected.begin() != victim->affected.end())
    victim->affect_remove (*victim->affected.begin());
  victim->affected_by = 0;
  victim->armor = 100;
  victim->position = POS_RESTING;
  victim->hit = std::max (1, victim->hit);
  victim->mana = std::max (1, victim->mana);
  victim->move = std::max (1, victim->move);
  victim->save_char_obj();
  return;
}

/*
 * Compute xp for a kill.
 * Also adjust alignment of killer.
 * Edit this function to change xp computations.
 */
int xp_compute (Character * gch, Character * victim)
{
  int align;
  int xp;
  int extra;
  int level;
  int number;

  xp = 300 - URANGE (-3, gch->level - victim->level, 6) * 50;
  align = gch->alignment - victim->alignment;

  if (align > 500) {
    gch->alignment = std::min (gch->alignment + (align - 500) / 4, 1000);
    xp = 5 * xp / 4;
  } else if (align < -500) {
    gch->alignment = std::max (gch->alignment + (align + 500) / 4, -1000);
  } else {
    gch->alignment -= gch->alignment / 4;
    xp = 3 * xp / 4;
  }

  /*
   * Adjust for popularity of target:
   *   -1/8 for each target over  'par' (down to -100%)
   *   +1/8 for each target under 'par' (  up to + 25%)
   */
  level = URANGE (0, victim->level, MAX_LEVEL - 1);
  number = std::max (1, kill_table[level].number);
  extra = victim->pIndexData->killed - kill_table[level].killed / number;
  xp -= xp * URANGE (-2, extra, 8) / 8;

  xp = number_range (xp * 3 / 4, xp * 5 / 4);
  xp = std::max (0, xp);

  return xp;
}

void group_gain (Character * ch, Character * victim)
{
  char buf[MAX_STRING_LENGTH];
  Character *lch;
  int xp;
  int members;

  /*
   * Monsters don't get kill xp's or alignment changes.
   * P-killing doesn't help either.
   * Dying of mortal wounds or poison doesn't give xp to anyone!
   */
  if (ch->is_npc () || !victim->is_npc () || victim == ch)
    return;

  members = 0;
  CharIter gch;
  for (gch = ch->in_room->people.begin(); gch != ch->in_room->people.end(); gch++) {
    if (is_same_group (*gch, ch))
      members++;
  }

  if (members == 0) {
    bug_printf ("Group_gain: members.", members);
    members = 1;
  }

  lch = (ch->leader != NULL) ? ch->leader : ch;

  for (gch = ch->in_room->people.begin(); gch != ch->in_room->people.end(); gch++) {
    Object *obj;

    if (!is_same_group (*gch, ch))
      continue;

    if ((*gch)->level - lch->level >= 6) {
      (*gch)->send_to_char ("You are too high for this group.\r\n");
      continue;
    }

    if ((*gch)->level - lch->level <= -6) {
      (*gch)->send_to_char ("You are too low for this group.\r\n");
      continue;
    }

    xp = xp_compute (*gch, victim) / members;
    snprintf (buf, sizeof buf, "You receive %d experience points.\r\n", xp);
    (*gch)->send_to_char (buf);
    (*gch)->gain_exp(xp);

    ObjIter o, onext;
    for (o = ch->carrying.begin(); o != ch->carrying.end(); o = onext) {
      obj = *o;
      onext = ++o;
      if (obj->wear_loc == WEAR_NONE)
        continue;

      if ((obj->is_obj_stat(ITEM_ANTI_EVIL) && ch->is_evil ())
        || (obj->is_obj_stat(ITEM_ANTI_GOOD) && ch->is_good ())
        || (obj->is_obj_stat(ITEM_ANTI_NEUTRAL) && ch->is_neutral ())) {
        ch->act ("You are zapped by $p.", obj, NULL, TO_CHAR);
        ch->act ("$n is zapped by $p.", obj, NULL, TO_ROOM);
        obj->obj_from_char();
        obj->obj_to_room(ch->in_room);
      }
    }
  }

  return;
}

void dam_message (Character * ch, Character * victim, int dam, int dt)
{
  static char *const attack_table[] = {
    "hit",
    "slice", "stab", "slash", "whip", "claw",
    "blast", "pound", "crush", "grep", "bite",
    "pierce", "suction"
  };

  char buf1[256], buf2[256], buf3[256];
  const char *vs;
  const char *vp;
  std::string attack;
  char punct;

  if (dam == 0) {
    vs = "miss";
    vp = "misses";
  } else if (dam <= 4) {
    vs = "scratch";
    vp = "scratches";
  } else if (dam <= 8) {
    vs = "graze";
    vp = "grazes";
  } else if (dam <= 12) {
    vs = "hit";
    vp = "hits";
  } else if (dam <= 16) {
    vs = "injure";
    vp = "injures";
  } else if (dam <= 20) {
    vs = "wound";
    vp = "wounds";
  } else if (dam <= 24) {
    vs = "maul";
    vp = "mauls";
  } else if (dam <= 28) {
    vs = "decimate";
    vp = "decimates";
  } else if (dam <= 32) {
    vs = "devastate";
    vp = "devastates";
  } else if (dam <= 36) {
    vs = "maim";
    vp = "maims";
  } else if (dam <= 40) {
    vs = "MUTILATE";
    vp = "MUTILATES";
  } else if (dam <= 44) {
    vs = "DISEMBOWEL";
    vp = "DISEMBOWELS";
  } else if (dam <= 48) {
    vs = "EVISCERATE";
    vp = "EVISCERATES";
  } else if (dam <= 52) {
    vs = "MASSACRE";
    vp = "MASSACRES";
  } else if (dam <= 100) {
    vs = "*** DEMOLISH ***";
    vp = "*** DEMOLISHES ***";
  } else {
    vs = "*** ANNIHILATE ***";
    vp = "*** ANNIHILATES ***";
  }

  punct = (dam <= 24) ? '.' : '!';

  if (dt == TYPE_HIT) {
    snprintf (buf1, sizeof buf1, "$n %s $N%c", vp, punct);
    snprintf (buf2, sizeof buf2, "You %s $N%c", vs, punct);
    snprintf (buf3, sizeof buf3, "$n %s you%c", vp, punct);
  } else {
    if (dt >= 0 && dt < MAX_SKILL)
      attack = skill_table[dt].noun_damage;
    else if (dt >= TYPE_HIT
      && dt < (int) (TYPE_HIT + sizeof (attack_table) / sizeof (attack_table[0])))
      attack = attack_table[dt - TYPE_HIT];
    else {
      bug_printf ("Dam_message: bad dt %d.", dt);
      dt = TYPE_HIT;
      attack = attack_table[0];
    }

    snprintf (buf1, sizeof buf1, "$n's %s %s $N%c", attack.c_str(), vp, punct);
    snprintf (buf2, sizeof buf2, "Your %s %s $N%c", attack.c_str(), vp, punct);
    snprintf (buf3, sizeof buf3, "$n's %s %s you%c", attack.c_str(), vp, punct);
  }

  ch->act (buf1, NULL, victim, TO_NOTVICT);
  ch->act (buf2, NULL, victim, TO_CHAR);
  ch->act (buf3, NULL, victim, TO_VICT);

  return;
}

/*
 * Disarm a creature.
 * Caller must check for successful attack.
 */
void disarm (Character * ch, Character * victim)
{
  Object *obj;

  if ((obj = victim->get_eq_char (WEAR_WIELD)) == NULL)
    return;

  if (ch->get_eq_char (WEAR_WIELD) == NULL && number_percent() <= 50)
    return;

  ch->act ("$n DISARMS you!", NULL, victim, TO_VICT);
  ch->act ("You disarm $N!", NULL, victim, TO_CHAR);
  ch->act ("$n DISARMS $N!", NULL, victim, TO_NOTVICT);

  obj->obj_from_char();
  if (victim->is_npc ())
    obj->obj_to_char (victim);
  else
    obj->obj_to_room (victim->in_room);

  return;
}

/*
 * Trip a creature.
 * Caller must check for successful attack.
 */
void trip (Character * ch, Character * victim)
{
  if (victim->wait == 0) {
    ch->act ("$n trips you and you go down!", NULL, victim, TO_VICT);
    ch->act ("You trip $N and $N goes down!", NULL, victim, TO_CHAR);
    ch->act ("$n trips $N and $N goes down!", NULL, victim, TO_NOTVICT);

    ch->wait_state (2 * PULSE_VIOLENCE);
    victim->wait_state (2 * PULSE_VIOLENCE);
    victim->position = POS_RESTING;
  }

  return;
}

/*
 * Inflict damage from a hit.
 */
void damage (Character * ch, Character * victim, int dam, int dt)
{
  if (victim->position == POS_DEAD)
    return;

  /*
   * Stop up any residual loopholes.
   */
  if (dam > 1000) {
    bug_printf ("Damage: %d: more than 1000 points!", dam);
    dam = 1000;
  }

  if (victim != ch) {
    /*
     * Certain attacks are forbidden.
     * Most other attacks are returned.
     */
    if (is_safe (ch, victim))
      return;
    check_killer (ch, victim);

    if (victim->position > POS_STUNNED) {
      if (victim->fighting == NULL)
        victim->set_fighting(ch);
      victim->position = POS_FIGHTING;
    }

    if (victim->position > POS_STUNNED) {
      if (ch->fighting == NULL)
        ch->set_fighting(victim);

      /*
       * If victim is charmed, ch might attack victim's master.
       */
      if (ch->is_npc ()
        && victim->is_npc ()
        && victim->is_affected (AFF_CHARM)
        && victim->master != NULL
        && victim->master->in_room == ch->in_room && number_range(0, 7) == 0) {
        ch->stop_fighting(false);
        multi_hit (ch, victim->master, TYPE_UNDEFINED);
        return;
      }
    }

    /*
     * More charm stuff.
     */
    if (victim->master == ch)
      victim->stop_follower();

    /*
     * Inviso attacks ... not.
     */
    if (ch->is_affected (AFF_INVISIBLE)) {
      ch->affect_strip (gsn_invis);
      ch->affect_strip (gsn_mass_invis);
      REMOVE_BIT (ch->affected_by, AFF_INVISIBLE);
      ch->act ("$n fades into existence.", NULL, NULL, TO_ROOM);
    }

    /*
     * Damage modifiers.
     */
    if (victim->is_affected (AFF_SANCTUARY))
      dam /= 2;

    if (victim->is_affected (AFF_PROTECT) && ch->is_evil ())
      dam -= dam / 4;

    if (dam < 0)
      dam = 0;

    /*
     * Check for disarm, trip, parry, and dodge.
     */
    if (dt >= TYPE_HIT) {
      if (ch->is_npc () && number_percent () < ch->level / 2)
        disarm (ch, victim);
      if (ch->is_npc () && number_percent () < ch->level / 2)
        trip (ch, victim);
      if (check_parry (ch, victim))
        return;
      if (check_dodge (ch, victim))
        return;
    }

    dam_message (ch, victim, dam, dt);
  }

  /*
   * Hurt the victim.
   * Inform the victim of his new state.
   */
  victim->hit -= dam;
  if (!victim->is_npc ()
    && victim->level >= LEVEL_IMMORTAL && victim->hit < 1)
    victim->hit = 1;
  victim->update_pos();

  switch (victim->position) {
  case POS_MORTAL:
    victim->act ("$n is mortally wounded, and will die soon, if not aided.",
      NULL, NULL, TO_ROOM);
    victim->send_to_char
      ("You are mortally wounded, and will die soon, if not aided.\r\n");
    break;

  case POS_INCAP:
    victim->act ("$n is incapacitated and will slowly die, if not aided.",
      NULL, NULL, TO_ROOM);
    victim->send_to_char
      ("You are incapacitated and will slowly die, if not aided.\r\n");
    break;

  case POS_STUNNED:
    victim->act ("$n is stunned, but will probably recover.",
      NULL, NULL, TO_ROOM);
    victim->send_to_char ("You are stunned, but will probably recover.\r\n");
    break;

  case POS_DEAD:
    victim->act ("$n is DEAD!!", 0, 0, TO_ROOM);
    victim->send_to_char ("You have been KILLED!!\r\n\r\n");
    break;

  default:
    if (dam > victim->max_hit / 4)
      victim->send_to_char ("That really did HURT!\r\n");
    if (victim->hit < victim->max_hit / 4)
      victim->send_to_char ("You sure are BLEEDING!\r\n");
    break;
  }

  /*
   * Sleep spells and extremely wounded folks.
   */
  if (!victim->is_awake ())
    victim->stop_fighting(false);

  /*
   * Payoff for killing things.
   */
  if (victim->position == POS_DEAD) {
    group_gain (ch, victim);

    if (!victim->is_npc ()) {
      log_printf ("%s killed by %s at %d", victim->name.c_str(),
        (ch->is_npc () ? ch->short_descr.c_str() : ch->name.c_str()), victim->in_room->vnum);

      /*
       * Dying penalty:
       * 1/2 way back to previous level.
       */
      if (victim->exp > 1000 * victim->level)
        victim->gain_exp((1000 * victim->level - victim->exp) / 2);
    }

    raw_kill (victim);

    if (!ch->is_npc () && victim->is_npc ()) {
      if (IS_SET (ch->actflags, PLR_AUTOLOOT))
        ch->do_get ("all corpse");
      else
        ch->do_look ("in corpse");

      if (IS_SET (ch->actflags, PLR_AUTOSAC))
        ch->do_sacrifice ("corpse");
    }

    return;
  }

  if (victim == ch)
    return;

  /*
   * Take care of link dead people.
   */
  if (!victim->is_npc () && victim->desc == NULL) {
    if (number_range (0, victim->wait) == 0) {
      victim->do_recall ("");
      return;
    }
  }

  /*
   * Wimp out?
   */
  if (victim->is_npc () && dam > 0) {
    if ((IS_SET (victim->actflags, ACT_WIMPY) && number_percent() <= 50
        && victim->hit < victim->max_hit / 2)
      || (victim->is_affected (AFF_CHARM) && victim->master != NULL
        && victim->master->in_room != victim->in_room))
      victim->do_flee ("");
  }

  if (!victim->is_npc ()
    && victim->hit > 0 && victim->hit <= victim->wimpy && victim->wait == 0)
    victim->do_flee ("");

  tail_chain ();
  return;
}

/*
 * Hit one guy once.
 */
void one_hit (Character * ch, Character * victim, int dt)
{
  Object *wield;
  int victim_ac;
  int thac0;
  int thac0_00;
  int thac0_32;
  int dam;

  /*
   * Can't beat a dead char!
   * Guard against weird room-leavings.
   */
  if (victim->position == POS_DEAD || ch->in_room != victim->in_room)
    return;

  /*
   * Figure out the type of damage message.
   */
  wield = ch->get_eq_char (WEAR_WIELD);
  if (dt == TYPE_UNDEFINED) {
    dt = TYPE_HIT;
    if (wield != NULL && wield->item_type == ITEM_WEAPON)
      dt += wield->value[3];
  }

  /*
   * Calculate to-hit-armor-class-0 versus armor.
   */
  if (ch->is_npc ()) {
    thac0_00 = 20;
    thac0_32 = 0;
  } else {
    thac0_00 = class_table[ch->klass].thac0_00;
    thac0_32 = class_table[ch->klass].thac0_32;
  }
  thac0 = interpolate (ch->level, thac0_00, thac0_32) - ch->get_hitroll();
  victim_ac = std::max (-15, victim->get_ac() / 10);
  if (!ch->can_see(victim))
    victim_ac -= 4;

  /*
   * The moment of excitement!
   */
  int diceroll = number_range(0, 19);
  if (diceroll == 0 || (diceroll != 19 && diceroll < thac0 - victim_ac)) {
    /* Miss. */
    damage (ch, victim, 0, dt);
    tail_chain ();
    return;
  }

  /*
   * Hit.
   * Calc damage.
   */
  if (ch->is_npc ()) {
    dam = number_range (ch->level / 2, ch->level * 3 / 2);
    if (wield != NULL)
      dam += dam / 2;
  } else {
    if (wield != NULL)
      dam = number_range (wield->value[1], wield->value[2]);
    else
      dam = number_range (1, 4);
  }

  /*
   * Bonuses.
   */
  dam += ch->get_damroll();
  if (!ch->is_npc () && ch->pcdata->learned[gsn_enhanced_damage] > 0)
    dam += dam * ch->pcdata->learned[gsn_enhanced_damage] / 150;
  if (!victim->is_awake ())
    dam *= 2;
  if (dt == gsn_backstab)
    dam *= 2 + ch->level / 8;

  if (dam <= 0)
    dam = 1;

  damage (ch, victim, dam, dt);
  tail_chain ();
  return;
}

/*
 * Do one group of attacks.
 */
void multi_hit (Character * ch, Character * victim, int dt)
{
  int chance;

  one_hit (ch, victim, dt);
  if (ch->fighting != victim || dt == gsn_backstab)
    return;

  chance =
    ch->is_npc () ? ch->level : ch->pcdata->learned[gsn_second_attack] / 2;
  if (number_percent () < chance) {
    one_hit (ch, victim, dt);
    if (ch->fighting != victim)
      return;
  }

  chance =
    ch->is_npc () ? ch->level : ch->pcdata->learned[gsn_third_attack] / 4;
  if (number_percent () < chance) {
    one_hit (ch, victim, dt);
    if (ch->fighting != victim)
      return;
  }

  chance = ch->is_npc () ? ch->level / 2 : 0;
  if (number_percent () < chance)
    one_hit (ch, victim, dt);

  return;
}

/*
 * Utter mystical words for an sn.
 */
void say_spell (Character * ch, int sn)
{
  std::string mwords, buf, buf2;
  const char *pName;
  int iSyl;
  int length;

  struct syl_type {
    char *old;
    char *newsyl;
  };

  static const struct syl_type syl_table[] = {
    {" ", " "},
    {"ar", "abra"},
    {"au", "kada"},
    {"bless", "fido"},
    {"blind", "nose"},
    {"bur", "mosa"},
    {"cu", "judi"},
    {"de", "oculo"},
    {"en", "unso"},
    {"light", "dies"},
    {"lo", "hi"},
    {"mor", "zak"},
    {"move", "sido"},
    {"ness", "lacri"},
    {"ning", "illa"},
    {"per", "duda"},
    {"ra", "gru"},
    {"re", "candus"},
    {"son", "sabru"},
    {"tect", "infra"},
    {"tri", "cula"},
    {"ven", "nofo"},
    {"a", "a"}, {"b", "b"}, {"c", "q"}, {"d", "e"},
    {"e", "z"}, {"f", "y"}, {"g", "o"}, {"h", "p"},
    {"i", "u"}, {"j", "y"}, {"k", "t"}, {"l", "r"},
    {"m", "w"}, {"n", "i"}, {"o", "a"}, {"p", "s"},
    {"q", "d"}, {"r", "f"}, {"s", "g"}, {"t", "h"},
    {"u", "j"}, {"v", "z"}, {"w", "x"}, {"x", "n"},
    {"y", "l"}, {"z", "k"},
    {"", ""}
  };

  for (pName = skill_table[sn].name; *pName != '\0'; pName += length) {
    for (iSyl = 0; (length = strlen (syl_table[iSyl].old)) != 0; iSyl++) {
      if (!str_prefix (syl_table[iSyl].old, pName)) {
        mwords.append(syl_table[iSyl].newsyl);
        break;
      }
    }

    if (length == 0)
      length = 1;
  }

  buf = "$n utters the words, '";
  buf.append(skill_table[sn].name);
  buf.append("'.");
  buf2 = "$n utters the words, '";
  buf2.append(mwords);
  buf2.append("'.");

  CharIter rch;
  for (rch = ch->in_room->people.begin(); rch != ch->in_room->people.end(); rch++) {
    if (*rch != ch)
      ch->act ( (ch->klass == (*rch)->klass ? buf : buf2).c_str(), NULL, *rch, TO_VICT);
  }

  return;
}

/*
 * Cast spells at targets using a magical object.
 */
void obj_cast_spell (int sn, int level, Character * ch, Character * victim,
  Object * obj)
{
  void *vo;

  if (sn <= 0)
    return;

  if (sn >= MAX_SKILL || skill_table[sn].spell_fun == 0) {
    bug_printf ("Obj_cast_spell: bad sn %d.", sn);
    return;
  }

  switch (skill_table[sn].target) {
  default:
    bug_printf ("Obj_cast_spell: bad target for sn %d.", sn);
    return;

  case TAR_IGNORE:
    vo = NULL;
    break;

  case TAR_CHAR_OFFENSIVE:
    if (victim == NULL)
      victim = ch->fighting;
    if (victim == NULL || !victim->is_npc ()) {
      ch->send_to_char ("You can't do that.\r\n");
      return;
    }
    vo = (void *) victim;
    break;

  case TAR_CHAR_DEFENSIVE:
    if (victim == NULL)
      victim = ch;
    vo = (void *) victim;
    break;

  case TAR_CHAR_SELF:
    vo = (void *) ch;
    break;

  case TAR_OBJ_INV:
    if (obj == NULL) {
      ch->send_to_char ("You can't do that.\r\n");
      return;
    }
    vo = (void *) obj;
    break;
  }

  target_name = "";
  (ch->*(skill_table[sn].spell_fun)) (sn, level, vo);

  if (skill_table[sn].target == TAR_CHAR_OFFENSIVE && victim->master != ch) {
    Character *vch;

    CharIter rch, next;
    for (rch = ch->in_room->people.begin(); rch != ch->in_room->people.end(); rch = next) {
      vch = *rch;
      next = ++rch;
      if (victim == vch && victim->fighting == NULL) {
        multi_hit (victim, ch, TYPE_UNDEFINED);
        break;
      }
    }
  }

  return;
}

/* Snarf a MOBprogram section from the area file.
 */
void load_mobprogs (std::ifstream & fp)
{
  char letter;
  MobPrototype *iMob;
  int value;
  MobProgram *original;
  MobProgram *working;

  for (;;)
    switch (letter = fread_letter (fp)) {
    default:
      fatal_printf ("Load_mobprogs: bad command '%c'.", letter);
      break;
    case 'S':
    case 's':
      fread_to_eol (fp);
      return;
    case '*':
      fread_to_eol (fp);
      break;
    case 'M':
    case 'm':
      value = fread_number (fp);
      if ((iMob = get_mob_index (value)) == NULL) {
        fatal_printf ("Load_mobprogs: vnum %d doesnt exist", value);
      }

      if ((original = iMob->mobprogs) != NULL)
        for (; original->next != NULL; original = original->next);
      working = new MobProgram();
      if (original)
        original->next = working;
      else
        iMob->mobprogs = working;
      working = mprog_file_read (fread_word (fp), working, iMob);
      working->next = NULL;
      fread_to_eol (fp);
      break;
    }
}

void mprog_percent_check (Character * mob, Character * actor, Object * obj,
  void *vo, int type)
{
  MobProgram *mprg;

  for (mprg = mob->pIndexData->mobprogs; mprg != NULL; mprg = mprg->next)
    if ((mprg->type & type)
      && (number_percent () < atoi (mprg->arglist.c_str()))) {
      mprog_driver (mprg->comlist, mob, actor, obj, vo);
      if (type != GREET_PROG && type != ALL_GREET_PROG)
        break;
    }

  return;

}

/* The triggers.. These are really basic, and since most appear only
 * once in the code (hmm. i think they all do) it would be more efficient
 * to substitute the code in and make the mprog_xxx_check routines global.
 * However, they are all here in one nice place at the moment to make it
 * easier to see what they look like. If you do substitute them back in,
 * make sure you remember to modify the variable names to the ones in the
 * trigger calls.
 */
void mprog_act_trigger (const std::string & buf, Character * mob, Character * ch,
  Object * obj, void *vo)
{
  if (mob == NULL || ch == NULL)
    return;

  MobProgramActList *tmp_act;

  if (mob->is_npc ()
    && (mob->pIndexData->progtypes & ACT_PROG)) {
    tmp_act = new MobProgramActList();
    if (mob->mpactnum > 0)
      tmp_act->next = mob->mpact->next;
    else
      tmp_act->next = NULL;

    mob->mpact = tmp_act;
    mob->mpact->buf = buf;
    mob->mpact->ch = ch;
    mob->mpact->obj = obj;
    mob->mpact->vo = vo;
    mob->mpactnum++;

  }
  return;

}

void mprog_bribe_trigger (Character * mob, Character * ch, int amount)
{
  if (mob == NULL || ch == NULL)
    return;

  char buf[MAX_STRING_LENGTH];
  MobProgram *mprg;
  Object *obj;

  if (mob->is_npc ()
    && (mob->pIndexData->progtypes & BRIBE_PROG)) {
    obj = get_obj_index (OBJ_VNUM_MONEY_SOME)->create_object(0);
    snprintf (buf, sizeof buf, obj->short_descr.c_str(), amount);
    obj->short_descr = buf;
    obj->value[0] = amount;
    obj->obj_to_char (mob);
    mob->gold -= amount;

    for (mprg = mob->pIndexData->mobprogs; mprg != NULL; mprg = mprg->next)
      if ((mprg->type & BRIBE_PROG)
        && (amount >= atoi (mprg->arglist.c_str()))) {
        mprog_driver (mprg->comlist, mob, ch, obj, NULL);
        break;
      }
  }

  return;

}

void mprog_death_trigger (Character * mob)
{
  if (mob == NULL)
    return;

  if (mob->is_npc ()
    && (mob->pIndexData->progtypes & DEATH_PROG)) {
    mprog_percent_check (mob, NULL, NULL, NULL, DEATH_PROG);
  }

  death_cry (mob);
  return;

}

void mprog_entry_trigger (Character * mob)
{
  if (mob == NULL)
    return;

  if (mob->is_npc ()
    && (mob->pIndexData->progtypes & ENTRY_PROG))
    mprog_percent_check (mob, NULL, NULL, NULL, ENTRY_PROG);

  return;

}

void mprog_fight_trigger (Character * mob, Character * ch)
{
  if (mob == NULL || ch == NULL)
    return;

  if (mob->is_npc ()
    && (mob->pIndexData->progtypes & FIGHT_PROG))
    mprog_percent_check (mob, ch, NULL, NULL, FIGHT_PROG);

  return;

}

void mprog_give_trigger (Character * mob, Character * ch, Object * obj)
{
  if (mob == NULL || ch == NULL || obj == NULL)
    return;

  std::string buf;
  MobProgram *mprg;

  if (mob->is_npc ()
    && (mob->pIndexData->progtypes & GIVE_PROG))
    for (mprg = mob->pIndexData->mobprogs; mprg != NULL; mprg = mprg->next) {
      one_argument (mprg->arglist, buf);
      if ((mprg->type & GIVE_PROG)
        && ((!str_cmp (obj->name, mprg->arglist))
          || (!str_cmp ("all", buf)))) {
        mprog_driver (mprg->comlist, mob, ch, obj, NULL);
        break;
      }
    }

  return;

}

void mprog_greet_trigger (Character * mob)
{
  if (mob == NULL)
    return;

  Room* rm = mob->in_room;
  Character* vmob;
  CharIter v;
  for (v = rm->people.begin(); v != rm->people.end(); v++) {
    vmob = *v;
    if (vmob->is_npc ()
      && (vmob->fighting == NULL)
      && vmob->is_awake ()) {
      if (mob != vmob && vmob->can_see(mob)
        && (vmob->pIndexData->progtypes & GREET_PROG)) {
        mprog_percent_check (vmob, mob, NULL, NULL, GREET_PROG);
      } else if (vmob->pIndexData->progtypes & ALL_GREET_PROG) {
        mprog_percent_check (vmob, mob, NULL, NULL, ALL_GREET_PROG);
      }
    }
  }
  return;
}

void mprog_hitprcnt_trigger (Character * mob, Character * ch)
{
  if (mob == NULL || ch == NULL)
    return;
  MobProgram *mprg;

  if (mob->is_npc ()
    && (mob->pIndexData->progtypes & HITPRCNT_PROG))
    for (mprg = mob->pIndexData->mobprogs; mprg != NULL; mprg = mprg->next)
      if ((mprg->type & HITPRCNT_PROG)
        && ((100 * mob->hit / mob->max_hit) < atoi (mprg->arglist.c_str()))) {
        mprog_driver (mprg->comlist, mob, ch, NULL, NULL);
        break;
      }

  return;

}

void mprog_random_trigger (Character * mob)
{
  if (mob == NULL)
    return;

  if (mob->pIndexData->progtypes & RAND_PROG)
    mprog_percent_check (mob, NULL, NULL, NULL, RAND_PROG);

  return;

}

void mprog_speech_trigger (const std::string & txt, Character * mob)
{
  if (mob == NULL)
    return;

  Room* rm = mob->in_room;
  Character* vmob;
  CharIter v;
  for (v = rm->people.begin(); v != rm->people.end(); v++) {
    vmob = *v;
    if (vmob->is_npc () && (vmob->pIndexData->progtypes & SPEECH_PROG))
      mprog_wordlist_check (txt, vmob, mob, NULL, NULL, SPEECH_PROG);
  }

  return;

}

void Character::do_areas (std::string argument)
{
  char buf[MAX_STRING_LENGTH];
  std::list<Area *>::iterator pArea1;
  std::list<Area *>::iterator pArea2;
  int iArea;
  int iAreaHalf;

  iAreaHalf = (Area::top_area + 1) / 2;
  pArea1 = pArea2 = area_list.begin();

  for (iArea = 0; iArea < iAreaHalf; iArea++, pArea2++);

  for (iArea = 0; iArea < iAreaHalf; iArea++, pArea1++, pArea2++) {
    snprintf (buf, sizeof buf, "%-39s%-39s\r\n",
      (*pArea1)->name.c_str(), (pArea2 != area_list.end()) ? (*pArea2)->name.c_str() : "");
    send_to_char (buf);
  }

  return;
}

void Character::do_memory (std::string argument)
{
  char buf[MAX_STRING_LENGTH];

  snprintf (buf, sizeof buf, "Affects %5d\r\n", Affect::top_affect);
  send_to_char (buf);
  snprintf (buf, sizeof buf, "Areas   %5d\r\n", Area::top_area);
  send_to_char (buf);
  snprintf (buf, sizeof buf, "ExDes   %5d\r\n", ExtraDescription::top_ed);
  send_to_char (buf);
  snprintf (buf, sizeof buf, "Exits   %5d\r\n", Exit::top_exit);
  send_to_char (buf);
  snprintf (buf, sizeof buf, "Helps   %5d\r\n", Help::top_help);
  send_to_char (buf);
  snprintf (buf, sizeof buf, "Mobs    %5d\r\n", MobPrototype::top_mob);
  send_to_char (buf);
  snprintf (buf, sizeof buf, "Objs    %5d\r\n", ObjectPrototype::top_obj);
  send_to_char (buf);
  snprintf (buf, sizeof buf, "Resets  %5d\r\n", Reset::top_reset);
  send_to_char (buf);
  snprintf (buf, sizeof buf, "Rooms   %5d\r\n", Room::top_room);
  send_to_char (buf);
  snprintf (buf, sizeof buf, "Shops   %5d\r\n", Shop::top_shop);
  send_to_char (buf);
  return;
}

/*
 * Core procedure for dragons.
 */
bool dragon (Character * ch, char *spell_name)
{
  Character *victim = NULL;
  int sn;

  if (ch->position != POS_FIGHTING)
    return false;

  CharIter rch;
  for (rch = ch->in_room->people.begin(); rch != ch->in_room->people.end(); rch++) {
    if ((*rch)->fighting == ch && number_percent() <= 25) {
      victim = *rch;
      break;
    }
  }

  if (victim == NULL)
    return false;

  if ((sn = skill_lookup (spell_name)) < 0)
    return false;
  (ch->*(skill_table[sn].spell_fun)) (sn, ch->level, victim);
  return true;
}

/*
 * Special procedures for mobiles.
 */
bool spec_breath_any (Character * ch)
{
  if (ch->position != POS_FIGHTING)
    return false;

  switch (number_range(0, 7)) {
  case 0:
    return spec_breath_fire (ch);
  case 1:
  case 2:
    return spec_breath_lightning (ch);
  case 3:
    return spec_breath_gas (ch);
  case 4:
    return spec_breath_acid (ch);
  case 5:
  case 6:
  case 7:
    return spec_breath_frost (ch);
  }

  return false;
}

bool spec_breath_acid (Character * ch)
{
  return dragon (ch, "acid breath");
}

bool spec_breath_fire (Character * ch)
{
  return dragon (ch, "fire breath");
}

bool spec_breath_frost (Character * ch)
{
  return dragon (ch, "frost breath");
}

bool spec_breath_gas (Character * ch)
{
  int sn;

  if (ch->position != POS_FIGHTING)
    return false;

  if ((sn = skill_lookup ("gas breath")) < 0)
    return false;
  (ch->*(skill_table[sn].spell_fun)) (sn, ch->level, NULL);
  return true;
}

bool spec_breath_lightning (Character * ch)
{
  return dragon (ch, "lightning breath");
}

bool spec_cast_adept (Character * ch)
{
  Character *victim = NULL;

  if (!ch->is_awake ())
    return false;

  CharIter rch;
  for (rch = ch->in_room->people.begin(); rch != ch->in_room->people.end(); rch++) {
    if (*rch != ch && ch->can_see(*rch) && number_percent() <= 50) {
      victim = *rch;
      break;
    }
  }

  if (victim == NULL)
    return false;

  switch (number_range(0, 7)) {
  case 0:
    ch->act ("$n utters the word 'tehctah'.", NULL, NULL, TO_ROOM);
    ch->spell_armor (skill_lookup ("armor"), ch->level, victim);
    return true;

  case 1:
    ch->act ("$n utters the word 'nhak'.", NULL, NULL, TO_ROOM);
    ch->spell_bless (skill_lookup ("bless"), ch->level, victim);
    return true;

  case 2:
    ch->act ("$n utters the word 'yeruf'.", NULL, NULL, TO_ROOM);
    ch->spell_cure_blindness (skill_lookup ("cure blindness"),
      ch->level, victim);
    return true;

  case 3:
    ch->act ("$n utters the word 'garf'.", NULL, NULL, TO_ROOM);
    ch->spell_cure_light (skill_lookup ("cure light"), ch->level, victim);
    return true;

  case 4:
    ch->act ("$n utters the words 'rozar'.", NULL, NULL, TO_ROOM);
    ch->spell_cure_poison (skill_lookup ("cure poison"), ch->level, victim);
    return true;

  case 5:
    ch->act ("$n utters the words 'nadroj'.", NULL, NULL, TO_ROOM);
    ch->spell_refresh (skill_lookup ("refresh"), ch->level, victim);
    return true;

  }

  return false;
}

bool spec_cast_cleric (Character * ch)
{
  Character *victim = NULL;
  char *spell;
  int sn;

  if (ch->position != POS_FIGHTING)
    return false;

  CharIter rch;
  for (rch = ch->in_room->people.begin(); rch != ch->in_room->people.end(); rch++) {
    if ((*rch)->fighting == ch && number_percent() <= 50) {
      victim = *rch;
      break;
    }
  }

  if (victim == NULL)
    return false;

  for (;;) {
    int min_level;

    switch (number_range(0, 15)) {
    case 0:
      min_level = 0;
      spell = "blindness";
      break;
    case 1:
      min_level = 3;
      spell = "cause serious";
      break;
    case 2:
      min_level = 7;
      spell = "earthquake";
      break;
    case 3:
      min_level = 9;
      spell = "cause critical";
      break;
    case 4:
      min_level = 10;
      spell = "dispel evil";
      break;
    case 5:
      min_level = 12;
      spell = "curse";
      break;
    case 6:
      min_level = 12;
      spell = "change sex";
      break;
    case 7:
      min_level = 13;
      spell = "flamestrike";
      break;
    case 8:
    case 9:
    case 10:
      min_level = 15;
      spell = "harm";
      break;
    default:
      min_level = 16;
      spell = "dispel magic";
      break;
    }

    if (ch->level >= min_level)
      break;
  }

  if ((sn = skill_lookup (spell)) < 0)
    return false;
  (ch->*(skill_table[sn].spell_fun)) (sn, ch->level, victim);
  return true;
}

bool spec_cast_judge (Character * ch)
{
  Character *victim = NULL;
  char *spell;
  int sn;

  if (ch->position != POS_FIGHTING)
    return false;

  CharIter rch;
  for (rch = ch->in_room->people.begin(); rch != ch->in_room->people.end(); rch++) {
    if ((*rch)->fighting == ch && number_percent() <= 50) {
      victim = *rch;
      break;
    }
  }

  if (victim == NULL)
    return false;

  spell = "high explosive";
  if ((sn = skill_lookup (spell)) < 0)
    return false;
  (ch->*(skill_table[sn].spell_fun)) (sn, ch->level, victim);
  return true;
}

bool spec_cast_mage (Character * ch)
{
  Character *victim = NULL;
  char *spell;
  int sn;

  if (ch->position != POS_FIGHTING)
    return false;

  CharIter rch;
  for (rch = ch->in_room->people.begin(); rch != ch->in_room->people.end(); rch++) {
    if ((*rch)->fighting == ch && number_percent() <= 50) {
      victim = *rch;
      break;
    }
  }

  if (victim == NULL)
    return false;

  for (;;) {
    int min_level;

    switch (number_range(0, 15)) {
    case 0:
      min_level = 0;
      spell = "blindness";
      break;
    case 1:
      min_level = 3;
      spell = "chill touch";
      break;
    case 2:
      min_level = 7;
      spell = "weaken";
      break;
    case 3:
      min_level = 8;
      spell = "teleport";
      break;
    case 4:
      min_level = 11;
      spell = "colour spray";
      break;
    case 5:
      min_level = 12;
      spell = "change sex";
      break;
    case 6:
      min_level = 13;
      spell = "energy drain";
      break;
    case 7:
    case 8:
    case 9:
      min_level = 15;
      spell = "fireball";
      break;
    default:
      min_level = 20;
      spell = "acid blast";
      break;
    }

    if (ch->level >= min_level)
      break;
  }

  if ((sn = skill_lookup (spell)) < 0)
    return false;
  (ch->*(skill_table[sn].spell_fun)) (sn, ch->level, victim);
  return true;
}

bool spec_cast_undead (Character * ch)
{
  Character *victim = NULL;
  char *spell;
  int sn;

  if (ch->position != POS_FIGHTING)
    return false;

  CharIter rch;
  for (rch = ch->in_room->people.begin(); rch != ch->in_room->people.end(); rch++) {
    if ((*rch)->fighting == ch && number_percent() <= 50) {
      victim = *rch;
      break;
    }
  }

  if (victim == NULL)
    return false;

  for (;;) {
    int min_level;

    switch (number_range(0, 15)) {
    case 0:
      min_level = 0;
      spell = "curse";
      break;
    case 1:
      min_level = 3;
      spell = "weaken";
      break;
    case 2:
      min_level = 6;
      spell = "chill touch";
      break;
    case 3:
      min_level = 9;
      spell = "blindness";
      break;
    case 4:
      min_level = 12;
      spell = "poison";
      break;
    case 5:
      min_level = 15;
      spell = "energy drain";
      break;
    case 6:
      min_level = 18;
      spell = "harm";
      break;
    case 7:
      min_level = 21;
      spell = "teleport";
      break;
    default:
      min_level = 24;
      spell = "gate";
      break;
    }

    if (ch->level >= min_level)
      break;
  }

  if ((sn = skill_lookup (spell)) < 0)
    return false;
  (ch->*(skill_table[sn].spell_fun)) (sn, ch->level, victim);
  return true;
}

bool spec_executioner (Character * ch)
{
  if (!ch->is_awake () || ch->fighting != NULL)
    return false;

  Character *victim = NULL;
  char *crime = "";
  CharIter rch;
  for (rch = ch->in_room->people.begin(); rch != ch->in_room->people.end(); rch++) {

    if (!(*rch)->is_npc () && IS_SET ((*rch)->actflags, PLR_KILLER)) {
      victim = *rch;
      crime = "KILLER";
      break;
    }

    if (!(*rch)->is_npc () && IS_SET ((*rch)->actflags, PLR_THIEF)) {
      victim = *rch;
      crime = "THIEF";
      break;
    }
  }

  if (victim == NULL)
    return false;

  char buf[MAX_STRING_LENGTH];
  snprintf (buf, sizeof buf, "%s is a %s!  PROTECT THE INNOCENT!  MORE BLOOOOD!!!",
    victim->name.c_str(), crime);
  ch->do_shout (buf);
  multi_hit (ch, victim, TYPE_UNDEFINED);
  get_mob_index(MOB_VNUM_CITYGUARD)->create_mobile()->char_to_room(ch->in_room);
  get_mob_index(MOB_VNUM_CITYGUARD)->create_mobile()->char_to_room(ch->in_room);
  return true;
}

bool spec_fido (Character * ch)
{
  if (!ch->is_awake ())
    return false;

  Object *corpse;
  Object *obj;
  ObjIter c, cnext;
  for (c = ch->in_room->contents.begin(); c != ch->in_room->contents.end(); c = cnext) {
    corpse = *c;
    cnext = ++c;
    if (corpse->item_type != ITEM_CORPSE_NPC)
      continue;

    ch->act ("$n savagely devours a corpse.", NULL, NULL, TO_ROOM);
    ObjIter o, onext;
    for (o = corpse->contains.begin(); o != corpse->contains.end(); o = onext) {
      obj = *o;
      onext = ++o;
      obj->obj_from_obj ();
      obj->obj_to_room (ch->in_room);
    }
    corpse->extract_obj ();
    return true;
  }

  return false;
}

bool spec_guard (Character * ch)
{
  if (!ch->is_awake () || ch->fighting != NULL)
    return false;

  Character *victim = NULL;
  int max_evil = 300;
  Character* ech = NULL;
  char* crime = "";
  CharIter rch;
  for (rch = ch->in_room->people.begin(); rch != ch->in_room->people.end(); rch++) {

    if (!(*rch)->is_npc () && IS_SET ((*rch)->actflags, PLR_KILLER)) {
      victim = *rch;
      crime = "KILLER";
      break;
    }

    if (!(*rch)->is_npc () && IS_SET ((*rch)->actflags, PLR_THIEF)) {
      victim = *rch;
      crime = "THIEF";
      break;
    }

    if ((*rch)->fighting != NULL
      && (*rch)->fighting != ch && (*rch)->alignment < max_evil) {
      max_evil = (*rch)->alignment;
      ech = *rch;
    }
  }

  if (victim != NULL) {
    char buf[MAX_STRING_LENGTH];
    snprintf (buf, sizeof buf, "%s is a %s!  PROTECT THE INNOCENT!!  BANZAI!!",
      victim->name.c_str(), crime);
    ch->do_shout (buf);
    multi_hit (ch, victim, TYPE_UNDEFINED);
    return true;
  }

  if (ech != NULL) {
    ch->act ("$n screams 'PROTECT THE INNOCENT!!  BANZAI!!",
      NULL, NULL, TO_ROOM);
    multi_hit (ch, ech, TYPE_UNDEFINED);
    return true;
  }

  return false;
}

bool spec_janitor (Character * ch)
{
  Object *trash;

  if (!ch->is_awake ())
    return false;

  ObjIter o, onext;
  for (o = ch->in_room->contents.begin(); o != ch->in_room->contents.end(); o = onext) {
    trash = *o;
    onext = ++o;
    if (!IS_SET (trash->wear_flags, ITEM_TAKE))
      continue;
    if (trash->item_type == ITEM_DRINK_CON
      || trash->item_type == ITEM_TRASH || trash->cost < 10) {
      ch->act ("$n picks up some trash.", NULL, NULL, TO_ROOM);
      trash->obj_from_room ();
      trash->obj_to_char (ch);
      return true;
    }
  }

  return false;
}

bool spec_mayor (Character * ch)
{
  static const char open_path[] =
    "W3a3003b33000c111d0d111Oe333333Oe22c222112212111a1S.";

  static const char close_path[] =
    "W3a3003b33000c111d0d111CE333333CE22c222112212111a1S.";

  static const char *path;
  static int pos;
  static bool move;

  if (!move) {
    if (time_info.hour == 6) {
      path = open_path;
      move = true;
      pos = 0;
    }

    if (time_info.hour == 20) {
      path = close_path;
      move = true;
      pos = 0;
    }
  }

  if (ch->fighting != NULL)
    return spec_cast_cleric (ch);
  if (!move || ch->position < POS_SLEEPING)
    return false;

  switch (path[pos]) {
  case '0':
  case '1':
  case '2':
  case '3':
    ch->move_char (path[pos] - '0');
    break;

  case 'W':
    ch->position = POS_STANDING;
    ch->act ("$n awakens and groans loudly.", NULL, NULL, TO_ROOM);
    break;

  case 'S':
    ch->position = POS_SLEEPING;
    ch->act ("$n lies down and falls asleep.", NULL, NULL, TO_ROOM);
    break;

  case 'a':
    ch->act ("$n says 'Hello Honey!'", NULL, NULL, TO_ROOM);
    break;

  case 'b':
    ch->act ("$n says 'What a view!  I must do something about that dump!'",
      NULL, NULL, TO_ROOM);
    break;

  case 'c':
    ch->act ("$n says 'Vandals!  Youngsters have no respect for anything!'",
      NULL, NULL, TO_ROOM);
    break;

  case 'd':
    ch->act ("$n says 'Good day, citizens!'", NULL, NULL, TO_ROOM);
    break;

  case 'e':
    ch->act ("$n says 'I hereby declare the city of Midgaard open!'",
      NULL, NULL, TO_ROOM);
    break;

  case 'E':
    ch->act ("$n says 'I hereby declare the city of Midgaard closed!'",
      NULL, NULL, TO_ROOM);
    break;

  case 'O':
    ch->do_unlock ("gate");
    ch->do_open ("gate");
    break;

  case 'C':
    ch->do_close ("gate");
    ch->do_lock ("gate");
    break;

  case '.':
    move = false;
    break;
  }

  pos++;
  return false;
}

bool spec_poison (Character * ch)
{
  Character *victim;

  if (ch->position != POS_FIGHTING
    || (victim = ch->fighting) == NULL || number_percent () > 2 * ch->level)
    return false;

  ch->act ("You bite $N!", NULL, victim, TO_CHAR);
  ch->act ("$n bites $N!", NULL, victim, TO_NOTVICT);
  ch->act ("$n bites you!", NULL, victim, TO_VICT);
  ch->spell_poison (gsn_poison, ch->level, victim);
  return true;
}

bool spec_thief (Character * ch)
{
  if (ch->position != POS_STANDING)
    return false;

  CharIter rch;
  for (rch = ch->in_room->people.begin(); rch != ch->in_room->people.end(); rch++) {
    Character* victim = *rch;

    if (victim->is_npc() || victim->level >= LEVEL_IMMORTAL ||
      number_percent() <= 75 || !ch->can_see(victim))      /* Thx Glop */
      continue;

    if (victim->is_awake () && number_range (0, ch->level) == 0) {
      ch->act ("You discover $n's hands in your wallet!",
        NULL, victim, TO_VICT);
      ch->act ("$N discovers $n's hands in $S wallet!",
        NULL, victim, TO_NOTVICT);
      return true;
    } else {
      int gold = victim->gold * number_range (1, 20) / 100;
      ch->gold += 7 * gold / 8;
      victim->gold -= gold;
      return true;
    }
  }

  return false;
}

void Character::do_kill (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Kill whom?\r\n");
    return;
  }

  Character *victim;
  if ((victim = get_char_room (arg)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (!victim->is_npc ()) {
    if (!IS_SET (victim->actflags, PLR_KILLER)
      && !IS_SET (victim->actflags, PLR_THIEF)) {
      send_to_char ("You must MURDER a player.\r\n");
      return;
    }
  } else {
    if (victim->is_affected (AFF_CHARM) && victim->master != NULL) {
      send_to_char ("You must MURDER a charmed creature.\r\n");
      return;
    }
  }

  if (victim == this) {
    send_to_char ("You hit yourself.  Ouch!\r\n");
    multi_hit (this, this, TYPE_UNDEFINED);
    return;
  }

  if (is_safe (this, victim))
    return;

  if (is_affected (AFF_CHARM) && master == victim) {
    act ("$N is your beloved master.", NULL, victim, TO_CHAR);
    return;
  }

  if (position == POS_FIGHTING) {
    send_to_char ("You do the best you can!\r\n");
    return;
  }

  wait_state (1 * PULSE_VIOLENCE);
  check_killer (this, victim);
  multi_hit (this, victim, TYPE_UNDEFINED);
  return;
}

void Character::do_murde (std::string argument)
{
  send_to_char ("If you want to MURDER, spell it out.\r\n");
  return;
}

void Character::do_murder (std::string argument)
{
  std::string arg, buf;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Murder whom?\r\n");
    return;
  }

  Character *victim;
  if ((victim = get_char_room (arg)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (victim == this) {
    send_to_char ("Suicide is a mortal sin.\r\n");
    return;
  }

  if (is_safe (this, victim))
    return;

  if (is_affected (AFF_CHARM) && master == victim) {
    act ("$N is your beloved master.", NULL, victim, TO_CHAR);
    return;
  }

  if (position == POS_FIGHTING) {
    send_to_char ("You do the best you can!\r\n");
    return;
  }

  wait_state (1 * PULSE_VIOLENCE);
  buf += "Help!  I am being attacked by " + name + "!";
  victim->do_shout (buf);
  check_killer (this, victim);
  multi_hit (this, victim, TYPE_UNDEFINED);
  return;
}

void Character::do_backstab (std::string argument)
{
  std::string arg;

  if (!is_npc ()
    && level < skill_table[gsn_backstab].skill_level[klass]) {
    send_to_char ("You better leave the assassin trade to thieves.\r\n");
    return;
  }

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Backstab whom?\r\n");
    return;
  }

  Character *victim;
  if ((victim = get_char_room (arg)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (victim == this) {
    send_to_char ("How can you sneak up on yourself?\r\n");
    return;
  }

  if (is_safe (this, victim))
    return;

  Object *obj;
  if ((obj = get_eq_char (WEAR_WIELD)) == NULL || obj->value[3] != 11) {
    send_to_char ("You need to wield a piercing weapon.\r\n");
    return;
  }

  if (victim->fighting != NULL) {
    send_to_char ("You can't backstab a fighting person.\r\n");
    return;
  }

  if (victim->hit < victim->max_hit) {
    act ("$N is hurt and suspicious ... you can't sneak up.",
      NULL, victim, TO_CHAR);
    return;
  }

  check_killer (this, victim);
  wait_state (skill_table[gsn_backstab].beats);
  if (!victim->is_awake ()
    || is_npc ()
    || number_percent () < pcdata->learned[gsn_backstab])
    multi_hit (this, victim, gsn_backstab);
  else
    damage (this, victim, 0, gsn_backstab);

  return;
}

void Character::do_flee (std::string argument)
{
  if (fighting == NULL) {
    if (position == POS_FIGHTING)
      position = POS_STANDING;
    send_to_char ("You aren't fighting anyone.\r\n");
    return;
  }

  Room *now_in;
  Room* was_in = in_room;
  for (int attempt = 0; attempt < 6; attempt++) {
    Exit *pexit;
    int door;

    door = number_door ();
    if ((pexit = was_in->exit[door]) == 0
      || pexit->to_room == NULL || IS_SET (pexit->exit_info, EX_CLOSED)
      || (is_npc ()
        && (IS_SET (pexit->to_room->room_flags, ROOM_NO_MOB)
          || (IS_SET (actflags, ACT_STAY_AREA)
            && pexit->to_room->area != in_room->area))))
      continue;

    move_char (door);
    if ((now_in = in_room) == was_in)
      continue;

    in_room = was_in;
    act ("$n has fled!", NULL, NULL, TO_ROOM);
    in_room = now_in;

    if (!is_npc ()) {
      send_to_char ("You flee from combat!  You lose 25 exps.\r\n");
      gain_exp(-25);
    }

    stop_fighting(true);
    return;
  }

  send_to_char ("You failed!  You lose 10 exps.\r\n");
  gain_exp(-10);
  return;
}

void Character::do_rescue (std::string argument)
{
  if (!is_npc ()
    && level < skill_table[gsn_rescue].skill_level[klass]) {
    send_to_char ("You better leave the heroic acts to warriors.\r\n");
    return;
  }

  std::string arg;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Rescue whom?\r\n");
    return;
  }

  Character *victim;
  if ((victim = get_char_room (arg)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (victim == this) {
    send_to_char ("What about fleeing instead?\r\n");
    return;
  }

  if (!is_npc () && victim->is_npc ()) {
    send_to_char ("Doesn't need your help!\r\n");
    return;
  }

  if (fighting == victim) {
    send_to_char ("Too late.\r\n");
    return;
  }

  Character *fch;
  if ((fch = victim->fighting) == NULL) {
    send_to_char ("That person is not fighting right now.\r\n");
    return;
  }

  wait_state (skill_table[gsn_rescue].beats);
  if (!is_npc () && number_percent () > pcdata->learned[gsn_rescue]) {
    send_to_char ("You fail the rescue.\r\n");
    return;
  }

  act ("You rescue $N!", NULL, victim, TO_CHAR);
  act ("$n rescues you!", NULL, victim, TO_VICT);
  act ("$n rescues $N!", NULL, victim, TO_NOTVICT);

  fch->stop_fighting(false);
  victim->stop_fighting(false);

  check_killer (this, fch);
  set_fighting(fch);
  fch->set_fighting(this);
  return;
}

void Character::do_kick (std::string argument)
{
  if (!is_npc ()
    && level < skill_table[gsn_kick].skill_level[klass]) {
    send_to_char ("You better leave the martial arts to fighters.\r\n");
    return;
  }

  Character *victim;

  if ((victim = fighting) == NULL) {
    send_to_char ("You aren't fighting anyone.\r\n");
    return;
  }

  wait_state (skill_table[gsn_kick].beats);
  if (is_npc () || number_percent () < pcdata->learned[gsn_kick])
    damage (this, victim, number_range (1, level), gsn_kick);
  else
    damage (this, victim, 0, gsn_kick);

  return;
}

void Character::do_disarm (std::string argument)
{
  if (!is_npc ()
    && level < skill_table[gsn_disarm].skill_level[klass]) {
    send_to_char ("You don't know how to disarm opponents.\r\n");
    return;
  }

  if (get_eq_char (WEAR_WIELD) == NULL) {
    send_to_char ("You must wield a weapon to disarm.\r\n");
    return;
  }

  Character *victim;

  if ((victim = fighting) == NULL) {
    send_to_char ("You aren't fighting anyone.\r\n");
    return;
  }

  if (victim->get_eq_char (WEAR_WIELD) == NULL) {
    send_to_char ("Your opponent is not wielding a weapon.\r\n");
    return;
  }

  wait_state (skill_table[gsn_disarm].beats);
  int percent = number_percent () + victim->level - level;
  if (is_npc () || percent < pcdata->learned[gsn_disarm] * 2 / 3)
    disarm (this, victim);
  else
    send_to_char ("You failed.\r\n");
  return;
}

void Character::do_sla (std::string argument)
{
  send_to_char ("If you want to SLAY, spell it out.\r\n");
  return;
}

void Character::do_slay (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);
  if (arg.empty()) {
    send_to_char ("Slay whom?\r\n");
    return;
  }

  Character *victim;
  if ((victim = get_char_room (arg)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (this == victim) {
    send_to_char ("Suicide is a mortal sin.\r\n");
    return;
  }

  if (!victim->is_npc () && victim->level >= level) {
    send_to_char ("You failed.\r\n");
    return;
  }

  act ("You slay $M in cold blood!", NULL, victim, TO_CHAR);
  act ("$n slays you in cold blood!", NULL, victim, TO_VICT);
  act ("$n slays $N in cold blood!", NULL, victim, TO_NOTVICT);
  raw_kill (victim);
  return;
}

void Character::do_cast (std::string argument)
{
  /*
   * Only MOBprogrammed mobs not charmed can cast spells
   * like PC's
   */
  if (is_npc ()
    && (!pIndexData->progtypes || is_affected (AFF_CHARM)))
    return;

  std::string arg1, arg2;

  target_name = one_argument (argument, arg1);
  one_argument (target_name, arg2);

  if (arg1.empty()) {
    send_to_char ("Cast which what where?\r\n");
    return;
  }

  int sn;
  if ((sn = skill_lookup (arg1)) < 0
    || (!is_npc () && level < skill_table[sn].skill_level[klass])) {
    send_to_char ("You can't do that.\r\n");
    return;
  }

  if (position < skill_table[sn].minimum_position) {
    send_to_char ("You can't concentrate enough.\r\n");
    return;
  }

  int mn = mana_cost (sn);
  /*
   * Locate targets.
   */
  Character *victim = NULL;
  Object *obj = NULL;
  void *vo = NULL;

  switch (skill_table[sn].target) {
  default:
    bug_printf ("Do_cast: bad target for sn %d.", sn);
    return;

  case TAR_IGNORE:
    break;

  case TAR_CHAR_OFFENSIVE:
    if (arg2.empty()) {
      if ((victim = fighting) == NULL) {
        send_to_char ("Cast the spell on whom?\r\n");
        return;
      }
    } else {
      if ((victim = get_char_room (arg2)) == NULL) {
        send_to_char ("They aren't here.\r\n");
        return;
      }
    }
    vo = (void *) victim;
    break;

  case TAR_CHAR_DEFENSIVE:
    if (arg2.empty()) {
      victim = this;
    } else {
      if ((victim = get_char_room (arg2)) == NULL) {
        send_to_char ("They aren't here.\r\n");
        return;
      }
    }

    vo = (void *) victim;
    break;

  case TAR_CHAR_SELF:
    if (!arg2.empty() && !is_name (arg2, name)) {
      send_to_char ("You cannot cast this spell on another.\r\n");
      return;
    }

    vo = (void *) this;
    break;

  case TAR_OBJ_INV:
    if (arg2.empty()) {
      send_to_char ("What should the spell be cast upon?\r\n");
      return;
    }

    if ((obj = get_obj_carry (arg2)) == NULL) {
      send_to_char ("You are not carrying that.\r\n");
      return;
    }

    vo = (void *) obj;
    break;
  }

  if (!is_npc () && mana < mn) {
    send_to_char ("You don't have enough mana.\r\n");
    return;
  }

  if (str_cmp (skill_table[sn].name, "ventriloquate"))
    say_spell (this, sn);

  wait_state (skill_table[sn].beats);

  if (!is_npc () && number_percent () > pcdata->learned[sn]) {
    send_to_char ("You lost your concentration.\r\n");
    mana -= mn / 2;
  } else {
    mana -= mn;
    (this->*(skill_table[sn].spell_fun)) (sn, level, vo);
  }

  if (skill_table[sn].target == TAR_CHAR_OFFENSIVE
    && victim->master != this && victim != this) {
    Character *vch;

    CharIter rch, next;
    for (rch = in_room->people.begin(); rch != in_room->people.end(); rch = next) {
      vch = *rch;
      next = ++rch;
      if (victim == vch && victim->fighting == NULL) {
        multi_hit (victim, this, TYPE_UNDEFINED);
        break;
      }
    }
  }

  return;
}

/*
 * Spell functions.
 */
void Character::spell_acid_blast (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  int dam;

  dam = dice (lvl, 6);
  if (victim->saves_spell (lvl))
    dam /= 2;
  damage (this, victim, dam, sn);
  return;
}

void Character::spell_armor (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->has_affect(sn))
    return;
  af.type = sn;
  af.duration = 24;
  af.modifier = -20;
  af.location = APPLY_AC;
  af.bitvector = 0;
  victim->affect_to_char(&af);
  victim->send_to_char ("You feel someone protecting you.\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_bless (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->position == POS_FIGHTING || victim->has_affect(sn))
    return;
  af.type = sn;
  af.duration = 6 + lvl;
  af.location = APPLY_HITROLL;
  af.modifier = lvl / 8;
  af.bitvector = 0;
  victim->affect_to_char(&af);

  af.location = APPLY_SAVING_SPELL;
  af.modifier = 0 - lvl / 8;
  victim->affect_to_char(&af);
  victim->send_to_char ("You feel righteous.\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_blindness (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->is_affected (AFF_BLIND) || victim->saves_spell (lvl))
    return;

  af.type = sn;
  af.location = APPLY_HITROLL;
  af.modifier = -4;
  af.duration = 1 + lvl;
  af.bitvector = AFF_BLIND;
  victim->affect_to_char(&af);
  victim->send_to_char ("You are blinded!\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_burning_hands (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  static const sh_int dam_each[] = {
    0,
    0, 0, 0, 0, 14, 17, 20, 23, 26, 29,
    29, 29, 30, 30, 31, 31, 32, 32, 33, 33,
    34, 34, 35, 35, 36, 36, 37, 37, 38, 38,
    39, 39, 40, 40, 41, 41, 42, 42, 43, 43,
    44, 44, 45, 45, 46, 46, 47, 47, 48, 48
  };

  lvl = std::min (lvl, (int) (sizeof (dam_each) / sizeof (dam_each[0]) - 1));
  lvl = std::max (0, lvl);
  int dam = number_range (dam_each[lvl] / 2, dam_each[lvl] * 2);
  if (victim->saves_spell (lvl))
    dam /= 2;
  damage (this, victim, dam, sn);
  return;
}

void Character::spell_call_lightning (int sn, int lvl, void *vo)
{
  Character *vch;

  if (!is_outside()) {
    send_to_char ("You must be out of doors.\r\n");
    return;
  }

  if (weather_info.sky < SKY_RAINING) {
    send_to_char ("You need bad weather.\r\n");
    return;
  }

  int dam = dice (lvl / 2, 8);

  send_to_char ("God's lightning strikes your foes!\r\n");
  act ("$n calls God's lightning to strike $s foes!",
    NULL, NULL, TO_ROOM);

  CharIter c, next;
  for (c = char_list.begin(); c != char_list.end(); c = next) {
    vch = *c;
    next = ++c;
    if (vch->in_room == NULL)
      continue;
    if (vch->in_room == in_room) {
      if (vch != this && (is_npc () ? !vch->is_npc () : vch->is_npc ()))
        damage (this, vch, vch->saves_spell (lvl) ? dam / 2 : dam, sn);
      continue;
    }

    if (vch->in_room->area == in_room->area && vch->is_outside()
      && vch->is_awake ())
      vch->send_to_char ("Lightning flashes in the sky.\r\n");
  }

  return;
}

void Character::spell_cause_light (int sn, int lvl, void *vo)
{
  damage (this, (Character *) vo, dice (1, 8) + lvl / 3, sn);
  return;
}

void Character::spell_cause_critical (int sn, int lvl, void *vo)
{
  damage (this, (Character *) vo, dice (3, 8) + lvl - 6, sn);
  return;
}

void Character::spell_cause_serious (int sn, int lvl, void *vo)
{
  damage (this, (Character *) vo, dice (2, 8) + lvl / 2, sn);
  return;
}

void Character::spell_change_sex (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->has_affect(sn))
    return;
  af.type = sn;
  af.duration = 10 * lvl;
  af.location = APPLY_SEX;
  do {
    af.modifier = number_range (0, 2) - victim->sex;
  }
  while (af.modifier == 0);
  af.bitvector = 0;
  victim->affect_to_char(&af);
  victim->send_to_char ("You feel different.\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_charm_person (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim == this) {
    send_to_char ("You like yourself even better!\r\n");
    return;
  }

  if (victim->is_affected (AFF_CHARM)
    || is_affected (AFF_CHARM)
    || lvl < victim->level || victim->saves_spell (lvl))
    return;

  if (victim->master)
    victim->stop_follower();
  victim->add_follower(this);
  af.type = sn;
  af.duration = number_fuzzy (lvl / 4);
  af.location = 0;
  af.modifier = 0;
  af.bitvector = AFF_CHARM;
  victim->affect_to_char(&af);
  act ("Isn't $n just so nice?", NULL, victim, TO_VICT);
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_chill_touch (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  static const sh_int dam_each[] = {
    0,
    0, 0, 6, 7, 8, 9, 12, 13, 13, 13,
    14, 14, 14, 15, 15, 15, 16, 16, 16, 17,
    17, 17, 18, 18, 18, 19, 19, 19, 20, 20,
    20, 21, 21, 21, 22, 22, 22, 23, 23, 23,
    24, 24, 24, 25, 25, 25, 26, 26, 26, 27
  };
  Affect af;

  lvl = std::min (lvl, (int) (sizeof (dam_each) / sizeof (dam_each[0]) - 1));
  lvl = std::max (0, lvl);
  int dam = number_range (dam_each[lvl] / 2, dam_each[lvl] * 2);
  if (!victim->saves_spell (lvl)) {
    af.type = sn;
    af.duration = 6;
    af.location = APPLY_STR;
    af.modifier = -1;
    af.bitvector = 0;
    victim->affect_join (&af);
  } else {
    dam /= 2;
  }

  damage (this, victim, dam, sn);
  return;
}

void Character::spell_colour_spray (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  static const sh_int dam_each[] = {
    0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    30, 35, 40, 45, 50, 55, 55, 55, 56, 57,
    58, 58, 59, 60, 61, 61, 62, 63, 64, 64,
    65, 66, 67, 67, 68, 69, 70, 70, 71, 72,
    73, 73, 74, 75, 76, 76, 77, 78, 79, 79
  };

  lvl = std::min (lvl, (int) (sizeof (dam_each) / sizeof (dam_each[0]) - 1));
  lvl = std::max (0, lvl);
  int dam = number_range (dam_each[lvl] / 2, dam_each[lvl] * 2);
  if (victim->saves_spell (lvl))
    dam /= 2;

  damage (this, victim, dam, sn);
  return;
}

void Character::spell_continual_light (int sn, int lvl, void *vo)
{
  Object *light;

  light = get_obj_index(OBJ_VNUM_LIGHT_BALL)->create_object(0);
  light->obj_to_room (in_room);
  act ("$n twiddles $s thumbs and $p appears.", light, NULL, TO_ROOM);
  act ("You twiddle your thumbs and $p appears.", light, NULL, TO_CHAR);
  return;
}

void Character::spell_control_weather (int sn, int lvl, void *vo)
{
  if (!str_cmp (target_name, "better"))
    weather_info.change += dice (lvl / 3, 4);
  else if (!str_cmp (target_name, "worse"))
    weather_info.change -= dice (lvl / 3, 4);
  else
    send_to_char ("Do you want it to get better or worse?\r\n");

  send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_create_food (int sn, int lvl, void *vo)
{
  Object* mushroom = get_obj_index(OBJ_VNUM_MUSHROOM)->create_object(0);
  mushroom->value[0] = 5 + lvl;
  mushroom->obj_to_room (in_room);
  act ("$p suddenly appears.", mushroom, NULL, TO_ROOM);
  act ("$p suddenly appears.", mushroom, NULL, TO_CHAR);
  return;
}

void Character::spell_create_spring (int sn, int lvl, void *vo)
{
  Object* spring = get_obj_index(OBJ_VNUM_SPRING)->create_object(0);
  spring->timer = lvl;
  spring->obj_to_room (in_room);
  act ("$p flows from the ground.", spring, NULL, TO_ROOM);
  act ("$p flows from the ground.", spring, NULL, TO_CHAR);
  return;
}

void Character::spell_create_water (int sn, int lvl, void *vo)
{
  Object *obj = (Object *) vo;

  if (obj->item_type != ITEM_DRINK_CON) {
    send_to_char ("It is unable to hold water.\r\n");
    return;
  }

  if (obj->value[2] != LIQ_WATER && obj->value[1] != 0) {
    send_to_char ("It contains some other liquid.\r\n");
    return;
  }

  int water = std::min (lvl * (weather_info.sky >= SKY_RAINING ? 4 : 2),
    obj->value[0] - obj->value[1]
    );

  if (water > 0) {
    obj->value[2] = LIQ_WATER;
    obj->value[1] += water;
    if (!is_name ("water", obj->name)) {
      obj->name = obj->name + " water";
    }
    act ("$p is filled.", obj, NULL, TO_CHAR);
  }

  return;
}

void Character::spell_cure_blindness (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  if (!victim->has_affect(gsn_blindness))
    return;
  victim->affect_strip (gsn_blindness);
  victim->send_to_char ("Your vision returns!\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_cure_critical (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;

  int heal = dice (3, 8) + lvl - 6;
  victim->hit = std::min (victim->hit + heal, victim->max_hit);
  victim->update_pos();
  victim->send_to_char ("You feel better!\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_cure_light (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;

  int heal = dice (1, 8) + lvl / 3;
  victim->hit = std::min (victim->hit + heal, victim->max_hit);
  victim->update_pos();
  victim->send_to_char ("You feel better!\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_cure_poison (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  if (victim->has_affect(gsn_poison)) {
    victim->affect_strip (gsn_poison);
    act ("$N looks better.", NULL, victim, TO_NOTVICT);
    victim->send_to_char ("A warm feeling runs through your body.\r\n");
    send_to_char ("Ok.\r\n");
  }
  return;
}

void Character::spell_cure_serious (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;

  int heal = dice (2, 8) + lvl / 2;
  victim->hit = std::min (victim->hit + heal, victim->max_hit);
  victim->update_pos();
  victim->send_to_char ("You feel better!\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_curse (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->is_affected (AFF_CURSE) || victim->saves_spell (lvl))
    return;
  af.type = sn;
  af.duration = 4 * lvl;
  af.location = APPLY_HITROLL;
  af.modifier = -1;
  af.bitvector = AFF_CURSE;
  victim->affect_to_char(&af);

  af.location = APPLY_SAVING_SPELL;
  af.modifier = 1;
  victim->affect_to_char(&af);

  victim->send_to_char ("You feel unclean.\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_detect_evil (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->is_affected (AFF_DETECT_EVIL))
    return;
  af.type = sn;
  af.duration = lvl;
  af.modifier = 0;
  af.location = APPLY_NONE;
  af.bitvector = AFF_DETECT_EVIL;
  victim->affect_to_char(&af);
  victim->send_to_char ("Your eyes tingle.\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_detect_hidden (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->is_affected (AFF_DETECT_HIDDEN))
    return;
  af.type = sn;
  af.duration = lvl;
  af.location = APPLY_NONE;
  af.modifier = 0;
  af.bitvector = AFF_DETECT_HIDDEN;
  victim->affect_to_char(&af);
  victim->send_to_char ("Your awareness improves.\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_detect_invis (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->is_affected (AFF_DETECT_INVIS))
    return;
  af.type = sn;
  af.duration = lvl;
  af.modifier = 0;
  af.location = APPLY_NONE;
  af.bitvector = AFF_DETECT_INVIS;
  victim->affect_to_char(&af);
  victim->send_to_char ("Your eyes tingle.\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_detect_magic (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->is_affected (AFF_DETECT_MAGIC))
    return;
  af.type = sn;
  af.duration = lvl;
  af.modifier = 0;
  af.location = APPLY_NONE;
  af.bitvector = AFF_DETECT_MAGIC;
  victim->affect_to_char(&af);
  victim->send_to_char ("Your eyes tingle.\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_detect_poison (int sn, int lvl, void *vo)
{
  Object *obj = (Object *) vo;

  if (obj->item_type == ITEM_DRINK_CON || obj->item_type == ITEM_FOOD) {
    if (obj->value[3] != 0)
      send_to_char ("You smell poisonous fumes.\r\n");
    else
      send_to_char ("It looks very delicious.\r\n");
  } else {
    send_to_char ("It doesn't look poisoned.\r\n");
  }

  return;
}

void Character::spell_dispel_magic (int sn, int lvl, void *vo)
{
  send_to_char ("Sorry but this spell has been disabled.\r\n");
  return;
}

void Character::spell_dispel_evil (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;

  if (!is_npc () && is_evil ())
    victim = this;

  if (victim->is_good ()) {
    act ("God protects $N.", NULL, victim, TO_ROOM);
    return;
  }

  if (victim->is_neutral ()) {
    act ("$N does not seem to be affected.", NULL, victim, TO_CHAR);
    return;
  }

  int dam = dice (lvl, 4);
  if (victim->saves_spell (lvl))
    dam /= 2;
  damage (this, victim, dam, sn);
  return;
}

void Character::spell_earthquake (int sn, int lvl, void *vo)
{
  send_to_char ("The earth trembles beneath your feet!\r\n");
  act ("$n makes the earth tremble and shiver.", NULL, NULL, TO_ROOM);

  CharIter c, next;
  for (c = char_list.begin(); c != char_list.end(); c = next) {
    Character* vch = *c;
    next = ++c;
    if (vch->in_room == NULL)
      continue;
    if (vch->in_room == in_room) {
      if (vch != this && (is_npc () ? !vch->is_npc () : vch->is_npc ()))
        damage (this, vch, lvl + dice (2, 8), sn);
      continue;
    }

    if (vch->in_room->area == in_room->area)
      vch->send_to_char ("The earth trembles and shivers.\r\n");
  }

  return;
}

void Character::spell_enchant_weapon (int sn, int lvl, void *vo)
{
  Object *obj = (Object *) vo;
  Affect *paf;

  if (obj->item_type != ITEM_WEAPON || obj->is_obj_stat(ITEM_MAGIC)
    || !obj->affected.empty())
    return;

  paf = new Affect();

  paf->type = sn;
  paf->duration = -1;
  paf->location = APPLY_HITROLL;
  paf->modifier = lvl / 5;
  paf->bitvector = 0;
  obj->affected.push_back(paf);

  paf = new Affect();

  paf->type = -1;
  paf->duration = -1;
  paf->location = APPLY_DAMROLL;
  paf->modifier = lvl / 10;
  paf->bitvector = 0;
  obj->affected.push_back(paf);
  obj->level = number_fuzzy (level - 5);

  if (is_good ()) {
    SET_BIT (obj->extra_flags, ITEM_ANTI_EVIL);
    act ("$p glows blue.", obj, NULL, TO_CHAR);
  } else if (is_evil ()) {
    SET_BIT (obj->extra_flags, ITEM_ANTI_GOOD);
    act ("$p glows red.", obj, NULL, TO_CHAR);
  } else {
    SET_BIT (obj->extra_flags, ITEM_ANTI_EVIL);
    SET_BIT (obj->extra_flags, ITEM_ANTI_GOOD);
    act ("$p glows yellow.", obj, NULL, TO_CHAR);
  }

  send_to_char ("Ok.\r\n");
  return;
}

/*
 * Drain XP, MANA, HP.
 * Caster gains HP.
 */
void Character::spell_energy_drain (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  int dam;

  if (victim->saves_spell (lvl))
    return;

  alignment = std::max (-1000, alignment - 200);
  if (victim->level <= 2) {
    dam = hit + 1;
  } else {
    victim->gain_exp(0 - number_range (lvl / 2, 3 * lvl / 2));
    victim->mana /= 2;
    victim->move /= 2;
    dam = dice (1, lvl);
    hit += dam;
  }

  damage (this, victim, dam, sn);

  return;
}

void Character::spell_fireball (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  static const sh_int dam_each[] = {
    0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 30, 35, 40, 45, 50, 55,
    60, 65, 70, 75, 80, 82, 84, 86, 88, 90,
    92, 94, 96, 98, 100, 102, 104, 106, 108, 110,
    112, 114, 116, 118, 120, 122, 124, 126, 128, 130
  };

  lvl = std::min (lvl, (int) (sizeof (dam_each) / sizeof (dam_each[0]) - 1));
  lvl = std::max (0, lvl);
  int dam = number_range (dam_each[lvl] / 2, dam_each[lvl] * 2);
  if (victim->saves_spell (lvl))
    dam /= 2;
  damage (this, victim, dam, sn);
  return;
}

void Character::spell_flamestrike (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;

  int dam = dice (6, lvl);
  if (victim->saves_spell (lvl))
    dam /= 2;
  damage (this, victim, dam, sn);
  return;
}

void Character::spell_faerie_fire (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->is_affected (AFF_FAERIE_FIRE))
    return;
  af.type = sn;
  af.duration = lvl;
  af.location = APPLY_AC;
  af.modifier = 2 * lvl;
  af.bitvector = AFF_FAERIE_FIRE;
  victim->affect_to_char(&af);
  victim->send_to_char ("You are surrounded by a pink outline.\r\n");
  victim->act ("$n is surrounded by a pink outline.", NULL, NULL, TO_ROOM);
  return;
}

void Character::spell_faerie_fog (int sn, int lvl, void *vo)
{
  act ("$n conjures a cloud of purple smoke.", NULL, NULL, TO_ROOM);
  send_to_char ("You conjure a cloud of purple smoke.\r\n");

  CharIter ich;
  for (ich = in_room->people.begin(); ich != in_room->people.end(); ich++) {
    if (!(*ich)->is_npc () && IS_SET ((*ich)->actflags, PLR_WIZINVIS))
      continue;

    if (*ich == this || (*ich)->saves_spell (lvl))
      continue;

    (*ich)->affect_strip (gsn_invis);
    (*ich)->affect_strip (gsn_mass_invis);
    (*ich)->affect_strip (gsn_sneak);
    REMOVE_BIT ((*ich)->affected_by, AFF_HIDE);
    REMOVE_BIT ((*ich)->affected_by, AFF_INVISIBLE);
    REMOVE_BIT ((*ich)->affected_by, AFF_SNEAK);
    (*ich)->act ("$n is revealed!", NULL, NULL, TO_ROOM);
    (*ich)->send_to_char ("You are revealed!\r\n");
  }

  return;
}

void Character::spell_fly (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->is_affected (AFF_FLYING))
    return;
  af.type = sn;
  af.duration = lvl + 3;
  af.location = 0;
  af.modifier = 0;
  af.bitvector = AFF_FLYING;
  victim->affect_to_char(&af);
  victim->send_to_char ("Your feet rise off the ground.\r\n");
  victim->act ("$n's feet rise off the ground.", NULL, NULL, TO_ROOM);
  return;
}

void Character::spell_gate (int sn, int lvl, void *vo)
{
  get_mob_index(MOB_VNUM_VAMPIRE)->create_mobile()->char_to_room(in_room);
  return;
}

/*
 * Spell for mega1.are from Glop/Erkenbrand.
 */
void Character::spell_general_purpose (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;

  int dam = number_range (25, 100);
  if (victim->saves_spell (lvl))
    dam /= 2;
  damage (this, victim, dam, sn);
  return;
}

void Character::spell_giant_strength (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->has_affect(sn))
    return;
  af.type = sn;
  af.duration = lvl;
  af.location = APPLY_STR;
  af.modifier = 1 + (lvl >= 18) + (lvl >= 25);
  af.bitvector = 0;
  victim->affect_to_char(&af);
  victim->send_to_char ("You feel stronger.\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_harm (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  int dam;

  dam = std::max (20, victim->hit - dice (1, 4));
  if (victim->saves_spell (lvl))
    dam = std::min (50, dam / 4);
  dam = std::min (100, dam);
  damage (this, victim, dam, sn);
  return;
}

void Character::spell_heal (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  victim->hit = std::min (victim->hit + 100, victim->max_hit);
  victim->update_pos();
  victim->send_to_char ("A warm feeling fills your body.\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

/*
 * Spell for mega1.are from Glop/Erkenbrand.
 */
void Character::spell_high_explosive (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;

  int dam = number_range (30, 120);
  if (victim->saves_spell (lvl))
    dam /= 2;
  damage (this, victim, dam, sn);
  return;
}

void Character::spell_identify (int sn, int lvl, void *vo)
{
  Object *obj = (Object *) vo;
  char buf[MAX_STRING_LENGTH];

  snprintf (buf, sizeof buf,
    "Object '%s' is type %s, extra flags %s.\r\nWeight is %d, value is %d, lvl is %d.\r\n",
    obj->name.c_str(),
    obj->item_type_name().c_str(),
    extra_bit_name (obj->extra_flags).c_str(), obj->weight, obj->cost, obj->level);
  send_to_char (buf);

  switch (obj->item_type) {
  case ITEM_SCROLL:
  case ITEM_POTION:
    snprintf (buf, sizeof buf, "Level %d spells of:", obj->value[0]);
    send_to_char (buf);

    if (obj->value[1] >= 0 && obj->value[1] < MAX_SKILL) {
      send_to_char (" '");
      send_to_char (skill_table[obj->value[1]].name);
      send_to_char ("'");
    }

    if (obj->value[2] >= 0 && obj->value[2] < MAX_SKILL) {
      send_to_char (" '");
      send_to_char (skill_table[obj->value[2]].name);
      send_to_char ("'");
    }

    if (obj->value[3] >= 0 && obj->value[3] < MAX_SKILL) {
      send_to_char (" '");
      send_to_char (skill_table[obj->value[3]].name);
      send_to_char ("'");
    }

    send_to_char (".\r\n");
    break;

  case ITEM_WAND:
  case ITEM_STAFF:
    snprintf (buf, sizeof buf, "Has %d(%d) charges of level %d",
      obj->value[1], obj->value[2], obj->value[0]);
    send_to_char (buf);

    if (obj->value[3] >= 0 && obj->value[3] < MAX_SKILL) {
      send_to_char (" '");
      send_to_char (skill_table[obj->value[3]].name);
      send_to_char ("'");
    }

    send_to_char (".\r\n");
    break;

  case ITEM_WEAPON:
    snprintf (buf, sizeof buf, "Damage is %d to %d (average %d).\r\n",
      obj->value[1], obj->value[2], (obj->value[1] + obj->value[2]) / 2);
    send_to_char (buf);
    break;

  case ITEM_ARMOR:
    snprintf (buf, sizeof buf, "Armor class is %d.\r\n", obj->value[0]);
    send_to_char (buf);
    break;
  }

  AffIter af;
  for (af = obj->pIndexData->affected.begin(); af != obj->pIndexData->affected.end(); af++) {
    if ((*af)->location != APPLY_NONE && (*af)->modifier != 0) {
      snprintf (buf, sizeof buf, "Affects %s by %d.\r\n",
        affect_loc_name ((*af)->location).c_str(), (*af)->modifier);
      send_to_char (buf);
    }
  }

  for (af = obj->affected.begin(); af != obj->affected.end(); af++) {
    if ((*af)->location != APPLY_NONE && (*af)->modifier != 0) {
      snprintf (buf, sizeof buf, "Affects %s by %d.\r\n",
        affect_loc_name ((*af)->location).c_str(), (*af)->modifier);
      send_to_char (buf);
    }
  }

  return;
}

void Character::spell_infravision (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->is_affected (AFF_INFRARED))
    return;
  act ("$n's eyes glow red.\r\n", NULL, NULL, TO_ROOM);
  af.type = sn;
  af.duration = 2 * lvl;
  af.location = APPLY_NONE;
  af.modifier = 0;
  af.bitvector = AFF_INFRARED;
  victim->affect_to_char(&af);
  victim->send_to_char ("Your eyes glow red.\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_invis (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->is_affected (AFF_INVISIBLE))
    return;

  victim->act ("$n fades out of existence.", NULL, NULL, TO_ROOM);
  af.type = sn;
  af.duration = 24;
  af.location = APPLY_NONE;
  af.modifier = 0;
  af.bitvector = AFF_INVISIBLE;
  victim->affect_to_char(&af);
  victim->send_to_char ("You fade out of existence.\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_know_alignment (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  char *msg;

  int ap = victim->alignment;

  if (ap > 700)
    msg = "$N has an aura as white as the driven snow.";
  else if (ap > 350)
    msg = "$N is of excellent moral character.";
  else if (ap > 100)
    msg = "$N is often kind and thoughtful.";
  else if (ap > -100)
    msg = "$N doesn't have a firm moral commitment.";
  else if (ap > -350)
    msg = "$N lies to $S friends.";
  else if (ap > -700)
    msg = "$N's slash DISEMBOWELS you!";
  else
    msg = "I'd rather just not say anything at all about $N.";

  act (msg, NULL, victim, TO_CHAR);
  return;
}

void Character::spell_lightning_bolt (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  static const sh_int dam_each[] = {
    0,
    0, 0, 0, 0, 0, 0, 0, 0, 25, 28,
    31, 34, 37, 40, 40, 41, 42, 42, 43, 44,
    44, 45, 46, 46, 47, 48, 48, 49, 50, 50,
    51, 52, 52, 53, 54, 54, 55, 56, 56, 57,
    58, 58, 59, 60, 60, 61, 62, 62, 63, 64
  };

  lvl = std::min (lvl, (int) (sizeof (dam_each) / sizeof (dam_each[0]) - 1));
  lvl = std::max (0, lvl);
  int dam = number_range (dam_each[lvl] / 2, dam_each[lvl] * 2);
  if (victim->saves_spell (lvl))
    dam /= 2;
  damage (this, victim, dam, sn);
  return;
}

void Character::spell_locate_object (int sn, int lvl, void *vo)
{
  std::string buf;
  bool found = false;
  ObjIter o;
  for (o = object_list.begin(); o != object_list.end(); o++) {
    Object *in_obj;

    if (!can_see_obj(*o) || !is_name (target_name, (*o)->name))
      continue;

    found = true;

    for (in_obj = *o; in_obj->in_obj != NULL; in_obj = in_obj->in_obj);

    if (in_obj->carried_by != NULL) {
      buf += (*o)->short_descr + " carried by " + in_obj->carried_by->describe_to(this) + "\r\n";
    } else {
      buf += (*o)->short_descr + " in " +
        (in_obj->in_room == NULL ? "somewhere" : in_obj->in_room->name.c_str()) +
        ".\r\n";
    }

    buf[0] = toupper (buf[0]);
    send_to_char (buf);
  }

  if (!found)
    send_to_char ("Nothing like that in hell, earth, or heaven.\r\n");

  return;
}

void Character::spell_magic_missile (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  static const sh_int dam_each[] = {
    0,
    3, 3, 4, 4, 5, 6, 6, 6, 6, 6,
    7, 7, 7, 7, 7, 8, 8, 8, 8, 8,
    9, 9, 9, 9, 9, 10, 10, 10, 10, 10,
    11, 11, 11, 11, 11, 12, 12, 12, 12, 12,
    13, 13, 13, 13, 13, 14, 14, 14, 14, 14
  };

  lvl = std::min (lvl, (int) (sizeof (dam_each) / sizeof (dam_each[0]) - 1));
  lvl = std::max (0, lvl);
  int dam = number_range (dam_each[lvl] / 2, dam_each[lvl] * 2);
  if (victim->saves_spell (lvl))
    dam /= 2;
  damage (this, victim, dam, sn);
  return;
}

void Character::spell_mass_invis (int sn, int lvl, void *vo)
{
  Affect af;

  CharIter gch;
  for (gch = in_room->people.begin(); gch != in_room->people.end(); gch++) {
    if (!is_same_group (*gch, this) || (*gch)->is_affected (AFF_INVISIBLE))
      continue;
    (*gch)->act ("$n slowly fades out of existence.", NULL, NULL, TO_ROOM);
    (*gch)->send_to_char ("You slowly fade out of existence.\r\n");
    af.type = sn;
    af.duration = 24;
    af.location = APPLY_NONE;
    af.modifier = 0;
    af.bitvector = AFF_INVISIBLE;
    (*gch)->affect_to_char(&af);
  }
  send_to_char ("Ok.\r\n");

  return;
}

void Character::spell_null (int sn, int lvl, void *vo)
{
  send_to_char ("That's not a spell!\r\n");
  return;
}

void Character::spell_pass_door (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->is_affected (AFF_PASS_DOOR))
    return;
  af.type = sn;
  af.duration = number_fuzzy (lvl / 4);
  af.location = APPLY_NONE;
  af.modifier = 0;
  af.bitvector = AFF_PASS_DOOR;
  victim->affect_to_char(&af);
  victim->act ("$n turns translucent.", NULL, NULL, TO_ROOM);
  victim->send_to_char ("You turn translucent.\r\n");
  return;
}

void Character::spell_poison (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->saves_spell (lvl))
    return;
  af.type = sn;
  af.duration = lvl;
  af.location = APPLY_STR;
  af.modifier = -2;
  af.bitvector = AFF_POISON;
  victim->affect_join (&af);
  victim->send_to_char ("You feel very sick.\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_protection (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->is_affected (AFF_PROTECT))
    return;
  af.type = sn;
  af.duration = 24;
  af.location = APPLY_NONE;
  af.modifier = 0;
  af.bitvector = AFF_PROTECT;
  victim->affect_to_char(&af);
  victim->send_to_char ("You feel protected.\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_refresh (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  victim->move = std::min (victim->move + lvl, victim->max_move);
  victim->send_to_char ("You feel less tired.\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

void Character::spell_remove_curse (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  if (victim->has_affect(gsn_curse)) {
    victim->affect_strip (gsn_curse);
    victim->send_to_char ("You feel better.\r\n");
    if (this != victim)
      send_to_char ("Ok.\r\n");
  }

  return;
}

void Character::spell_sanctuary (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->is_affected (AFF_SANCTUARY))
    return;
  af.type = sn;
  af.duration = number_fuzzy (lvl / 8);
  af.location = APPLY_NONE;
  af.modifier = 0;
  af.bitvector = AFF_SANCTUARY;
  victim->affect_to_char(&af);
  victim->act ("$n is surrounded by a white aura.", NULL, NULL, TO_ROOM);
  victim->send_to_char ("You are surrounded by a white aura.\r\n");
  return;
}

void Character::spell_shield (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->has_affect(sn))
    return;
  af.type = sn;
  af.duration = 8 + lvl;
  af.location = APPLY_AC;
  af.modifier = -20;
  af.bitvector = 0;
  victim->affect_to_char(&af);
  victim->act ("$n is surrounded by a force shield.", NULL, NULL, TO_ROOM);
  victim->send_to_char ("You are surrounded by a force shield.\r\n");
  return;
}

void Character::spell_shocking_grasp (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  static const int dam_each[] = {
    0,
    0, 0, 0, 0, 0, 0, 20, 25, 29, 33,
    36, 39, 39, 39, 40, 40, 41, 41, 42, 42,
    43, 43, 44, 44, 45, 45, 46, 46, 47, 47,
    48, 48, 49, 49, 50, 50, 51, 51, 52, 52,
    53, 53, 54, 54, 55, 55, 56, 56, 57, 57
  };

  lvl = std::min (lvl, (int) (sizeof (dam_each) / sizeof (dam_each[0]) - 1));
  lvl = std::max (0, lvl);
  int dam = number_range (dam_each[lvl] / 2, dam_each[lvl] * 2);
  if (victim->saves_spell (lvl))
    dam /= 2;
  damage (this, victim, dam, sn);
  return;
}

void Character::spell_sleep (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->is_affected (AFF_SLEEP)
    || lvl < victim->level || victim->saves_spell (lvl))
    return;

  af.type = sn;
  af.duration = 4 + lvl;
  af.location = APPLY_NONE;
  af.modifier = 0;
  af.bitvector = AFF_SLEEP;
  victim->affect_join (&af);

  if (victim->is_awake ()) {
    victim->send_to_char ("You feel very sleepy ..... zzzzzz.\r\n");
    victim->act ("$n goes to sleep.", NULL, NULL, TO_ROOM);
    victim->position = POS_SLEEPING;
  }

  return;
}

void Character::spell_stone_skin (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (has_affect(sn))
    return;
  af.type = sn;
  af.duration = lvl;
  af.location = APPLY_AC;
  af.modifier = -40;
  af.bitvector = 0;
  victim->affect_to_char(&af);
  victim->act ("$n's skin turns to stone.", NULL, NULL, TO_ROOM);
  victim->send_to_char ("Your skin turns to stone.\r\n");
  return;
}

void Character::spell_summon (int sn, int lvl, void *vo)
{
  Character *victim;

  if ((victim = get_char_world (target_name)) == NULL
    || victim == this
    || victim->in_room == NULL
    || IS_SET (victim->in_room->room_flags, ROOM_SAFE)
    || IS_SET (victim->in_room->room_flags, ROOM_PRIVATE)
    || IS_SET (victim->in_room->room_flags, ROOM_SOLITARY)
    || IS_SET (victim->in_room->room_flags, ROOM_NO_RECALL)
    || victim->level >= lvl + 3
    || victim->fighting != NULL
    || victim->in_room->area != in_room->area
    || (victim->is_npc () && victim->saves_spell (lvl))) {
    send_to_char ("You failed.\r\n");
    return;
  }

  victim->act ("$n disappears suddenly.", NULL, NULL, TO_ROOM);
  victim->char_from_room();
  victim->char_to_room(in_room);
  victim->act ("$n arrives suddenly.", NULL, NULL, TO_ROOM);
  act ("$N has summoned you!", NULL, victim, TO_VICT);
  victim->do_look ("auto");
  return;
}

void Character::spell_teleport (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;

  if (victim->in_room == NULL
    || IS_SET (victim->in_room->room_flags, ROOM_NO_RECALL)
    || (!is_npc () && victim->fighting != NULL)
    || (victim != this
      && (victim->saves_spell (lvl) || victim->saves_spell (lvl)))) {
    send_to_char ("You failed.\r\n");
    return;
  }

  Room *pRoomIndex;
  for (;;) {
    pRoomIndex = get_room_index (number_range (0, 65535));
    if (pRoomIndex != NULL)
      if (!IS_SET (pRoomIndex->room_flags, ROOM_PRIVATE)
        && !IS_SET (pRoomIndex->room_flags, ROOM_SOLITARY))
        break;
  }

  victim->act ("$n slowly fades out of existence.", NULL, NULL, TO_ROOM);
  victim->char_from_room();
  victim->char_to_room(pRoomIndex);
  victim->act ("$n slowly fades into existence.", NULL, NULL, TO_ROOM);
  victim->do_look ("auto");
  return;
}

void Character::spell_ventriloquate (int sn, int lvl, void *vo)
{
  std::string speaker;

  target_name = one_argument (target_name, speaker);

  char buf1[MAX_STRING_LENGTH];
  char buf2[MAX_STRING_LENGTH];
  snprintf (buf1, sizeof buf1, "%s says '%s'.\r\n", speaker.c_str(), target_name.c_str());
  snprintf (buf2, sizeof buf2, "Someone makes %s say '%s'.\r\n", speaker.c_str(), target_name.c_str());
  buf1[0] = toupper (buf1[0]);

  CharIter vch;
  for (vch = in_room->people.begin(); vch != in_room->people.end(); vch++) {
    if (!is_name (speaker, (*vch)->name))
      (*vch)->send_to_char ((*vch)->saves_spell (lvl) ? buf2 : buf1);
  }

  return;
}

void Character::spell_weaken (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;
  Affect af;

  if (victim->has_affect(sn) || victim->saves_spell (lvl))
    return;
  af.type = sn;
  af.duration = lvl / 2;
  af.location = APPLY_STR;
  af.modifier = -2;
  af.bitvector = 0;
  victim->affect_to_char(&af);
  victim->send_to_char ("You feel weaker.\r\n");
  if (this != victim)
    send_to_char ("Ok.\r\n");
  return;
}

/*
 * This is for muds that _want_ scrolls of recall.
 * Ick.
 */
void Character::spell_word_of_recall (int sn, int lvl, void *vo)
{
  ((Character *) vo)->do_recall ("");
  return;
}

/*
 * NPC spells.
 */
void Character::spell_acid_breath (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;

  if (number_percent () < 2 * lvl && !victim->saves_spell (lvl)) {
    Object *obj_lose;
    ObjIter o, onext;
    for (o = victim->carrying.begin(); o != victim->carrying.end(); o = onext) {
      obj_lose = *o;
      onext = ++o;
      int iWear;

      if (number_percent() <= 75)
        continue;

      switch (obj_lose->item_type) {
      case ITEM_ARMOR:
        if (obj_lose->value[0] > 0) {
          victim->act ("$p is pitted and etched!", obj_lose, NULL, TO_CHAR);
          if ((iWear = obj_lose->wear_loc) != WEAR_NONE)
            victim->armor -= obj_lose->apply_ac (iWear);
          obj_lose->value[0] -= 1;
          obj_lose->cost = 0;
          if (iWear != WEAR_NONE)
            victim->armor += obj_lose->apply_ac (iWear);
        }
        break;

      case ITEM_CONTAINER:
        victim->act ("$p fumes and dissolves!", obj_lose, NULL, TO_CHAR);
        obj_lose->extract_obj ();
        break;
      }
    }
  }

  int hpch = std::max (10, hit);
  int dam = number_range (hpch / 16 + 1, hpch / 8);
  if (victim->saves_spell (lvl))
    dam /= 2;
  damage (this, victim, dam, sn);
  return;
}

void Character::spell_fire_breath (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;

  if (number_percent () < 2 * lvl && !victim->saves_spell (lvl)) {
    Object *obj_lose;
    ObjIter o, onext;
    for (o = victim->carrying.begin(); o != victim->carrying.end(); o = onext) {
      obj_lose = *o;
      onext = ++o;
      char *msg;

      if (number_percent() <= 75)
        continue;

      switch (obj_lose->item_type) {
      default:
        continue;
      case ITEM_CONTAINER:
        msg = "$p ignites and burns!";
        break;
      case ITEM_POTION:
        msg = "$p bubbles and boils!";
        break;
      case ITEM_SCROLL:
        msg = "$p crackles and burns!";
        break;
      case ITEM_STAFF:
        msg = "$p smokes and chars!";
        break;
      case ITEM_WAND:
        msg = "$p sparks and sputters!";
        break;
      case ITEM_FOOD:
        msg = "$p blackens and crisps!";
        break;
      case ITEM_PILL:
        msg = "$p melts and drips!";
        break;
      }

      victim->act (msg, obj_lose, NULL, TO_CHAR);
      obj_lose->extract_obj ();
    }
  }

  int hpch = std::max (10, hit);
  int dam = number_range (hpch / 16 + 1, hpch / 8);
  if (victim->saves_spell (lvl))
    dam /= 2;
  damage (this, victim, dam, sn);
  return;
}

void Character::spell_frost_breath (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;

  if (number_percent () < 2 * lvl && !victim->saves_spell (lvl)) {
    Object *obj_lose;
    ObjIter o, onext;
    for (o = victim->carrying.begin(); o != victim->carrying.end(); o = onext) {
      obj_lose = *o;
      onext = ++o;
      char *msg;

      if (number_percent() <= 75)
        continue;

      switch (obj_lose->item_type) {
      default:
        continue;
      case ITEM_CONTAINER:
      case ITEM_DRINK_CON:
      case ITEM_POTION:
        msg = "$p freezes and shatters!";
        break;
      }

      victim->act (msg, obj_lose, NULL, TO_CHAR);
      obj_lose->extract_obj ();
    }
  }

  int hpch = std::max (10, hit);
  int dam = number_range (hpch / 16 + 1, hpch / 8);
  if (victim->saves_spell (lvl))
    dam /= 2;
  damage (this, victim, dam, sn);
  return;
}

void Character::spell_gas_breath (int sn, int lvl, void *vo)
{
  Character *vch;

  CharIter rch, next;
  for (rch = in_room->people.begin(); rch != in_room->people.end(); rch = next) {
    vch = *rch;
    next = ++rch;
    if (is_npc () ? !vch->is_npc () : vch->is_npc ()) {
      int hpch = std::max (10, hit);
      int dam = number_range (hpch / 16 + 1, hpch / 8);
      if (vch->saves_spell (lvl))
        dam /= 2;
      damage (this, vch, dam, sn);
    }
  }
  return;
}

void Character::spell_lightning_breath (int sn, int lvl, void *vo)
{
  Character *victim = (Character *) vo;

  int hpch = std::max (10, hit);
  int dam = number_range (hpch / 16 + 1, hpch / 8);
  if (victim->saves_spell (lvl))
    dam /= 2;
  damage (this, victim, dam, sn);
  return;
}

/* Date stamp idea comes from Alander of ROM */
void Character::do_note (std::string argument)
{
  if (is_npc ())
    return;

  std::string arg, buf1;

  argument = one_argument (argument, arg);
  smash_tilde (argument);

  if (arg.empty()) {
    do_note ("read");
    return;
  }

  char buf[MAX_STRING_LENGTH];
  int vnum;
  int anum;
  if (!str_cmp (arg, "list")) {
    vnum = 0;
    for (std::list<Note*>::iterator p = note_list.begin();
      p != note_list.end(); p++) {
      if (is_note_to (this, *p)) {
        snprintf (buf, sizeof buf, "[%3d%s] %s: %s\r\n",
          vnum,
          ((*p)->date_stamp > last_note
            && str_cmp ((*p)->sender, name)) ? "N" : " ",
          (*p)->sender.c_str(), (*p)->subject.c_str());
        buf1.append(buf);
        vnum++;
      }
    }
    send_to_char (buf1);
    return;
  }

  if (!str_cmp (arg, "read")) {
    bool fAll;

    if (!str_cmp (argument, "all")) {
      fAll = true;
      anum = 0;
    } else if (argument.empty() || !str_prefix (argument, "next"))
      /* read next unread note */
    {
      vnum = 0;
      for (std::list<Note*>::iterator p = note_list.begin();
        p != note_list.end(); p++) {
        if (is_note_to (this, *p)
          && str_cmp (name, (*p)->sender)
          && last_note < (*p)->date_stamp) {
          snprintf (buf, sizeof buf, "[%3d] %s: %s\r\n%s\r\nTo: %s\r\n",
            vnum, (*p)->sender.c_str(), (*p)->subject.c_str(),
            (*p)->date.c_str(), (*p)->to_list.c_str());
          buf1.append(buf);
          buf1.append((*p)->text);
          last_note = std::max (last_note, (*p)->date_stamp);
          send_to_char (buf1);
          return;
        } else
          vnum++;
      }
      send_to_char ("You have no unread notes.\r\n");
      return;
    } else if (is_number (argument)) {
      fAll = false;
      anum = atoi (argument.c_str());
    } else {
      send_to_char ("Note read which number?\r\n");
      return;
    }

    vnum = 0;
    for (std::list<Note*>::iterator p = note_list.begin();
      p != note_list.end(); p++) {
      if (is_note_to (this, *p) && (vnum++ == anum || fAll)) {
        snprintf (buf, sizeof buf, "[%3d] %s: %s\r\n%s\r\nTo: %s\r\n",
          vnum - 1,
          (*p)->sender.c_str(), (*p)->subject.c_str(),
          (*p)->date.c_str(), (*p)->to_list.c_str());
        buf1.append(buf);
        buf1.append((*p)->text);
        send_to_char (buf1);
        last_note = std::max (last_note, (*p)->date_stamp);
        return;
      }
    }

    send_to_char ("No such note.\r\n");
    return;
  }

  if (!str_cmp (arg, "+")) {
    note_attach (this);
    strncpy (buf, pnote->text.c_str(), sizeof buf);
    if (strlen (buf) + argument.size() >= MAX_STRING_LENGTH - 200) {
      send_to_char ("Note too long.\r\n");
      return;
    }

    strncat (buf, argument.c_str(), sizeof buf - argument.size());
    strncat (buf, "\r\n", sizeof buf - strlen("\r\n"));
    pnote->text = buf;
    send_to_char ("Ok.\r\n");
    return;
  }

  if (!str_cmp (arg, "subject")) {
    note_attach (this);
    pnote->subject = argument;
    send_to_char ("Ok.\r\n");
    return;
  }

  if (!str_cmp (arg, "to")) {
    note_attach (this);
    pnote->to_list = argument;
    send_to_char ("Ok.\r\n");
    return;
  }

  if (!str_cmp (arg, "clear")) {
    if (pnote != NULL) {
      delete pnote;
      pnote = NULL;
    }

    send_to_char ("Ok.\r\n");
    return;
  }

  if (!str_cmp (arg, "show")) {
    if (pnote == NULL) {
      send_to_char ("You have no note in progress.\r\n");
      return;
    }

    snprintf (buf, sizeof buf, "%s: %s\r\nTo: %s\r\n",
      pnote->sender.c_str(), pnote->subject.c_str(), pnote->to_list.c_str());
    send_to_char (buf);
    send_to_char (pnote->text);
    return;
  }

  if (!str_cmp (arg, "post") || !str_prefix (arg, "send")) {
    char *strtime;

    if (pnote == NULL) {
      send_to_char ("You have no note in progress.\r\n");
      return;
    }

    if (!str_cmp (pnote->to_list, "")) {
      send_to_char
        ("You need to provide a recipient (name, all, or immortal).\r\n");
      return;
    }

    if (!str_cmp (pnote->subject, "")) {
      send_to_char ("You need to provide a subject.\r\n");
      return;
    }

    strtime = ctime (&current_time);
    strtime[strlen (strtime) - 1] = '\0';
    pnote->date = strtime;
    pnote->date_stamp = current_time;

    note_list.push_back(pnote);

    std::ofstream notefile;

    notefile.open (NOTE_FILE, std::ofstream::out | std::ofstream::app | std::ofstream::binary);
    if (!notefile.is_open()) {
      perror (NOTE_FILE);
    } else {
      notefile << "Sender  " << pnote->sender << "~\n";
      notefile << "Date    " << pnote->date << "~\n";
      notefile << "Stamp   " << pnote->date_stamp << "\n";
      notefile << "To      " << pnote->to_list << "~\n";
      notefile << "Subject " << pnote->subject << "~\n";
      notefile << "Text\n" << pnote->text << "~\n\n";
      notefile.close();
    }

    pnote = NULL;
    send_to_char ("Ok.\r\n");
    return;
  }

  if (!str_cmp (arg, "remove")) {
    if (!is_number (argument)) {
      send_to_char ("Note remove which number?\r\n");
      return;
    }

    anum = atoi (argument.c_str());
    vnum = 0;
    std::list<Note*>::iterator next;
    for (std::list<Note*>::iterator p = note_list.begin();
      p != note_list.end(); p = next) {
      Note* curr = *p;
      next = ++p;
      if (is_note_to (this, curr) && vnum++ == anum) {
        note_remove (this, curr);
        send_to_char ("Ok.\r\n");
        return;
      }
    }

    send_to_char ("No such note.\r\n");
    return;
  }

  send_to_char ("Huh?  Type 'help note' for usage.\r\n");
  return;
}

void Character::do_auction (std::string argument)
{
  talk_channel (this, argument, CHANNEL_AUCTION, "auction");
  return;
}

void Character::do_chat (std::string argument)
{
  talk_channel (this, argument, CHANNEL_CHAT, "chat");
  return;
}

/*
 * Alander's new channels.
 */
void Character::do_music (std::string argument)
{
  talk_channel (this, argument, CHANNEL_MUSIC, "music");
  return;
}

void Character::do_question (std::string argument)
{
  talk_channel (this, argument, CHANNEL_QUESTION, "question");
  return;
}

void Character::do_answer (std::string argument)
{
  talk_channel (this, argument, CHANNEL_QUESTION, "answer");
  return;
}

void Character::do_shout (std::string argument)
{
  talk_channel (this, argument, CHANNEL_SHOUT, "shout");
  wait_state (12);
  return;
}

void Character::do_yell (std::string argument)
{
  talk_channel (this, argument, CHANNEL_YELL, "yell");
  return;
}

void Character::do_immtalk (std::string argument)
{
  talk_channel (this, argument, CHANNEL_IMMTALK, "immtalk");
  return;
}

void Character::do_say (std::string argument)
{
  if (argument.empty()) {
    send_to_char ("Say what?\r\n");
    return;
  }

  act ("$n says '$T'.", NULL, argument.c_str(), TO_ROOM);
  act ("You say '$T'.", NULL, argument.c_str(), TO_CHAR);
  mprog_speech_trigger (argument, this);
  return;
}

void Character::do_tell (std::string argument)
{
  if (!is_npc () && IS_SET (actflags, PLR_SILENCE)) {
    send_to_char ("Your message didn't get through.\r\n");
    return;
  }

  std::string arg;
  argument = one_argument (argument, arg);

  if (arg.empty() || argument.empty()) {
    send_to_char ("Tell whom what?\r\n");
    return;
  }

  /*
   * Can tell to PC's anywhere, but NPC's only in same room.
   * -- Furey
   */
  Character *victim;
  if ((victim = get_char_world (arg)) == NULL
    || (victim->is_npc () && victim->in_room != in_room)) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (!is_immortal() && !victim->is_awake ()) {
    act ("$E can't hear you.", 0, victim, TO_CHAR);
    return;
  }

  act ("You tell $N '$t'.", argument.c_str(), victim, TO_CHAR);
  int savepos = victim->position;
  victim->position = POS_STANDING;
  act ("$n tells you '$t'.", argument.c_str(), victim, TO_VICT);
  victim->position = savepos;
  victim->reply = this;

  return;
}

void Character::do_reply (std::string argument)
{
  if (!is_npc () && IS_SET (actflags, PLR_SILENCE)) {
    send_to_char ("Your message didn't get through.\r\n");
    return;
  }

  Character *victim;

  if ((victim = reply) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (!is_immortal() && !victim->is_awake ()) {
    act ("$E can't hear you.", 0, victim, TO_CHAR);
    return;
  }

  act ("You tell $N '$t'.", argument.c_str(), victim, TO_CHAR);
  int savepos = victim->position;
  victim->position = POS_STANDING;
  act ("$n tells you '$t'.", argument.c_str(), victim, TO_VICT);
  victim->position = savepos;
  victim->reply = this;

  return;
}

void Character::do_emote (std::string argument)
{
  if (!is_npc () && IS_SET (actflags, PLR_NO_EMOTE)) {
    send_to_char ("You can't show your emotions.\r\n");
    return;
  }

  if (argument.empty()) {
    send_to_char ("Emote what?\r\n");
    return;
  }

  if (isalpha(argument[argument.size()-1]))
    argument += ".";

  act ("$n $T", NULL, argument.c_str(), TO_ROOM);
  act ("$n $T", NULL, argument.c_str(), TO_CHAR);
  return;
}

void Character::do_bug (std::string argument)
{
  append_file (BUG_FILE, argument);
  send_to_char ("Ok.  Thanks.\r\n");
  return;
}

void Character::do_idea (std::string argument)
{
  append_file (IDEA_FILE, argument);
  send_to_char ("Ok.  Thanks.\r\n");
  return;
}

void Character::do_typo (std::string argument)
{
  append_file (TYPO_FILE, argument);
  send_to_char ("Ok.  Thanks.\r\n");
  return;
}

void Character::do_rent (std::string argument)
{
  send_to_char ("There is no rent here.  Just save and quit.\r\n");
  return;
}

void Character::do_qui (std::string argument)
{
  send_to_char ("If you want to QUIT, you have to spell it out.\r\n");
  return;
}

void Character::do_quit (std::string argument)
{
  if (is_npc ())
    return;

  if (position == POS_FIGHTING) {
    send_to_char ("No way! You are fighting.\r\n");
    return;
  }

  if (position < POS_STUNNED) {
    send_to_char ("You're not DEAD yet.\r\n");
    return;
  }

  send_to_char
    ("Had I but time--as this fell sergeant, Death,\r\nIs strict in his arrest--O, I could tell you--\r\nBut let it be.\r\n");
  act ("$n has left the game.", NULL, NULL, TO_ROOM);
  log_printf ("%s has quit.", name.c_str());

  /*
   * After extract_char the this is no longer valid!
   */
  save_char_obj();
  Descriptor *d = desc;
  extract_char (true);
  if (d != NULL)
    d->close_socket();

  return;
}

void Character::do_save (std::string argument)
{
  if (is_npc ())
    return;

  if (level < 2) {
    send_to_char ("You must be at least second level to save.\r\n");
    return;
  }

  save_char_obj();
  send_to_char ("Ok.\r\n");
  return;
}

void Character::do_follow (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Follow whom?\r\n");
    return;
  }

  Character *victim;
  if ((victim = get_char_room (arg)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (is_affected (AFF_CHARM) && master != NULL) {
    act ("But you'd rather follow $N!", NULL, master, TO_CHAR);
    return;
  }

  if (victim == this) {
    if (master == NULL) {
      send_to_char ("You already follow yourself.\r\n");
      return;
    }
    stop_follower();
    return;
  }

  if ((level - victim->level < -5 || level - victim->level > 5)
    && !is_hero()) {
    send_to_char ("You are not of the right caliber to follow.\r\n");
    return;
  }

  if (master != NULL)
    stop_follower();

  add_follower(victim);
  return;
}

void Character::do_order (std::string argument)
{
  std::string arg;

  argument = one_argument (argument, arg);

  if (arg.empty() || argument.empty()) {
    send_to_char ("Order whom to do what?\r\n");
    return;
  }

  if (is_affected (AFF_CHARM)) {
    send_to_char ("You feel like taking, not giving, orders.\r\n");
    return;
  }

  Character *victim;
  bool fAll;
  if (!str_cmp (arg, "all")) {
    fAll = true;
    victim = NULL;
  } else {
    fAll = false;
    if ((victim = get_char_room (arg)) == NULL) {
      send_to_char ("They aren't here.\r\n");
      return;
    }

    if (victim == this) {
      send_to_char ("Aye aye, right away!\r\n");
      return;
    }

    if (!victim->is_affected (AFF_CHARM) || victim->master != this) {
      send_to_char ("Do it yourself!\r\n");
      return;
    }
  }

  Character *och;
  bool found = false;
  CharIter rch, next;
  for (rch = in_room->people.begin(); rch != in_room->people.end(); rch = next) {
    och = *rch;
    next = ++rch;

    if (och->is_affected (AFF_CHARM)
      && och->master == this && (fAll || och == victim)) {
      found = true;
      act ("$n orders you to '$t'.", argument.c_str(), och, TO_VICT);
      och->interpret (argument);
    }
  }

  if (found)
    send_to_char ("Ok.\r\n");
  else
    send_to_char ("You have no followers here.\r\n");
  return;
}

void Character::do_group (std::string argument)
{
  char buf[MAX_STRING_LENGTH];
  std::string arg;

  one_argument (argument, arg);

  if (arg.empty()) {
    Character *ldr = (leader != NULL) ? leader : this;
    snprintf (buf, sizeof buf, "%s's group:\r\n", ldr->describe_to(this).c_str());
    send_to_char (buf);

    CharIter c;
    for (c = char_list.begin(); c != char_list.end(); c++) {
      if (is_same_group (*c, this)) {
        snprintf (buf, sizeof buf,
          "[%2d %s] %-16s %4d/%4d hp %4d/%4d mana %4d/%4d mv %5d xp\r\n",
          (*c)->level,
          (*c)->is_npc () ? "Mob" : class_table[(*c)->klass].who_name,
          capitalize ((*c)->describe_to(this)).c_str(),
          (*c)->hit, (*c)->max_hit,
          (*c)->mana, (*c)->max_mana, (*c)->move, (*c)->max_move, (*c)->exp);
        send_to_char (buf);
      }
    }
    return;
  }

  Character *victim;
  if ((victim = get_char_room (arg)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (master != NULL || (leader != NULL && leader != this)) {
    send_to_char ("But you are following someone else!\r\n");
    return;
  }

  if (victim->master != this && this != victim) {
    act ("$N isn't following you.", NULL, victim, TO_CHAR);
    return;
  }

  if (is_same_group (victim, this) && this != victim) {
    victim->leader = NULL;
    act ("$n removes $N from $s group.", NULL, victim, TO_NOTVICT);
    act ("$n removes you from $s group.", NULL, victim, TO_VICT);
    act ("You remove $N from your group.", NULL, victim, TO_CHAR);
    return;
  }

  if (level - victim->level < -5 || level - victim->level > 5) {
    act ("$N cannot join $n's group.", NULL, victim, TO_NOTVICT);
    act ("You cannot join $n's group.", NULL, victim, TO_VICT);
    act ("$N cannot join your group.", NULL, victim, TO_CHAR);
    return;
  }

  victim->leader = this;
  act ("$N joins $n's group.", NULL, victim, TO_NOTVICT);
  act ("You join $n's group.", NULL, victim, TO_VICT);
  act ("$N joins your group.", NULL, victim, TO_CHAR);
  return;
}

/*
 * 'Split' originally by Gnort, God of Chaos.
 */
void Character::do_split (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Split how much?\r\n");
    return;
  }

  int amount = atoi (arg.c_str());

  if (amount < 0) {
    send_to_char ("Your group wouldn't like that.\r\n");
    return;
  }

  if (amount == 0) {
    send_to_char ("You hand out zero coins, but no one notices.\r\n");
    return;
  }

  if (gold < amount) {
    send_to_char ("You don't have that much gold.\r\n");
    return;
  }

  int members = 0;
  CharIter gch;
  for (gch = in_room->people.begin(); gch != in_room->people.end(); gch++) {
    if (is_same_group (*gch, this))
      members++;
  }

  if (members < 2) {
    send_to_char ("Just keep it all.\r\n");
    return;
  }

  int share = amount / members;
  int extra = amount % members;

  if (share == 0) {
    send_to_char ("Don't even bother, cheapskate.\r\n");
    return;
  }

  gold -= amount;
  gold += share + extra;

  char buf[MAX_STRING_LENGTH];
  snprintf (buf, sizeof buf,
    "You split %d gold coins.  Your share is %d gold coins.\r\n",
    amount, share + extra);
  send_to_char (buf);

  snprintf (buf, sizeof buf, "$n splits %d gold coins.  Your share is %d gold coins.",
    amount, share);

  for (gch = in_room->people.begin(); gch != in_room->people.end(); gch++) {
    if (*gch != this && is_same_group (*gch, this)) {
      act (buf, NULL, *gch, TO_VICT);
      (*gch)->gold += share;
    }
  }

  return;
}

void Character::do_gtell (std::string argument)
{
  char buf[MAX_STRING_LENGTH];

  if (argument.empty()) {
    send_to_char ("Tell your group what?\r\n");
    return;
  }

  if (IS_SET (actflags, PLR_NO_TELL)) {
    send_to_char ("Your message didn't get through!\r\n");
    return;
  }

  /*
   * Note use of send_to_char, so gtell works on sleepers.
   */
  snprintf (buf, sizeof buf, "%s tells the group '%s'.\r\n", name.c_str(), argument.c_str());
  for (CharIter c = char_list.begin(); c != char_list.end(); c++) {
    if (is_same_group (*c, this))
      (*c)->send_to_char (buf);
  }

  return;
}

void Character::do_look (std::string argument)
{
  if (!is_npc () && desc == NULL)
    return;

  if (position < POS_SLEEPING) {
    send_to_char ("You can't see anything but stars!\r\n");
    return;
  }

  if (position == POS_SLEEPING) {
    send_to_char ("You can't see anything, you're sleeping!\r\n");
    return;
  }

  if (!check_blind())
    return;

  if (!is_npc ()
    && !IS_SET (actflags, PLR_HOLYLIGHT)
    && in_room->is_dark()) {
    send_to_char ("It is pitch black ... \r\n");
    show_char_to_char (in_room->people);
    return;
  }

  std::string arg1, arg2;

  argument = one_argument (argument, arg1);
  argument = one_argument (argument, arg2);

  if (arg1.empty() || !str_cmp (arg1, "auto")) {
    /* 'look' or 'look auto' */
    send_to_char (in_room->name);
    send_to_char ("\r\n");

    if (!is_npc () && IS_SET (actflags, PLR_AUTOEXIT))
      do_exits ("auto");

    if (arg1.empty() || (!is_npc () && !IS_SET (actflags, PLR_BRIEF)))
      send_to_char (in_room->description);

    show_list_to_char (in_room->contents, false, false);
    show_char_to_char (in_room->people);
    return;
  }

  char buf[MAX_STRING_LENGTH];
  Object *obj;
  std::string pdesc;

  if (!str_cmp (arg1, "i") || !str_cmp (arg1, "in")) {
    /* 'look in' */
    if (arg2.empty()) {
      send_to_char ("Look in what?\r\n");
      return;
    }

    if ((obj = get_obj_here (arg2)) == NULL) {
      send_to_char ("You do not see that here.\r\n");
      return;
    }

    switch (obj->item_type) {
    default:
      send_to_char ("That is not a container.\r\n");
      break;

    case ITEM_DRINK_CON:
      if (obj->value[1] <= 0) {
        send_to_char ("It is empty.\r\n");
        break;
      }

      snprintf (buf, sizeof buf, "It's %s full of a %s liquid.\r\n",
        obj->value[1] < obj->value[0] / 4
        ? "less than" :
        obj->value[1] < 3 * obj->value[0] / 4
        ? "about" : "more than", liq_table[obj->value[2]].liq_color);

      send_to_char (buf);
      break;

    case ITEM_CONTAINER:
    case ITEM_CORPSE_NPC:
    case ITEM_CORPSE_PC:
      if (IS_SET (obj->value[1], CONT_CLOSED)) {
        send_to_char ("It is closed.\r\n");
        break;
      }

      act ("$p contains:", obj, NULL, TO_CHAR);
      show_list_to_char (obj->contains, true, true);
      break;
    }
    return;
  }

  Character *victim;
  if ((victim = get_char_room (arg1)) != NULL) {
    show_char_to_char_1 (victim);
    return;
  }

  ObjIter o;
  for (o = carrying.begin(); o != carrying.end(); o++) {
    if (can_see_obj(*o)) {
      pdesc = get_extra_descr (arg1, (*o)->extra_descr);
      if (!pdesc.empty()) {
        send_to_char (pdesc);
        return;
      }

      pdesc = get_extra_descr (arg1, (*o)->pIndexData->extra_descr);
      if (!pdesc.empty()) {
        send_to_char (pdesc);
        return;
      }
    }

    if (is_name (arg1, (*o)->name)) {
      send_to_char ((*o)->description);
      return;
    }
  }

  for (o = in_room->contents.begin(); o != in_room->contents.end(); o++) {
    if (can_see_obj(*o)) {
      pdesc = get_extra_descr (arg1, (*o)->extra_descr);
      if (!pdesc.empty()) {
        send_to_char (pdesc);
        return;
      }

      pdesc = get_extra_descr (arg1, (*o)->pIndexData->extra_descr);
      if (!pdesc.empty()) {
        send_to_char (pdesc);
        return;
      }
    }

    if (is_name (arg1, (*o)->name)) {
      send_to_char ((*o)->description);
      return;
    }
  }

  pdesc = get_extra_descr (arg1, in_room->extra_descr);
  if (!pdesc.empty()) {
    send_to_char (pdesc);
    return;
  }

  int door;
  if (!str_cmp (arg1, "n") || !str_cmp (arg1, "north"))
    door = 0;
  else if (!str_cmp (arg1, "e") || !str_cmp (arg1, "east"))
    door = 1;
  else if (!str_cmp (arg1, "s") || !str_cmp (arg1, "south"))
    door = 2;
  else if (!str_cmp (arg1, "w") || !str_cmp (arg1, "west"))
    door = 3;
  else if (!str_cmp (arg1, "u") || !str_cmp (arg1, "up"))
    door = 4;
  else if (!str_cmp (arg1, "d") || !str_cmp (arg1, "down"))
    door = 5;
  else {
    send_to_char ("You do not see that here.\r\n");
    return;
  }

  /* 'look direction' */
  Exit *pexit;
  if ((pexit = in_room->exit[door]) == NULL) {
    send_to_char ("Nothing special there.\r\n");
    return;
  }

  if (!pexit->description.empty())
    send_to_char (pexit->description);
  else
    send_to_char ("Nothing special there.\r\n");

  if (!pexit->keyword.empty() && pexit->keyword[0] != ' ') {
    if (IS_SET (pexit->exit_info, EX_CLOSED)) {
      act ("The $d is closed.", NULL, pexit->keyword.c_str(), TO_CHAR);
    } else if (IS_SET (pexit->exit_info, EX_ISDOOR)) {
      act ("The $d is open.", NULL, pexit->keyword.c_str(), TO_CHAR);
    }
  }

  return;
}

void Character::do_examine (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Examine what?\r\n");
    return;
  }

  do_look (arg);

  Object *obj;
  if ((obj = get_obj_here (arg)) != NULL) {
    switch (obj->item_type) {
    default:
      break;

    case ITEM_DRINK_CON:
    case ITEM_CONTAINER:
    case ITEM_CORPSE_NPC:
    case ITEM_CORPSE_PC:
      send_to_char ("When you look inside, you see:\r\n");
      std::string buf = "in " + arg;
      do_look (buf);
    }
  }

  return;
}

/*
 * Thanks to Zrin for auto-exit part.
 */
void Character::do_exits (std::string argument)
{
  if (!check_blind())
    return;

  char buf[MAX_STRING_LENGTH];
  buf[0] = '\0';
  bool fAuto = !str_cmp (argument, "auto");
  strncpy (buf, fAuto ? "[Exits:" : "Obvious exits:\r\n", sizeof buf);

  bool found = false;
  for (int door = 0; door <= 5; door++) {
    Exit *pexit;
    if ((pexit = in_room->exit[door]) != NULL
      && pexit->to_room != NULL && !IS_SET (pexit->exit_info, EX_CLOSED)) {
      found = true;
      if (fAuto) {
        strncat (buf, " ", sizeof(buf) - strlen(" "));
        strncat (buf, dir_name[door].c_str(), sizeof(buf) - dir_name[door].size());
      } else {
        snprintf (buf + strlen(buf), sizeof(buf) - strlen(buf), "%-5s - %s\r\n",
          capitalize (dir_name[door]).c_str(), pexit->to_room->is_dark()
          ? "Too dark to tell" : pexit->to_room->name.c_str());
      }
    }
  }

  if (!found)
    strncat (buf, fAuto ? " none" : "None.\r\n", sizeof(buf) - strlen("None.\r\n"));

  if (fAuto)
    strncat (buf, "]\r\n", sizeof(buf) - strlen("]\r\n"));

  send_to_char (buf);
  return;
}

void Character::do_score (std::string argument)
{
  char buf[MAX_STRING_LENGTH];

  snprintf (buf, sizeof buf,
    "You are %s%s, level %d, %d years old (%d hours).\r\n",
    name.c_str(),
    is_npc () ? "" : pcdata->title.c_str(),
    level, get_age(), (get_age() - 17) * 2);
  send_to_char (buf);

  if (get_trust () != level) {
    snprintf (buf, sizeof buf, "You are trusted at level %d.\r\n", get_trust ());
    send_to_char (buf);
  }

  snprintf (buf, sizeof buf,
    "You have %d/%d hit, %d/%d mana, %d/%d movement, %d practices.\r\n",
    hit, max_hit,
    mana, max_mana, move, max_move, practice);
  send_to_char (buf);

  snprintf (buf, sizeof buf,
    "You are carrying %d/%d items with weight %d/%d kg.\r\n",
    carry_number, can_carry_n(), carry_weight, can_carry_w());
  send_to_char (buf);

  snprintf (buf, sizeof buf,
    "Str: %d  Int: %d  Wis: %d  Dex: %d  Con: %d.\r\n",
    get_curr_str(), get_curr_int(), get_curr_wis(),
    get_curr_dex(), get_curr_con());
  send_to_char (buf);

  snprintf (buf, sizeof buf,
    "You have scored %d exp, and have %d gold coins.\r\n", exp, gold);
  send_to_char (buf);

  snprintf (buf, sizeof buf,
    "Autoexit: %s.  Autoloot: %s.  Autosac: %s.\r\n",
    (!is_npc () && IS_SET (actflags, PLR_AUTOEXIT)) ? "yes" : "no",
    (!is_npc () && IS_SET (actflags, PLR_AUTOLOOT)) ? "yes" : "no",
    (!is_npc () && IS_SET (actflags, PLR_AUTOSAC)) ? "yes" : "no");
  send_to_char (buf);

  snprintf (buf, sizeof buf, "Wimpy set to %d hit points.\r\n", wimpy);
  send_to_char (buf);

  if (!is_npc ()) {
    snprintf (buf, sizeof buf, "Page pausing set to %d lines of text.\r\n",
      pcdata->pagelen);
    send_to_char (buf);
  }

  if (!is_npc () && pcdata->condition[COND_DRUNK] > 10)
    send_to_char ("You are drunk.\r\n");
  if (!is_npc () && pcdata->condition[COND_THIRST] == 0)
    send_to_char ("You are thirsty.\r\n");
  if (!is_npc () && pcdata->condition[COND_FULL] == 0)
    send_to_char ("You are hungry.\r\n");

  switch (position) {
  case POS_DEAD:
    send_to_char ("You are DEAD!!\r\n");
    break;
  case POS_MORTAL:
    send_to_char ("You are mortally wounded.\r\n");
    break;
  case POS_INCAP:
    send_to_char ("You are incapacitated.\r\n");
    break;
  case POS_STUNNED:
    send_to_char ("You are stunned.\r\n");
    break;
  case POS_SLEEPING:
    send_to_char ("You are sleeping.\r\n");
    break;
  case POS_RESTING:
    send_to_char ("You are resting.\r\n");
    break;
  case POS_STANDING:
    send_to_char ("You are standing.\r\n");
    break;
  case POS_FIGHTING:
    send_to_char ("You are fighting.\r\n");
    break;
  }

  if (level >= 25) {
    snprintf (buf, sizeof buf, "AC: %d.  ", get_ac());
    send_to_char (buf);
  }

  send_to_char ("You are ");
  if (get_ac() >= 101)
    send_to_char ("WORSE than naked!\r\n");
  else if (get_ac() >= 80)
    send_to_char ("naked.\r\n");
  else if (get_ac() >= 60)
    send_to_char ("wearing clothes.\r\n");
  else if (get_ac() >= 40)
    send_to_char ("slightly armored.\r\n");
  else if (get_ac() >= 20)
    send_to_char ("somewhat armored.\r\n");
  else if (get_ac() >= 0)
    send_to_char ("armored.\r\n");
  else if (get_ac() >= -20)
    send_to_char ("well armored.\r\n");
  else if (get_ac() >= -40)
    send_to_char ("strongly armored.\r\n");
  else if (get_ac() >= -60)
    send_to_char ("heavily armored.\r\n");
  else if (get_ac() >= -80)
    send_to_char ("superbly armored.\r\n");
  else if (get_ac() >= -100)
    send_to_char ("divinely armored.\r\n");
  else
    send_to_char ("invincible!\r\n");

  if (level >= 15) {
    snprintf (buf, sizeof buf, "Hitroll: %d  Damroll: %d.\r\n",
      get_hitroll(), get_damroll());
    send_to_char (buf);
  }

  if (level >= 10) {
    snprintf (buf, sizeof buf, "Alignment: %d.  ", alignment);
    send_to_char (buf);
  }

  send_to_char ("You are ");
  if (alignment > 900)
    send_to_char ("angelic.\r\n");
  else if (alignment > 700)
    send_to_char ("saintly.\r\n");
  else if (alignment > 350)
    send_to_char ("good.\r\n");
  else if (alignment > 100)
    send_to_char ("kind.\r\n");
  else if (alignment > -100)
    send_to_char ("neutral.\r\n");
  else if (alignment > -350)
    send_to_char ("mean.\r\n");
  else if (alignment > -700)
    send_to_char ("evil.\r\n");
  else if (alignment > -900)
    send_to_char ("demonic.\r\n");
  else
    send_to_char ("satanic.\r\n");

  if (!affected.empty()) {
    send_to_char ("You are affected by:\r\n");
    AffIter af;
    for (af = affected.begin(); af != affected.end(); af++) {
      snprintf (buf, sizeof buf, "Spell: '%s'", skill_table[(*af)->type].name);
      send_to_char (buf);

      if (level >= 20) {
        snprintf (buf, sizeof buf,
          " modifies %s by %d for %d hours",
          affect_loc_name ((*af)->location).c_str(), (*af)->modifier, (*af)->duration);
        send_to_char (buf);
      }

      send_to_char (".\r\n");
    }
  }

  return;
}

void Character::do_time (std::string argument)
{
  char *suf;

  int day = time_info.day + 1;

  if (day > 4 && day < 20)
    suf = "th";
  else if (day % 10 == 1)
    suf = "st";
  else if (day % 10 == 2)
    suf = "nd";
  else if (day % 10 == 3)
    suf = "rd";
  else
    suf = "th";

  char buf[MAX_STRING_LENGTH];
  snprintf (buf, sizeof buf,
    "It is %d o'clock %s, Day of %s, %d%s the Month of %s.\r\nMerc started up at %s\rThe system time is %s\r",
    (time_info.hour % 12 == 0) ? 12 : time_info.hour % 12,
    time_info.hour >= 12 ? "pm" : "am",
    day_name[day % 7].c_str(),
    day, suf,
    month_name[time_info.month].c_str(), str_boot_time.c_str(), (char *) ctime (&current_time)
    );

  send_to_char (buf);
  return;
}

void Character::do_weather (std::string argument)
{
  static char *const sky_look[4] = {
    "cloudless",
    "cloudy",
    "rainy",
    "lit by flashes of lightning"
  };

  if (!is_outside()) {
    send_to_char ("You can't see the weather indoors.\r\n");
    return;
  }

  std::string buf;

  buf.append("The sky is ");
  buf.append(sky_look[weather_info.sky]);
  buf.append(" and ");
  buf.append(weather_info.change >= 0 ? "a warm southerly breeze blows" :
    "a cold northern gust blows");
  buf.append(".\r\n");
  send_to_char (buf);
  return;
}

void Character::do_help (std::string argument)
{
  std::list<Help*>::iterator pHelp;

  if (argument.empty())
    argument = "summary";

  for (pHelp = help_list.begin(); pHelp != help_list.end(); pHelp++) {
    if ((*pHelp)->level > get_trust ())
      continue;

    if (is_name (argument, (*pHelp)->keyword)) {
      if ((*pHelp)->level >= 0 && str_cmp (argument, "imotd")) {
        send_to_char ((*pHelp)->keyword);
        send_to_char ("\r\n");
      }

      /*
       * Strip leading '.' to allow initial blanks.
       */
      if ((*pHelp)->text[0] == '.')
        send_to_char ((*pHelp)->text.substr(1).c_str() + 1);
      else
        send_to_char ((*pHelp)->text.c_str());
      return;
    }
  }

  send_to_char ("No help on that word.\r\n");
  return;
}

/*
 * New 'who' command originally by Alander of Rivers of Mud.
 */
void Character::do_who (std::string argument)
{
  int iClass;
  bool rgfClass[CLASS_MAX];

  /*
   * Set default arguments.
   */
  int iLevelLower = 0;
  int iLevelUpper = MAX_LEVEL;
  bool fClassRestrict = false;
  bool fImmortalOnly = false;

  for (iClass = 0; iClass < CLASS_MAX; iClass++)
    rgfClass[iClass] = false;

  /*
   * Parse arguments.
   */
  int nNumber = 0;
  for (;;) {
    std::string arg;

    argument = one_argument (argument, arg);
    if (arg.empty())
      break;

    if (is_number (arg)) {
      switch (++nNumber) {
      case 1:
        iLevelLower = atoi (arg.c_str());
        break;
      case 2:
        iLevelUpper = atoi (arg.c_str());
        break;
      default:
        send_to_char ("Only two level numbers allowed.\r\n");
        return;
      }
    } else {
      if (arg.size() < 3) {
        send_to_char ("Classes must be longer than that.\r\n");
        return;
      }

      /*
       * Look for classes to turn on.
       */
      int iClass;

      arg.erase(3);
      if (!str_cmp (arg, "imm")) {
        fImmortalOnly = true;
      } else {
        fClassRestrict = true;
        for (iClass = 0; iClass < CLASS_MAX; iClass++) {
          if (!str_cmp (arg, class_table[iClass].who_name)) {
            rgfClass[iClass] = true;
            break;
          }
        }

        if (iClass == CLASS_MAX) {
          send_to_char ("That's not a class.\r\n");
          return;
        }
      }
    }
  }

  /*
   * Now show matching chars.
   */
  int nMatch = 0;
  char buf[MAX_STRING_LENGTH];
  buf[0] = '\0';
  for (DescIter d = descriptor_list.begin();
    d != descriptor_list.end(); d++) {
    Character *wch;
    char const *klass;

    /*
     * Check for match against restrictions.
     * Don't use trust as that exposes trusted mortals.
     */
    if ((*d)->connected != CON_PLAYING || !can_see((*d)->character))
      continue;

    wch = ((*d)->original != NULL) ? (*d)->original : (*d)->character;
    if (wch->level < iLevelLower
      || wch->level > iLevelUpper
      || (fImmortalOnly && wch->level < LEVEL_HERO)
      || (fClassRestrict && !rgfClass[wch->klass]))
      continue;

    nMatch++;

    /*
     * Figure out what to print for class.
     */
    klass = class_table[wch->klass].who_name;
    switch (wch->level) {
    default:
      break;
    case MAX_LEVEL - 0:
      klass = "GOD";
      break;
    case MAX_LEVEL - 1:
      klass = "SUP";
      break;
    case MAX_LEVEL - 2:
      klass = "DEI";
      break;
    case MAX_LEVEL - 3:
      klass = "ANG";
      break;
    }

    /*
     * Format it up.
     */
    snprintf (buf + strlen(buf), sizeof(buf) - strlen(buf), "[%2d %s] %s%s%s%s\r\n",
      wch->level,
      klass,
      IS_SET (wch->actflags, PLR_KILLER) ? "(KILLER) " : "",
      IS_SET (wch->actflags, PLR_THIEF) ? "(THIEF) " : "",
      wch->name.c_str(), wch->pcdata->title.c_str());
  }

  char buf2[MAX_STRING_LENGTH];
  snprintf (buf2, sizeof buf2, "You see %d player%s in the game.\r\n",
    nMatch, nMatch == 1 ? "" : "s");
  strncat (buf, buf2, sizeof(buf) - sizeof(buf2));
  send_to_char (buf);
  return;
}

void Character::do_inventory (std::string argument)
{
  send_to_char ("You are carrying:\r\n");
  show_list_to_char (carrying, true, true);
  return;
}

void Character::do_equipment (std::string argument)
{

  send_to_char ("You are using:\r\n");
  bool found = false;
  for (int iWear = 0; iWear < MAX_WEAR; iWear++) {
    Object *obj;
    if ((obj = get_eq_char (iWear)) == NULL)
      continue;

    send_to_char (where_name[iWear]);
    if (can_see_obj(obj)) {
      send_to_char (obj->format_obj_to_char (this, true));
      send_to_char ("\r\n");
    } else {
      send_to_char ("something.\r\n");
    }
    found = true;
  }

  if (!found)
    send_to_char ("Nothing.\r\n");

  return;
}

void Character::do_compare (std::string argument)
{
  std::string arg1, arg2;

  argument = one_argument (argument, arg1);
  argument = one_argument (argument, arg2);
  if (arg1.empty()) {
    send_to_char ("Compare what to what?\r\n");
    return;
  }

  Object *obj1;
  if ((obj1 = get_obj_carry (arg1)) == NULL) {
    send_to_char ("You do not have that item.\r\n");
    return;
  }

  Object *obj2 = NULL;
  if (arg2.empty()) {
    ObjIter o;
    for (o = carrying.begin(); o != carrying.end(); o++) {
      obj2 = *o;
      if (obj2->wear_loc != WEAR_NONE && can_see_obj(obj2)
        && obj1->item_type == obj2->item_type
        && (obj1->wear_flags & obj2->wear_flags & ~ITEM_TAKE) != 0)
        break;
    }

    if (obj2 == NULL) {
      send_to_char ("You aren't wearing anything comparable.\r\n");
      return;
    }
  } else {
    if ((obj2 = get_obj_carry (arg2)) == NULL) {
      send_to_char ("You do not have that item.\r\n");
      return;
    }
  }

  char* msg = NULL;
  int value1 = 0;
  int value2 = 0;

  if (obj1 == obj2) {
    msg = "You compare $p to itself.  It looks about the same.";
  } else if (obj1->item_type != obj2->item_type) {
    msg = "You can't compare $p and $P.";
  } else {
    switch (obj1->item_type) {
    default:
      msg = "You can't compare $p and $P.";
      break;

    case ITEM_ARMOR:
      value1 = obj1->value[0];
      value2 = obj2->value[0];
      break;

    case ITEM_WEAPON:
      value1 = obj1->value[1] + obj1->value[2];
      value2 = obj2->value[1] + obj2->value[2];
      break;
    }
  }

  if (msg == NULL) {
    if (value1 == value2)
      msg = "$p and $P look about the same.";
    else if (value1 > value2)
      msg = "$p looks better than $P.";
    else
      msg = "$p looks worse than $P.";
  }

  act (msg, obj1, obj2, TO_CHAR);
  return;
}

void Character::do_credits (std::string argument)
{
  do_help ("diku");
  return;
}

void Character::do_where (std::string argument)
{
  std::string arg;
  char buf[MAX_STRING_LENGTH];
  Character *victim;
  bool found = false;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Players near you:\r\n");
    for (DescIter d = descriptor_list.begin();
      d != descriptor_list.end(); d++) {
      if ((*d)->connected == CON_PLAYING
        && (victim = (*d)->character) != NULL && !victim->is_npc ()
        && victim->in_room != NULL
        && victim->in_room->area == in_room->area
        && can_see(victim)) {
        found = true;
        snprintf (buf, sizeof buf, "%-28s %s\r\n", victim->name.c_str(), victim->in_room->name.c_str());
        send_to_char (buf);
      }
    }
    if (!found)
      send_to_char ("None\r\n");
  } else {
    for (CharIter c = char_list.begin(); c != char_list.end(); c++) {
      victim = *c;
      if (victim->in_room != NULL
        && victim->in_room->area == in_room->area
        && !victim->is_affected (AFF_HIDE)
        && !victim->is_affected (AFF_SNEAK)
        && can_see(victim)
        && is_name (arg, victim->name)) {
        found = true;
        snprintf (buf, sizeof buf, "%-28s %s\r\n",
          victim->describe_to(this).c_str(), victim->in_room->name.c_str());
        send_to_char (buf);
        break;
      }
    }
    if (!found)
      act ("You didn't find any $T.", NULL, arg.c_str(), TO_CHAR);
  }

  return;
}

void Character::do_consider (std::string argument)
{
  std::string arg, msg, buf;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Consider killing whom?\r\n");
    return;
  }

  Character *victim;
  if ((victim = get_char_room (arg)) == NULL) {
    send_to_char ("They're not here.\r\n");
    return;
  }

  if (!victim->is_npc ()) {
    send_to_char ("The gods do not accept this type of sacrafice.\r\n");
    return;
  }

  int diff = victim->level - level;

  if (diff <= -10)
    msg = "You can kill $N naked and weaponless.";
  else if (diff <= -5)
    msg = "$N is no match for you.";
  else if (diff <= -2)
    msg = "$N looks like an easy kill.";
  else if (diff <= 1)
    msg = "The perfect match!";
  else if (diff <= 4)
    msg = "$N says 'Do you feel lucky, punk?'.";
  else if (diff <= 9)
    msg = "$N laughs at you mercilessly.";
  else
    msg = "Death will thank you for your gift.";

  act (msg, NULL, victim, TO_CHAR);

  /* additions by king@tinuviel.cs.wcu.edu */
  int hpdiff = (hit - victim->hit);

  if (((diff >= 0) && (hpdiff <= 0))
    || ((diff <= 0) && (hpdiff >= 0))) {
    send_to_char ("Also,");
  } else {
    send_to_char ("However,");
  }

  if (hpdiff >= 101)
    buf = " you are currently much healthier than $E.";
  if (hpdiff <= 100)
    buf = " you are currently healthier than $E.";
  if (hpdiff <= 50)
    buf = " you are currently slightly healthier than $E.";
  if (hpdiff <= 25)
    buf = " you are a teensy bit healthier than $E.";
  if (hpdiff <= 0)
    buf = " $E is a teensy bit healthier than you.";
  if (hpdiff <= -25)
    buf = " $E is slightly healthier than you.";
  if (hpdiff <= -50)
    buf = " $E is healthier than you.";
  if (hpdiff <= -100)
    buf = " $E is much healthier than you.";

  act (buf, NULL, victim, TO_CHAR);
  return;
}

void Character::do_title (std::string argument)
{
  if (is_npc ())
    return;

  if (argument.empty()) {
    send_to_char ("Change your title to what?\r\n");
    return;
  }

  if (argument.size() > 50)
    argument.erase(50);

  smash_tilde (argument);
  set_title(argument);
  send_to_char ("Ok.\r\n");
}

void Character::do_description (std::string argument)
{
  if (!argument.empty()) {
    std::string buf;
    smash_tilde (argument);
    if (argument[0] == '+') {
      if (!description.empty())
        buf = description;
      argument.erase(0,1);
      argument.erase(0, argument.find_first_not_of(" "));
    }

    if (buf.size() + argument.size() >= MAX_STRING_LENGTH - 2) {
      send_to_char ("Description too long.\r\n");
      return;
    }

    buf.append(argument);
    buf.append("\r\n");
    description = buf;
  }

  send_to_char ("Your description is:\r\n");
  send_to_char (!description.empty() ? description.c_str() : "(None).\r\n");
  return;
}

void Character::do_report (std::string argument)
{
  char buf[MAX_INPUT_LENGTH];

  snprintf (buf, sizeof buf,
    "You report: %d/%d hp %d/%d mana %d/%d mv %d xp.\r\n",
    hit, max_hit,
    mana, max_mana, move, max_move, exp);

  send_to_char (buf);

  snprintf (buf, sizeof buf, "$n reports: %d/%d hp %d/%d mana %d/%d mv %d xp.",
    hit, max_hit,
    mana, max_mana, move, max_move, exp);

  act (buf, NULL, NULL, TO_ROOM);

  return;
}

void Character::do_practice (std::string argument)
{
  if (is_npc ())
    return;

  if (level < 3) {
    send_to_char
      ("You must be third level to practice.  Go train instead!\r\n");
    return;
  }

  char buf[MAX_STRING_LENGTH];
  std::string buf1;
  int sn;

  if (argument.empty()) {
    int col;

    col = 0;
    for (sn = 0; sn < MAX_SKILL; sn++) {
      if (skill_table[sn].name == NULL)
        break;
      if (level < skill_table[sn].skill_level[klass])
        continue;

      snprintf (buf, sizeof buf, "%18s %3d%%  ",
        skill_table[sn].name, pcdata->learned[sn]);
      buf1.append(buf);
      if (++col % 3 == 0)
        buf1.append("\r\n");
    }

    if (col % 3 != 0)
      buf1.append("\r\n");

    snprintf (buf, sizeof buf, "You have %d practice sessions left.\r\n", practice);
    buf1.append(buf);
    send_to_char (buf1);
  } else {
    int adept;

    if (!is_awake ()) {
      send_to_char ("In your dreams, or what?\r\n");
      return;
    }

    CharIter mob;
    for (mob = in_room->people.begin(); mob != in_room->people.end(); mob++) {
      if ((*mob)->is_npc () && IS_SET ((*mob)->actflags, ACT_PRACTICE))
        break;
    }

    if (mob == in_room->people.end()) {
      send_to_char ("You can't do that here.\r\n");
      return;
    }

    if (practice <= 0) {
      send_to_char ("You have no practice sessions left.\r\n");
      return;
    }

    if ((sn = skill_lookup (argument)) < 0 || (!is_npc ()
        && level < skill_table[sn].skill_level[klass])) {
      send_to_char ("You can't practice that.\r\n");
      return;
    }

    adept = is_npc () ? 100 : class_table[klass].skill_adept;

    if (pcdata->learned[sn] >= adept) {
      snprintf (buf, sizeof buf, "You are already an adept of %s.\r\n",
        skill_table[sn].name);
      send_to_char (buf);
    } else {
      practice--;
      pcdata->learned[sn] += int_app[get_curr_int()].learn;
      if (pcdata->learned[sn] < adept) {
        act ("You practice $T.", NULL, skill_table[sn].name, TO_CHAR);
        act ("$n practices $T.", NULL, skill_table[sn].name, TO_ROOM);
      } else {
        pcdata->learned[sn] = adept;
        act ("You are now an adept of $T.",
          NULL, skill_table[sn].name, TO_CHAR);
        act ("$n is now an adept of $T.",
          NULL, skill_table[sn].name, TO_ROOM);
      }
    }
  }
  return;
}

/*
 * 'Wimpy' originally by Dionysos.
 */
void Character::do_wimpy (std::string argument)
{
  std::string arg;
  int wpy;

  one_argument (argument, arg);

  if (arg.empty())
    wpy = max_hit / 5;
  else
    wpy = atoi (arg.c_str());

  if (wpy < 0) {
    send_to_char ("Your courage exceeds your wisdom.\r\n");
    return;
  }

  if (wpy > max_hit) {
    send_to_char ("Such cowardice ill becomes you.\r\n");
    return;
  }

  wimpy = wpy;
  char buf[MAX_STRING_LENGTH];
  snprintf (buf, sizeof buf, "Wimpy set to %d hit points.\r\n", wimpy);
  send_to_char (buf);
  return;
}

void Character::do_password (std::string argument)
{
  if (is_npc ())
    return;

  std::string arg1;
  std::string arg2;
  char *pwdnew;
  char *p;
  char cEnd;

  /*
   * Can't use one_argument here because it smashes case.
   * So we just steal all its code.  Bleagh.
   */
  std::string::iterator argp = argument.begin();

  arg1.erase();
  while (argp != argument.end() && isspace (*argp))
    argp++;

  cEnd = ' ';
  if (*argp == '\'' || *argp == '"')
    cEnd = *argp++;

  while (argp != argument.end()) {
    if (*argp == cEnd) {
      argp++;
      break;
    }
    arg1.append(1, *argp);
    argp++;
  }

  argp = argument.begin();

  arg2.erase();
  while (argp != argument.end() && isspace (*argp))
    argp++;

  cEnd = ' ';
  if (*argp == '\'' || *argp == '"')
    cEnd = *argp++;

  while (argp != argument.end()) {
    if (*argp == cEnd) {
      argp++;
      break;
    }
    arg2.append(1, *argp);
    argp++;
  }

  if (arg1.empty() || arg2.empty()) {
    send_to_char ("Syntax: password <old> <new>.\r\n");
    return;
  }

  char buf[MAX_STRING_LENGTH];  // Needed for Windows crypt
  strncpy(buf,arg1.c_str(), sizeof buf);
  if (strcmp (crypt (buf, pcdata->pwd.c_str()), pcdata->pwd.c_str())) {
    wait_state (40);
    send_to_char ("Wrong password.  Wait 10 seconds.\r\n");
    return;
  }

  if (arg2.size() < 5) {
    send_to_char ("New password must be at least five characters long.\r\n");
    return;
  }

  /*
   * No tilde allowed because of player file format.
   */
  strncpy(buf,arg2.c_str(), sizeof buf);
  pwdnew = crypt (buf, name.c_str());
  for (p = pwdnew; *p != '\0'; p++) {
    if (*p == '~') {
      send_to_char ("New password not acceptable, try again.\r\n");
      return;
    }
  }

  pcdata->pwd = pwdnew;
  save_char_obj();
  send_to_char ("Ok.\r\n");
  return;
}

void Character::do_socials (std::string argument)
{
  char buf[MAX_STRING_LENGTH];
  int col = 0;
  sqlite3_stmt *stmt = NULL;

  if (sqlite3_prepare(database,
      "SELECT name FROM socials ORDER BY name ASC",
      -1, &stmt, 0) != SQLITE_OK) {
    bug_printf("Could not prepare statement: %s", sqlite3_errmsg(database));
    return;
  }

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    snprintf (buf, sizeof buf, "%-12s", sqlite3_column_text( stmt, 0 ));
    send_to_char (buf);
    if (++col % 6 == 0)
      send_to_char ("\r\n");
  }

  if (col % 6 != 0)
    send_to_char ("\r\n");
  sqlite3_finalize(stmt);
  return;
}

/*
 * Contributed by Alander.
 */
void Character::do_commands (std::string argument)
{
  char buf[MAX_STRING_LENGTH];
  std::string buf1;
  int cmd;
  int col;

  col = 0;
  for (cmd = 0; cmd_table[cmd].name[0] != '\0'; cmd++) {
    if (cmd_table[cmd].level < LEVEL_HERO
      && cmd_table[cmd].level <= get_trust ()) {
      snprintf (buf, sizeof buf, "%-12s", cmd_table[cmd].name);
      buf1.append(buf);
      if (++col % 6 == 0)
        buf1.append("\r\n");
    }
  }

  if (col % 6 != 0)
    buf1.append("\r\n");

  send_to_char (buf1);
  return;
}

void Character::do_channels (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);

  if (arg.empty()) {
    if (!is_npc () && IS_SET (actflags, PLR_SILENCE)) {
      send_to_char ("You are silenced.\r\n");
      return;
    }

    send_to_char ("Channels:");

    send_to_char (!IS_SET (deaf, CHANNEL_AUCTION)
      ? " +AUCTION" : " -auction");

    send_to_char (!IS_SET (deaf, CHANNEL_CHAT)
      ? " +CHAT" : " -chat");

    if (is_hero()) {
      send_to_char (!IS_SET (deaf, CHANNEL_IMMTALK)
        ? " +IMMTALK" : " -immtalk");
    }

    send_to_char (!IS_SET (deaf, CHANNEL_MUSIC)
      ? " +MUSIC" : " -music");

    send_to_char (!IS_SET (deaf, CHANNEL_QUESTION)
      ? " +QUESTION" : " -question");

    send_to_char (!IS_SET (deaf, CHANNEL_SHOUT)
      ? " +SHOUT" : " -shout");

    send_to_char (!IS_SET (deaf, CHANNEL_YELL)
      ? " +YELL" : " -yell");

    send_to_char (".\r\n");
  } else {
    bool fClear;
    int bit;

    if (arg[0] == '+')
      fClear = true;
    else if (arg[0] == '-')
      fClear = false;
    else {
      send_to_char ("Channels -channel or +channel?\r\n");
      return;
    }

    if (!str_cmp (arg.substr(1), "auction"))
      bit = CHANNEL_AUCTION;
    else if (!str_cmp (arg.substr(1), "chat"))
      bit = CHANNEL_CHAT;
    else if (!str_cmp (arg.substr(1), "immtalk"))
      bit = CHANNEL_IMMTALK;
    else if (!str_cmp (arg.substr(1), "music"))
      bit = CHANNEL_MUSIC;
    else if (!str_cmp (arg.substr(1), "question"))
      bit = CHANNEL_QUESTION;
    else if (!str_cmp (arg.substr(1), "shout"))
      bit = CHANNEL_SHOUT;
    else if (!str_cmp (arg.substr(1), "yell"))
      bit = CHANNEL_YELL;
    else {
      send_to_char ("Set or clear which channel?\r\n");
      return;
    }

    if (fClear)
      REMOVE_BIT (deaf, bit);
    else
      SET_BIT (deaf, bit);

    send_to_char ("Ok.\r\n");
  }

  return;
}

/*
 * Contributed by Grodyn.
 */
void Character::do_config (std::string argument)
{
  if (is_npc ())
    return;

  std::string arg;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("[ Keyword  ] Option\r\n");

    send_to_char (IS_SET (actflags, PLR_AUTOEXIT)
      ? "[+AUTOEXIT ] You automatically see exits.\r\n"
      : "[-autoexit ] You don't automatically see exits.\r\n");

    send_to_char (IS_SET (actflags, PLR_AUTOLOOT)
      ? "[+AUTOLOOT ] You automatically loot corpses.\r\n"
      : "[-autoloot ] You don't automatically loot corpses.\r\n");

    send_to_char (IS_SET (actflags, PLR_AUTOSAC)
      ? "[+AUTOSAC  ] You automatically sacrifice corpses.\r\n"
      : "[-autosac  ] You don't automatically sacrifice corpses.\r\n");

    send_to_char (IS_SET (actflags, PLR_BLANK)
      ? "[+BLANK    ] You have a blank line before your prompt.\r\n"
      : "[-blank    ] You have no blank line before your prompt.\r\n");

    send_to_char (IS_SET (actflags, PLR_BRIEF)
      ? "[+BRIEF    ] You see brief descriptions.\r\n"
      : "[-brief    ] You see long descriptions.\r\n");

    send_to_char (IS_SET (actflags, PLR_COMBINE)
      ? "[+COMBINE  ] You see object lists in combined format.\r\n"
      : "[-combine  ] You see object lists in single format.\r\n");

    send_to_char (IS_SET (actflags, PLR_PROMPT)
      ? "[+PROMPT   ] You have a prompt.\r\n"
      : "[-prompt   ] You don't have a prompt.\r\n");

    send_to_char (IS_SET (actflags, PLR_TELNET_GA)
      ? "[+TELNETGA ] You receive a telnet GA sequence.\r\n"
      : "[-telnetga ] You don't receive a telnet GA sequence.\r\n");

    send_to_char (IS_SET (actflags, PLR_SILENCE)
      ? "[+SILENCE  ] You are silenced.\r\n" : "");

    send_to_char (!IS_SET (actflags, PLR_NO_EMOTE)
      ? "" : "[-emote    ] You can't emote.\r\n");

    send_to_char (!IS_SET (actflags, PLR_NO_TELL)
      ? "" : "[-tell     ] You can't use 'tell'.\r\n");
  } else {
    bool fSet;
    int bit;

    if (arg[0] == '+')
      fSet = true;
    else if (arg[0] == '-')
      fSet = false;
    else {
      send_to_char ("Config -option or +option?\r\n");
      return;
    }

    if (!str_cmp (arg.substr(1), "autoexit"))
      bit = PLR_AUTOEXIT;
    else if (!str_cmp (arg.substr(1), "autoloot"))
      bit = PLR_AUTOLOOT;
    else if (!str_cmp (arg.substr(1), "autosac"))
      bit = PLR_AUTOSAC;
    else if (!str_cmp (arg.substr(1), "blank"))
      bit = PLR_BLANK;
    else if (!str_cmp (arg.substr(1), "brief"))
      bit = PLR_BRIEF;
    else if (!str_cmp (arg.substr(1), "combine"))
      bit = PLR_COMBINE;
    else if (!str_cmp (arg.substr(1), "prompt"))
      bit = PLR_PROMPT;
    else if (!str_cmp (arg.substr(1), "telnetga"))
      bit = PLR_TELNET_GA;
    else {
      send_to_char ("Config which option?\r\n");
      return;
    }

    if (fSet)
      SET_BIT (actflags, bit);
    else
      REMOVE_BIT (actflags, bit);

    send_to_char ("Ok.\r\n");
  }

  return;
}

void Character::do_wizlist (std::string argument)
{
  do_help ("wizlist");
  return;
}

void Character::do_spells (std::string argument)
{
  char buf[MAX_STRING_LENGTH];
  std::string buf1;

  if ((!is_npc () && !class_table[klass].fMana)
    || is_npc ()) {
    send_to_char ("You do not know how to cast spells!\r\n");
    return;
  }

  int col = 0;
  for (int sn = 0; sn < MAX_SKILL; sn++) {
    if (skill_table[sn].name == NULL)
      break;
    if ((level < skill_table[sn].skill_level[klass])
      || (skill_table[sn].skill_level[klass] > LEVEL_HERO))
      continue;

    snprintf (buf, sizeof buf, "%18s %3dpts ", skill_table[sn].name, mana_cost (sn));
    buf1.append(buf);
    if (++col % 3 == 0)
      buf1.append("\r\n");
  }

  if (col % 3 != 0)
    buf1.append("\r\n");

  send_to_char (buf1);
  return;

}

void Character::do_slist (std::string argument)
{
  if ((!is_npc () && !class_table[klass].fMana) || is_npc ()) {
    send_to_char ("You do not need any stinking spells!\r\n");
    return;
  }

  std::string buf1;
  buf1.append("ALL Spells available for your class.\r\n\r\n");
  buf1.append("Lv          Spells\r\n\r\n");

  for (int lvl = 1; lvl < LEVEL_IMMORTAL; lvl++) {
    int col = 0;
    bool pSpell = true;
    char buf[MAX_STRING_LENGTH];

    for (int sn = 0; sn < MAX_SKILL; sn++) {
      if (skill_table[sn].name == NULL)
        break;
      if (skill_table[sn].skill_level[klass] != lvl)
        continue;

      if (pSpell) {
        snprintf (buf, sizeof buf, "%2d:", level);
        buf1.append(buf);
        pSpell = false;
      }

      if (++col % 5 == 0)
        buf1.append("   ");

      snprintf (buf, sizeof buf, "%18s", skill_table[sn].name);
      buf1.append(buf);

      if (col % 4 == 0)
        buf1.append("\r\n");

    }

    if (col % 4 != 0)
      buf1.append("\r\n");
  }
  send_to_char (buf1);
  return;
}

/* by passing the conf command - Kahn */
void Character::do_autoexit (std::string argument)
{
  (IS_SET (actflags, PLR_AUTOEXIT)
    ? do_config ("-autoexit")
    : do_config ("+autoexit"));
}

void Character::do_autoloot (std::string argument)
{
  (IS_SET (actflags, PLR_AUTOLOOT)
    ? do_config ("-autoloot")
    : do_config ("+autoloot"));
}

void Character::do_autosac (std::string argument)
{
  (IS_SET (actflags, PLR_AUTOSAC)
    ? do_config ("-autosac")
    : do_config ("+autosac"));
}

void Character::do_blank (std::string argument)
{
  (IS_SET (actflags, PLR_BLANK)
    ? do_config ("-blank")
    : do_config ("+blank"));
}

void Character::do_brief (std::string argument)
{
  (IS_SET (actflags, PLR_BRIEF)
    ? do_config ("-brief")
    : do_config ("+brief"));
}

void Character::do_combine (std::string argument)
{
  (IS_SET (actflags, PLR_COMBINE)
    ? do_config ("-combine")
    : do_config ("+combine"));
}

void Character::do_pagelen (std::string argument)
{
  char buf[MAX_STRING_LENGTH];
  std::string arg;
  int lines;

  one_argument (argument, arg);

  if (arg.empty())
    lines = 20;
  else
    lines = atoi (arg.c_str());

  if (lines < 1) {
    send_to_char
      ("Negative or Zero values for a page pause is not legal.\r\n");
    return;
  }

  pcdata->pagelen = lines;
  snprintf (buf, sizeof buf, "Page pause set to %d lines.\r\n", lines);
  send_to_char (buf);
  return;
}

/* Do_prompt from Morgenes from Aldara Mud */
void Character::do_prompt (std::string argument)
{
  if (argument.empty()) {
    (IS_SET (actflags, PLR_PROMPT)
      ? do_config ("-prompt")
      : do_config ("+prompt"));
    return;
  }

  std::string buf;

  if (!strcmp (argument.c_str(), "all"))
    buf = "<%hhp %mm %vmv> ";
  else {
    smash_tilde (argument);
    if (argument.size() > 50)
      argument.erase(50);
    buf = argument;
  }

  prompt = buf;
  send_to_char ("Ok.\r\n");
  return;
}

void Character::do_auto (std::string argument)
{
  do_config ("");
  return;
}

void Character::do_north (std::string argument)
{
  move_char (DIR_NORTH);
  return;
}

void Character::do_east (std::string argument)
{
  move_char (DIR_EAST);
  return;
}

void Character::do_south (std::string argument)
{
  move_char (DIR_SOUTH);
  return;
}

void Character::do_west (std::string argument)
{
  move_char (DIR_WEST);
  return;
}

void Character::do_up (std::string argument)
{
  move_char (DIR_UP);
  return;
}

void Character::do_down (std::string argument)
{
  move_char (DIR_DOWN);
  return;
}

void Character::do_open (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Open what?\r\n");
    return;
  }

  Object *obj;
  if ((obj = get_obj_here (arg)) != NULL) {
    /* 'open object' */
    if (obj->item_type != ITEM_CONTAINER) {
      send_to_char ("That's not a container.\r\n");
      return;
    }
    if (!IS_SET (obj->value[1], CONT_CLOSED)) {
      send_to_char ("It's already open.\r\n");
      return;
    }
    if (!IS_SET (obj->value[1], CONT_CLOSEABLE)) {
      send_to_char ("You can't do that.\r\n");
      return;
    }
    if (IS_SET (obj->value[1], CONT_LOCKED)) {
      send_to_char ("It's locked.\r\n");
      return;
    }

    REMOVE_BIT (obj->value[1], CONT_CLOSED);
    send_to_char ("Ok.\r\n");
    act ("$n opens $p.", obj, NULL, TO_ROOM);
    return;
  }

  int door;
  if ((door = find_door (arg)) >= 0) {
    /* 'open door' */
    Room *to_room;
    Exit *pexit;
    Exit *pexit_rev;

    pexit = in_room->exit[door];
    if (!IS_SET (pexit->exit_info, EX_CLOSED)) {
      send_to_char ("It's already open.\r\n");
      return;
    }
    if (IS_SET (pexit->exit_info, EX_LOCKED)) {
      send_to_char ("It's locked.\r\n");
      return;
    }

    REMOVE_BIT (pexit->exit_info, EX_CLOSED);
    act ("$n opens the $d.", NULL, pexit->keyword.c_str(), TO_ROOM);
    send_to_char ("Ok.\r\n");

    /* open the other side */
    if ((to_room = pexit->to_room) != NULL
      && (pexit_rev = to_room->exit[rev_dir[door]]) != NULL
      && pexit_rev->to_room == in_room) {

      REMOVE_BIT (pexit_rev->exit_info, EX_CLOSED);
      CharIter rch;
      for (rch = to_room->people.begin(); rch != to_room->people.end(); rch++)
        (*rch)->act ("The $d opens.", NULL, pexit_rev->keyword.c_str(), TO_CHAR);
    }
  }

  return;
}

void Character::do_close (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Close what?\r\n");
    return;
  }

  Object *obj;
  if ((obj = get_obj_here (arg)) != NULL) {
    /* 'close object' */
    if (obj->item_type != ITEM_CONTAINER) {
      send_to_char ("That's not a container.\r\n");
      return;
    }
    if (IS_SET (obj->value[1], CONT_CLOSED)) {
      send_to_char ("It's already closed.\r\n");
      return;
    }
    if (!IS_SET (obj->value[1], CONT_CLOSEABLE)) {
      send_to_char ("You can't do that.\r\n");
      return;
    }

    SET_BIT (obj->value[1], CONT_CLOSED);
    send_to_char ("Ok.\r\n");
    act ("$n closes $p.", obj, NULL, TO_ROOM);
    return;
  }

  int door;
  if ((door = find_door (arg)) >= 0) {
    /* 'close door' */
    Room *to_room;
    Exit *pexit;
    Exit *pexit_rev;

    pexit = in_room->exit[door];
    if (IS_SET (pexit->exit_info, EX_CLOSED)) {
      send_to_char ("It's already closed.\r\n");
      return;
    }

    SET_BIT (pexit->exit_info, EX_CLOSED);
    act ("$n closes the $d.", NULL, pexit->keyword.c_str(), TO_ROOM);
    send_to_char ("Ok.\r\n");

    /* close the other side */
    if ((to_room = pexit->to_room) != NULL
      && (pexit_rev = to_room->exit[rev_dir[door]]) != 0
      && pexit_rev->to_room == in_room) {

      SET_BIT (pexit_rev->exit_info, EX_CLOSED);
      CharIter rch;
      for (rch = to_room->people.begin(); rch != to_room->people.end(); rch++)
        (*rch)->act ("The $d closes.", NULL, pexit_rev->keyword.c_str(), TO_CHAR);
    }
  }

  return;
}

void Character::do_lock (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Lock what?\r\n");
    return;
  }

  Object *obj;
  if ((obj = get_obj_here (arg)) != NULL) {
    /* 'lock object' */
    if (obj->item_type != ITEM_CONTAINER) {
      send_to_char ("That's not a container.\r\n");
      return;
    }
    if (!IS_SET (obj->value[1], CONT_CLOSED)) {
      send_to_char ("It's not closed.\r\n");
      return;
    }
    if (obj->value[2] < 0) {
      send_to_char ("It can't be locked.\r\n");
      return;
    }
    if (!has_key(obj->value[2])) {
      send_to_char ("You lack the key.\r\n");
      return;
    }
    if (IS_SET (obj->value[1], CONT_LOCKED)) {
      send_to_char ("It's already locked.\r\n");
      return;
    }

    SET_BIT (obj->value[1], CONT_LOCKED);
    send_to_char ("*Click*\r\n");
    act ("$n locks $p.", obj, NULL, TO_ROOM);
    return;
  }

  int door;
  if ((door = find_door (arg)) >= 0) {
    /* 'lock door' */
    Room *to_room;
    Exit *pexit;
    Exit *pexit_rev;

    pexit = in_room->exit[door];
    if (!IS_SET (pexit->exit_info, EX_CLOSED)) {
      send_to_char ("It's not closed.\r\n");
      return;
    }
    if (pexit->key < 0) {
      send_to_char ("It can't be locked.\r\n");
      return;
    }
    if (!has_key(pexit->key)) {
      send_to_char ("You lack the key.\r\n");
      return;
    }
    if (IS_SET (pexit->exit_info, EX_LOCKED)) {
      send_to_char ("It's already locked.\r\n");
      return;
    }

    SET_BIT (pexit->exit_info, EX_LOCKED);
    send_to_char ("*Click*\r\n");
    act ("$n locks the $d.", NULL, pexit->keyword.c_str(), TO_ROOM);

    /* lock the other side */
    if ((to_room = pexit->to_room) != NULL
      && (pexit_rev = to_room->exit[rev_dir[door]]) != 0
      && pexit_rev->to_room == in_room) {
      SET_BIT (pexit_rev->exit_info, EX_LOCKED);
    }
  }

  return;
}

void Character::do_unlock (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Unlock what?\r\n");
    return;
  }

  Object *obj;
  if ((obj = get_obj_here (arg)) != NULL) {
    /* 'unlock object' */
    if (obj->item_type != ITEM_CONTAINER) {
      send_to_char ("That's not a container.\r\n");
      return;
    }
    if (!IS_SET (obj->value[1], CONT_CLOSED)) {
      send_to_char ("It's not closed.\r\n");
      return;
    }
    if (obj->value[2] < 0) {
      send_to_char ("It can't be unlocked.\r\n");
      return;
    }
    if (!has_key(obj->value[2])) {
      send_to_char ("You lack the key.\r\n");
      return;
    }
    if (!IS_SET (obj->value[1], CONT_LOCKED)) {
      send_to_char ("It's already unlocked.\r\n");
      return;
    }

    REMOVE_BIT (obj->value[1], CONT_LOCKED);
    send_to_char ("*Click*\r\n");
    act ("$n unlocks $p.", obj, NULL, TO_ROOM);
    return;
  }

  int door;
  if ((door = find_door (arg)) >= 0) {
    /* 'unlock door' */
    Room *to_room;
    Exit *pexit;
    Exit *pexit_rev;

    pexit = in_room->exit[door];
    if (!IS_SET (pexit->exit_info, EX_CLOSED)) {
      send_to_char ("It's not closed.\r\n");
      return;
    }
    if (pexit->key < 0) {
      send_to_char ("It can't be unlocked.\r\n");
      return;
    }
    if (!has_key(pexit->key)) {
      send_to_char ("You lack the key.\r\n");
      return;
    }
    if (!IS_SET (pexit->exit_info, EX_LOCKED)) {
      send_to_char ("It's already unlocked.\r\n");
      return;
    }

    REMOVE_BIT (pexit->exit_info, EX_LOCKED);
    send_to_char ("*Click*\r\n");
    act ("$n unlocks the $d.", NULL, pexit->keyword.c_str(), TO_ROOM);

    /* unlock the other side */
    if ((to_room = pexit->to_room) != NULL
      && (pexit_rev = to_room->exit[rev_dir[door]]) != NULL
      && pexit_rev->to_room == in_room) {
      REMOVE_BIT (pexit_rev->exit_info, EX_LOCKED);
    }
  }

  return;
}

void Character::do_pick (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Pick what?\r\n");
    return;
  }

  wait_state (skill_table[gsn_pick_lock].beats);

  /* look for guards */
  CharIter rch;
  for (rch = in_room->people.begin(); rch != in_room->people.end(); rch++) {
    if ((*rch)->is_npc () && (*rch)->is_awake () && level + 5 < (*rch)->level) {
      act ("$N is standing too close to the lock.", NULL, *rch, TO_CHAR);
      return;
    }
  }

  if (!is_npc () && number_percent () > pcdata->learned[gsn_pick_lock]) {
    send_to_char ("You failed.\r\n");
    return;
  }

  Object *obj;
  if ((obj = get_obj_here (arg)) != NULL) {
    /* 'pick object' */
    if (obj->item_type != ITEM_CONTAINER) {
      send_to_char ("That's not a container.\r\n");
      return;
    }
    if (!IS_SET (obj->value[1], CONT_CLOSED)) {
      send_to_char ("It's not closed.\r\n");
      return;
    }
    if (obj->value[2] < 0) {
      send_to_char ("It can't be unlocked.\r\n");
      return;
    }
    if (!IS_SET (obj->value[1], CONT_LOCKED)) {
      send_to_char ("It's already unlocked.\r\n");
      return;
    }
    if (IS_SET (obj->value[1], CONT_PICKPROOF)) {
      send_to_char ("You failed.\r\n");
      return;
    }

    REMOVE_BIT (obj->value[1], CONT_LOCKED);
    send_to_char ("*Click*\r\n");
    act ("$n picks $p.", obj, NULL, TO_ROOM);
    return;
  }

  int door;
  if ((door = find_door (arg)) >= 0) {
    /* 'pick door' */
    Room *to_room;
    Exit *pexit;
    Exit *pexit_rev;

    pexit = in_room->exit[door];
    if (!IS_SET (pexit->exit_info, EX_CLOSED)) {
      send_to_char ("It's not closed.\r\n");
      return;
    }
    if (pexit->key < 0) {
      send_to_char ("It can't be picked.\r\n");
      return;
    }
    if (!IS_SET (pexit->exit_info, EX_LOCKED)) {
      send_to_char ("It's already unlocked.\r\n");
      return;
    }
    if (IS_SET (pexit->exit_info, EX_PICKPROOF)) {
      send_to_char ("You failed.\r\n");
      return;
    }

    REMOVE_BIT (pexit->exit_info, EX_LOCKED);
    send_to_char ("*Click*\r\n");
    act ("$n picks the $d.", NULL, pexit->keyword.c_str(), TO_ROOM);

    /* pick the other side */
    if ((to_room = pexit->to_room) != NULL
      && (pexit_rev = to_room->exit[rev_dir[door]]) != NULL
      && pexit_rev->to_room == in_room) {
      REMOVE_BIT (pexit_rev->exit_info, EX_LOCKED);
    }
  }

  return;
}

void Character::do_stand (std::string argument)
{
  switch (position) {
  case POS_SLEEPING:
    if (is_affected (AFF_SLEEP)) {
      send_to_char ("You can't wake up!\r\n");
      return;
    }

    send_to_char ("You wake and stand up.\r\n");
    act ("$n wakes and stands up.", NULL, NULL, TO_ROOM);
    position = POS_STANDING;
    break;

  case POS_RESTING:
    send_to_char ("You stand up.\r\n");
    act ("$n stands up.", NULL, NULL, TO_ROOM);
    position = POS_STANDING;
    break;

  case POS_STANDING:
    send_to_char ("You are already standing.\r\n");
    break;

  case POS_FIGHTING:
    send_to_char ("You are already fighting!\r\n");
    break;
  }

  return;
}

void Character::do_rest (std::string argument)
{
  switch (position) {
  case POS_SLEEPING:
    send_to_char ("You are already sleeping.\r\n");
    break;

  case POS_RESTING:
    send_to_char ("You are already resting.\r\n");
    break;

  case POS_STANDING:
    send_to_char ("You rest.\r\n");
    act ("$n rests.", NULL, NULL, TO_ROOM);
    position = POS_RESTING;
    break;

  case POS_FIGHTING:
    send_to_char ("You are already fighting!\r\n");
    break;
  }

  return;
}

void Character::do_sleep (std::string argument)
{
  switch (position) {
  case POS_SLEEPING:
    send_to_char ("You are already sleeping.\r\n");
    break;

  case POS_RESTING:
  case POS_STANDING:
    send_to_char ("You sleep.\r\n");
    act ("$n sleeps.", NULL, NULL, TO_ROOM);
    position = POS_SLEEPING;
    break;

  case POS_FIGHTING:
    send_to_char ("You are already fighting!\r\n");
    break;
  }

  return;
}

void Character::do_wake (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);
  if (arg.empty()) {
    do_stand (argument);
    return;
  }

  if (!is_awake ()) {
    send_to_char ("You are asleep yourself!\r\n");
    return;
  }

  Character *victim;
  if ((victim = get_char_room (arg)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (victim->is_awake ()) {
    act ("$N is already awake.", NULL, victim, TO_CHAR);
    return;
  }

  if (victim->is_affected (AFF_SLEEP)) {
    act ("You can't wake $M!", NULL, victim, TO_CHAR);
    return;
  }

  act ("You wake $M.", NULL, victim, TO_CHAR);
  act ("$n wakes you.", NULL, victim, TO_VICT);
  victim->position = POS_STANDING;
  return;
}

void Character::do_sneak (std::string argument)
{
  Affect af;

  send_to_char ("You attempt to move silently.\r\n");
  affect_strip (gsn_sneak);

  if (is_npc () || number_percent () < pcdata->learned[gsn_sneak]) {
    af.type = gsn_sneak;
    af.duration = level;
    af.location = APPLY_NONE;
    af.modifier = 0;
    af.bitvector = AFF_SNEAK;
    affect_to_char(&af);
  }

  return;
}

void Character::do_hide (std::string argument)
{
  send_to_char ("You attempt to hide.\r\n");

  if (is_affected (AFF_HIDE))
    REMOVE_BIT (affected_by, AFF_HIDE);

  if (is_npc () || number_percent () < pcdata->learned[gsn_hide])
    SET_BIT (affected_by, AFF_HIDE);

  return;
}

/*
 * Contributed by Alander.
 */
void Character::do_visible (std::string argument)
{
  affect_strip (gsn_invis);
  affect_strip (gsn_mass_invis);
  affect_strip (gsn_sneak);
  REMOVE_BIT (affected_by, AFF_HIDE);
  REMOVE_BIT (affected_by, AFF_INVISIBLE);
  REMOVE_BIT (affected_by, AFF_SNEAK);
  send_to_char ("Ok.\r\n");
  return;
}

void Character::do_recall (std::string argument)
{
  char buf[MAX_STRING_LENGTH];
  Room *location;

  act ("$n prays for transportation!", 0, 0, TO_ROOM);

  if ((location = get_room_index (ROOM_VNUM_TEMPLE)) == NULL) {
    send_to_char ("You are completely lost.\r\n");
    return;
  }

  if (in_room == location)
    return;

  if (IS_SET (in_room->room_flags, ROOM_NO_RECALL)
    || is_affected (AFF_CURSE)) {
    send_to_char ("God has forsaken you.\r\n");
    return;
  }

  if (fighting != NULL) {
    int lose;

    if (number_percent() <= 50) {
      wait_state (4);
      lose = (desc != NULL) ? 50 : 100;
      gain_exp(0 - lose);
      snprintf (buf, sizeof buf, "You failed!  You lose %d exps.\r\n", lose);
      send_to_char (buf);
      return;
    }

    lose = (desc != NULL) ? 100 : 200;
    gain_exp(0 - lose);
    snprintf (buf, sizeof buf, "You recall from combat!  You lose %d exps.\r\n", lose);
    send_to_char (buf);
    stop_fighting(true);
  }

  move /= 2;
  act ("$n disappears.", NULL, NULL, TO_ROOM);
  char_from_room();
  char_to_room(location);
  act ("$n appears in the room.", NULL, NULL, TO_ROOM);
  do_look ("auto");

  return;
}

void Character::do_train (std::string argument)
{
  if (is_npc ())
    return;

  std::string buf;
  sh_int *pAbility;
  char *pOutput;

  /*
   * Check for trainer.
   */
  CharIter mob;
  for (mob = in_room->people.begin(); mob != in_room->people.end(); mob++) {
    if ((*mob)->is_npc () && IS_SET ((*mob)->actflags, ACT_TRAIN))
      break;
  }

  if (mob == in_room->people.end()) {
    send_to_char ("You can't do that here.\r\n");
    return;
  }

  if (argument.empty()) {
    buf = "You have " + itoa(practice, 10) + " practice sessions.\r\n";
    send_to_char (buf);
    argument = "foo";
  }

  int cost = 5;

  if (!str_cmp (argument, "str")) {
    if (class_table[klass].attr_prime == APPLY_STR)
      cost = 3;
    pAbility = &pcdata->perm_str;
    pOutput = "strength";
  } else if (!str_cmp (argument, "int")) {
    if (class_table[klass].attr_prime == APPLY_INT)
      cost = 3;
    pAbility = &pcdata->perm_int;
    pOutput = "intelligence";
  } else if (!str_cmp (argument, "wis")) {
    if (class_table[klass].attr_prime == APPLY_WIS)
      cost = 3;
    pAbility = &pcdata->perm_wis;
    pOutput = "wisdom";
  } else if (!str_cmp (argument, "dex")) {
    if (class_table[klass].attr_prime == APPLY_DEX)
      cost = 3;
    pAbility = &pcdata->perm_dex;
    pOutput = "dexterity";
  } else if (!str_cmp (argument, "con")) {
    if (class_table[klass].attr_prime == APPLY_CON)
      cost = 3;
    pAbility = &pcdata->perm_con;
    pOutput = "constitution";
  } else {
    buf = "You can train:";
    if (pcdata->perm_str < 18)
      buf.append(" str");
    if (pcdata->perm_int < 18)
      buf.append(" int");
    if (pcdata->perm_wis < 18)
      buf.append(" wis");
    if (pcdata->perm_dex < 18)
      buf.append(" dex");
    if (pcdata->perm_con < 18)
      buf.append(" con");

    if (buf[buf.size() - 1] != ':') {
      buf.append(".\r\n");
      send_to_char (buf);
    } else {
      /*
       * This message dedicated to Jordan ... you big stud!
       */
      act ("You have nothing left to train, you $T!",
        NULL,
        sex == SEX_MALE ? "big stud" :
        sex == SEX_FEMALE ? "hot babe" : "wild thing", TO_CHAR);
    }

    return;
  }

  if (*pAbility >= 18) {
    act ("Your $T is already at maximum.", NULL, pOutput, TO_CHAR);
    return;
  }

  if (cost > practice) {
    send_to_char ("You don't have enough practices.\r\n");
    return;
  }

  practice -= cost;
  *pAbility += 1;
  act ("Your $T increases!", NULL, pOutput, TO_CHAR);
  act ("$n's $T increases!", NULL, pOutput, TO_ROOM);
  return;
}

void Character::do_get (std::string argument)
{
  std::string arg1;
  std::string arg2;

  argument = one_argument (argument, arg1);
  argument = one_argument (argument, arg2);

  /* Get type. */
  if (arg1.empty()) {
    send_to_char ("Get what?\r\n");
    return;
  }

  Object *obj;
  Object *container;
  bool found;
  if (arg2.empty()) {
    if (str_cmp (arg1, "all") && str_prefix ("all.", arg1)) {
      /* 'get obj' */
      obj = get_obj_list (arg1, in_room->contents);
      if (obj == NULL) {
        act ("I see no $T here.", NULL, arg1.c_str(), TO_CHAR);
        return;
      }

      get_obj (obj, NULL);
    } else {
      /* 'get all' or 'get all.obj' */
      found = false;
      ObjIter o, onext;
      for (o = in_room->contents.begin(); o != in_room->contents.end(); o = onext) {
        obj = *o;
        onext = ++o;
        if ((arg1[3] == '\0' || is_name (&arg1[4], obj->name))
          && can_see_obj(obj)) {
          found = true;
          get_obj (obj, NULL);
        }
      }

      if (!found) {
        if (arg1[3] == '\0')
          send_to_char ("I see nothing here.\r\n");
        else
          act ("I see no $T here.", NULL, &arg1[4], TO_CHAR);
      }
    }
  } else {
    /* 'get ... container' */
    if (!str_cmp (arg2, "all") || !str_prefix ("all.", arg2)) {
      send_to_char ("You can't do that.\r\n");
      return;
    }

    if ((container = get_obj_here (arg2)) == NULL) {
      act ("I see no $T here.", NULL, arg2.c_str(), TO_CHAR);
      return;
    }

    switch (container->item_type) {
    default:
      send_to_char ("That's not a container.\r\n");
      return;

    case ITEM_CONTAINER:
    case ITEM_CORPSE_NPC:
      break;

    case ITEM_CORPSE_PC:
      {
        std::string nm;
        std::string pd;

        if (is_npc ()) {
          send_to_char ("You can't do that.\r\n");
          return;
        }

        pd = container->short_descr;
        pd = one_argument (pd, nm);
        pd = one_argument (pd, nm);
        pd = one_argument (pd, nm);

        if (str_cmp (nm, name) && !is_immortal()) {
          bool fGroup;

          fGroup = false;
          CharIter c;
          for (c = char_list.begin(); c != char_list.end(); c++) {
            if (!(*c)->is_npc ()
              && is_same_group (this, *c)
              && !str_cmp (nm, (*c)->name)) {
              fGroup = true;
              break;
            }
          }

          if (!fGroup) {
            send_to_char ("You can't do that.\r\n");
            return;
          }
        }
      }
    }

    if (IS_SET (container->value[1], CONT_CLOSED)) {
      act ("The $d is closed.", NULL, container->name.c_str(), TO_CHAR);
      return;
    }

    if (str_cmp (arg1, "all") && str_prefix ("all.", arg1)) {
      /* 'get obj container' */
      obj = get_obj_list (arg1, container->contains);
      if (obj == NULL) {
        act ("I see nothing like that in the $T.", NULL, arg2.c_str(), TO_CHAR);
        return;
      }
      get_obj (obj, container);
    } else {
      /* 'get all container' or 'get all.obj container' */
      found = false;
      ObjIter o, onext;
      for (o = container->contains.begin(); o != container->contains.end(); o = onext) {
        obj = *o;
        onext = ++o;
        if ((arg1[3] == '\0' || is_name (&arg1[4], obj->name))
          && can_see_obj(obj)) {
          found = true;
          get_obj (obj, container);
        }
      }

      if (!found) {
        if (arg1[3] == '\0')
          act ("I see nothing in the $T.", NULL, arg2.c_str(), TO_CHAR);
        else
          act ("I see nothing like that in the $T.", NULL, arg2.c_str(), TO_CHAR);
      }
    }
  }

  return;
}

void Character::do_put (std::string argument)
{
  std::string arg1;
  std::string arg2;

  argument = one_argument (argument, arg1);
  argument = one_argument (argument, arg2);

  if (arg1.empty() || arg2.empty()) {
    send_to_char ("Put what in what?\r\n");
    return;
  }

  if (!str_cmp (arg2, "all") || !str_prefix ("all.", arg2)) {
    send_to_char ("You can't do that.\r\n");
    return;
  }

  Object *container;
  if ((container = get_obj_here (arg2)) == NULL) {
    act ("I see no $T here.", NULL, arg2.c_str(), TO_CHAR);
    return;
  }

  if (container->item_type != ITEM_CONTAINER) {
    send_to_char ("That's not a container.\r\n");
    return;
  }

  if (IS_SET (container->value[1], CONT_CLOSED)) {
    act ("The $d is closed.", NULL, container->name.c_str(), TO_CHAR);
    return;
  }

  Object *obj;
  if (str_cmp (arg1, "all") && str_prefix ("all.", arg1)) {
    /* 'put obj container' */
    if ((obj = get_obj_carry (arg1)) == NULL) {
      send_to_char ("You do not have that item.\r\n");
      return;
    }

    if (obj == container) {
      send_to_char ("You can't fold it into itself.\r\n");
      return;
    }

    if (!can_drop_obj (obj)) {
      send_to_char ("You can't let go of it.\r\n");
      return;
    }

    if (obj->get_obj_weight() + container->get_obj_weight()
      > container->value[0]) {
      send_to_char ("It won't fit.\r\n");
      return;
    }

    obj->obj_from_char();
    obj->obj_to_obj (container);
    act ("$n puts $p in $P.", obj, container, TO_ROOM);
    act ("You put $p in $P.", obj, container, TO_CHAR);
  } else {
    /* 'put all container' or 'put all.obj container' */
    ObjIter o, onext;
    for (o = carrying.begin(); o != carrying.end(); o = onext) {
      obj = *o;
      onext = ++o;

      if ((arg1[3] == '\0' || is_name (&arg1[4], obj->name))
        && can_see_obj(obj)
        && obj->wear_loc == WEAR_NONE
        && obj != container && can_drop_obj (obj)
        && obj->get_obj_weight() + container->get_obj_weight()
        <= container->value[0]) {
        obj->obj_from_char ();
        obj->obj_to_obj (container);
        act ("$n puts $p in $P.", obj, container, TO_ROOM);
        act ("You put $p in $P.", obj, container, TO_CHAR);
      }
    }
  }

  return;
}

void Character::do_drop (std::string argument)
{
  std::string arg;

  argument = one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Drop what?\r\n");
    return;
  }

  Object *obj;
  bool found;
  if (is_number (arg)) {
    /* 'drop NNNN coins' */
    int amount;

    amount = atoi (arg.c_str());
    argument = one_argument (argument, arg);
    if (amount <= 0 || (str_cmp (arg, "coins") && str_cmp (arg, "coin"))) {
      send_to_char ("Sorry, you can't do that.\r\n");
      return;
    }

    if (gold < amount) {
      send_to_char ("You haven't got that many coins.\r\n");
      return;
    }

    gold -= amount;

    ObjIter o, onext;
    for (o = in_room->contents.begin(); o != in_room->contents.end(); o = onext) {
      obj = *o;
      onext = ++o;

      switch (obj->pIndexData->vnum) {
      case OBJ_VNUM_MONEY_ONE:
        amount += 1;
        obj->extract_obj ();
        break;

      case OBJ_VNUM_MONEY_SOME:
        amount += obj->value[0];
        obj->extract_obj ();
        break;
      }
    }

    create_money (amount)->obj_to_room (in_room);
    act ("$n drops some gold.", NULL, NULL, TO_ROOM);
    send_to_char ("OK.\r\n");
    return;
  }

  if (str_cmp (arg, "all") && str_prefix ("all.", arg)) {
    /* 'drop obj' */
    if ((obj = get_obj_carry (arg)) == NULL) {
      send_to_char ("You do not have that item.\r\n");
      return;
    }

    if (!can_drop_obj (obj)) {
      send_to_char ("You can't let go of it.\r\n");
      return;
    }

    obj->obj_from_char();
    obj->obj_to_room (in_room);
    act ("$n drops $p.", obj, NULL, TO_ROOM);
    act ("You drop $p.", obj, NULL, TO_CHAR);
  } else {
    /* 'drop all' or 'drop all.obj' */
    found = false;
    ObjIter o, onext;
    for (o = carrying.begin(); o != carrying.end(); o = onext) {
      obj = *o;
      onext = ++o;

      if ((arg[3] == '\0' || is_name (&arg[4], obj->name))
        && can_see_obj(obj)
        && obj->wear_loc == WEAR_NONE && can_drop_obj (obj)) {
        found = true;
        obj->obj_from_char();
        obj->obj_to_room(in_room);
        act ("$n drops $p.", obj, NULL, TO_ROOM);
        act ("You drop $p.", obj, NULL, TO_CHAR);
      }
    }

    if (!found) {
      if (arg[3] == '\0')
        act ("You are not carrying anything.", NULL, arg.c_str(), TO_CHAR);
      else
        act ("You are not carrying any $T.", NULL, &arg[4], TO_CHAR);
    }
  }

  return;
}

void Character::do_give (std::string argument)
{
  std::string arg1;
  std::string arg2;

  argument = one_argument (argument, arg1);
  argument = one_argument (argument, arg2);

  if (arg1.empty() || arg2.empty()) {
    send_to_char ("Give what to whom?\r\n");
    return;
  }

  Character *victim;
  Object *obj;
  if (is_number (arg1)) {
    /* 'give NNNN coins victim' */
    int amount;

    amount = atoi (arg1.c_str());
    if (amount <= 0 || (str_cmp (arg2, "coins") && str_cmp (arg2, "coin"))) {
      send_to_char ("Sorry, you can't do that.\r\n");
      return;
    }

    argument = one_argument (argument, arg2);
    if (arg2.empty()) {
      send_to_char ("Give what to whom?\r\n");
      return;
    }

    if ((victim = get_char_room (arg2)) == NULL) {
      send_to_char ("They aren't here.\r\n");
      return;
    }

    if (gold < amount) {
      send_to_char ("You haven't got that much gold.\r\n");
      return;
    }

    gold -= amount;
    victim->gold += amount;
    act ("$n gives you some gold.", NULL, victim, TO_VICT);
    act ("$n gives $N some gold.", NULL, victim, TO_NOTVICT);
    act ("You give $N some gold.", NULL, victim, TO_CHAR);
    send_to_char ("OK.\r\n");
    mprog_bribe_trigger (victim, this, amount);
    return;
  }

  if ((obj = get_obj_carry (arg1)) == NULL) {
    send_to_char ("You do not have that item.\r\n");
    return;
  }

  if (obj->wear_loc != WEAR_NONE) {
    send_to_char ("You must remove it first.\r\n");
    return;
  }

  if ((victim = get_char_room (arg2)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (!can_drop_obj (obj)) {
    send_to_char ("You can't let go of it.\r\n");
    return;
  }

  if (victim->carry_number + obj->get_obj_number() > victim->can_carry_n()) {
    act ("$N has $S hands full.", NULL, victim, TO_CHAR);
    return;
  }

  if (victim->carry_weight + obj->get_obj_weight() > victim->can_carry_w()) {
    act ("$N can't carry that much weight.", NULL, victim, TO_CHAR);
    return;
  }

  if (!victim->can_see_obj(obj)) {
    act ("$N can't see it.", NULL, victim, TO_CHAR);
    return;
  }

  obj->obj_from_char ();
  obj->obj_to_char (victim);
  MOBtrigger = false;
  act ("$n gives $p to $N.", obj, victim, TO_NOTVICT);
  act ("$n gives you $p.", obj, victim, TO_VICT);
  act ("You give $p to $N.", obj, victim, TO_CHAR);
  mprog_give_trigger (victim, this, obj);
  return;
}

void Character::do_fill (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Fill what?\r\n");
    return;
  }

  Object *obj;
  if ((obj = get_obj_carry (arg)) == NULL) {
    send_to_char ("You do not have that item.\r\n");
    return;
  }

  bool found = false;
  ObjIter o;
  for (o = in_room->contents.begin(); o != in_room->contents.end(); o++) {
    if ((*o)->item_type == ITEM_FOUNTAIN) {
      found = true;
      break;
    }
  }

  if (!found) {
    send_to_char ("There is no fountain here!\r\n");
    return;
  }

  if (obj->item_type != ITEM_DRINK_CON) {
    send_to_char ("You can't fill that.\r\n");
    return;
  }

  if (obj->value[1] != 0 && obj->value[2] != 0) {
    send_to_char ("There is already another liquid in it.\r\n");
    return;
  }

  if (obj->value[1] >= obj->value[0]) {
    send_to_char ("Your container is full.\r\n");
    return;
  }

  act ("You fill $p.", obj, NULL, TO_CHAR);
  obj->value[2] = 0;
  obj->value[1] = obj->value[0];
  return;
}

void Character::do_drink (std::string argument)
{
  std::string arg;
  Object *obj = NULL;
  int amount;
  int liquid;

  one_argument (argument, arg);

  if (arg.empty()) {
    ObjIter o;
    for (o = in_room->contents.begin(); o != in_room->contents.end(); o++) {
      obj = *o;
      if (obj->item_type == ITEM_FOUNTAIN)
        break;
    }

    if (obj == NULL) {
      send_to_char ("Drink what?\r\n");
      return;
    }
  } else {
    if ((obj = get_obj_here (arg)) == NULL) {
      send_to_char ("You can't find it.\r\n");
      return;
    }
  }

  if (!is_npc () && pcdata->condition[COND_DRUNK] > 10) {
    send_to_char ("You fail to reach your mouth.  *Hic*\r\n");
    return;
  }

  switch (obj->item_type) {
  default:
    send_to_char ("You can't drink from that.\r\n");
    break;

  case ITEM_FOUNTAIN:
    if (!is_npc ())
      pcdata->condition[COND_THIRST] = 48;
    act ("$n drinks from the fountain.", NULL, NULL, TO_ROOM);
    send_to_char ("You are not thirsty.\r\n");
    break;

  case ITEM_DRINK_CON:
    if (obj->value[1] <= 0) {
      send_to_char ("It is already empty.\r\n");
      return;
    }

    if ((liquid = obj->value[2]) >= LIQ_MAX) {
      bug_printf ("Do_drink: bad liquid number %d.", liquid);
      liquid = obj->value[2] = 0;
    }

    act ("$n drinks $T from $p.",
      obj, liq_table[liquid].liq_name, TO_ROOM);
    act ("You drink $T from $p.",
      obj, liq_table[liquid].liq_name, TO_CHAR);

    amount = number_range (3, 10);
    amount = std::min (amount, obj->value[1]);

    gain_condition (COND_DRUNK, amount * liq_table[liquid].liq_affect[COND_DRUNK]);
    gain_condition (COND_FULL, amount * liq_table[liquid].liq_affect[COND_FULL]);
    gain_condition (COND_THIRST, amount * liq_table[liquid].liq_affect[COND_THIRST]);

    if (!is_npc () && pcdata->condition[COND_DRUNK] > 10)
      send_to_char ("You feel drunk.\r\n");
    if (!is_npc () && pcdata->condition[COND_FULL] > 40)
      send_to_char ("You are full.\r\n");
    if (!is_npc () && pcdata->condition[COND_THIRST] > 40)
      send_to_char ("You do not feel thirsty.\r\n");

    if (obj->value[3] != 0) {
      /* The shit was poisoned ! */
      Affect af;

      act ("$n chokes and gags.", NULL, NULL, TO_ROOM);
      send_to_char ("You choke and gag.\r\n");
      af.type = gsn_poison;
      af.duration = 3 * amount;
      af.location = APPLY_NONE;
      af.modifier = 0;
      af.bitvector = AFF_POISON;
      affect_join (&af);
    }

    obj->value[1] -= amount;
    if (obj->value[1] <= 0) {
      send_to_char ("The empty container vanishes.\r\n");
      obj->extract_obj ();
    }
    break;
  }

  return;
}

void Character::do_eat (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);
  if (arg.empty()) {
    send_to_char ("Eat what?\r\n");
    return;
  }

  Object *obj;
  if ((obj = get_obj_carry (arg)) == NULL) {
    send_to_char ("You do not have that item.\r\n");
    return;
  }

  if (!is_immortal()) {
    if (obj->item_type != ITEM_FOOD && obj->item_type != ITEM_PILL) {
      send_to_char ("That's not edible.\r\n");
      return;
    }

    if (!is_npc () && pcdata->condition[COND_FULL] > 40) {
      send_to_char ("You are too full to eat more.\r\n");
      return;
    }
  }

  act ("$n eats $p.", obj, NULL, TO_ROOM);
  act ("You eat $p.", obj, NULL, TO_CHAR);

  switch (obj->item_type) {

  case ITEM_FOOD:
    if (!is_npc ()) {
      int condition;

      condition = pcdata->condition[COND_FULL];
      gain_condition (COND_FULL, obj->value[0]);
      if (condition == 0 && pcdata->condition[COND_FULL] > 0)
        send_to_char ("You are no longer hungry.\r\n");
      else if (pcdata->condition[COND_FULL] > 40)
        send_to_char ("You are full.\r\n");
    }

    if (obj->value[3] != 0) {
      /* The shit was poisoned! */
      Affect af;

      act ("$n chokes and gags.", 0, 0, TO_ROOM);
      send_to_char ("You choke and gag.\r\n");

      af.type = gsn_poison;
      af.duration = 2 * obj->value[0];
      af.location = APPLY_NONE;
      af.modifier = 0;
      af.bitvector = AFF_POISON;
      affect_join (&af);
    }
    break;

  case ITEM_PILL:
    obj_cast_spell (obj->value[1], obj->value[0], this, this, NULL);
    obj_cast_spell (obj->value[2], obj->value[0], this, this, NULL);
    obj_cast_spell (obj->value[3], obj->value[0], this, this, NULL);
    break;
  }

  obj->extract_obj ();
  return;
}

void Character::do_wear (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Wear, wield, or hold what?\r\n");
    return;
  }

  Object *obj;
  if (!str_cmp (arg, "all")) {
    ObjIter o, onext;
    for (o = carrying.begin(); o != carrying.end(); o = onext) {
      obj = *o;
      onext = ++o;
      if (obj->wear_loc == WEAR_NONE && can_see_obj(obj))
        wear_obj (obj, false);
    }
    return;
  } else {
    if ((obj = get_obj_carry (arg)) == NULL) {
      send_to_char ("You do not have that item.\r\n");
      return;
    }

    wear_obj (obj, true);
  }

  return;
}

void Character::do_remove (std::string argument)
{
  std::string arg;
  Object *obj;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Remove what?\r\n");
    return;
  }

  if ((obj = get_obj_wear (arg)) == NULL) {
    send_to_char ("You do not have that item.\r\n");
    return;
  }

  remove_obj (obj->wear_loc, true);
  return;
}

void Character::do_sacrifice (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);

  if (arg.empty() || !str_cmp (arg, name)) {
    act ("$n offers $mself to God, who graciously declines.",
      NULL, NULL, TO_ROOM);
    send_to_char ("God appreciates your offer and may accept it later.");
    return;
  }

  Object* obj = get_obj_list (arg, in_room->contents);
  if (obj == NULL) {
    send_to_char ("You can't find it.\r\n");
    return;
  }

  if (!obj->can_wear(ITEM_TAKE)) {
    act ("$p is not an acceptable sacrifice.", obj, 0, TO_CHAR);
    return;
  }

  send_to_char ("God gives you one gold coin for your sacrifice.\r\n");
  gold += 1;

  act ("$n sacrifices $p to God.", obj, NULL, TO_ROOM);
  obj->extract_obj ();
  return;
}

void Character::do_quaff (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Quaff what?\r\n");
    return;
  }

  Object *obj;
  if ((obj = get_obj_carry (arg)) == NULL) {
    send_to_char ("You do not have that potion.\r\n");
    return;
  }

  if (obj->item_type != ITEM_POTION) {
    send_to_char ("You can quaff only potions.\r\n");
    return;
  }

  act ("$n quaffs $p.", obj, NULL, TO_ROOM);
  act ("You quaff $p.", obj, NULL, TO_CHAR);

  obj_cast_spell (obj->value[1], obj->value[0], this, this, NULL);
  obj_cast_spell (obj->value[2], obj->value[0], this, this, NULL);
  obj_cast_spell (obj->value[3], obj->value[0], this, this, NULL);

  obj->extract_obj ();
  return;
}

void Character::do_recite (std::string argument)
{
  std::string arg1;
  std::string arg2;

  argument = one_argument (argument, arg1);
  argument = one_argument (argument, arg2);

  Object *scroll;
  if ((scroll = get_obj_carry (arg1)) == NULL) {
    send_to_char ("You do not have that scroll.\r\n");
    return;
  }

  if (scroll->item_type != ITEM_SCROLL) {
    send_to_char ("You can recite only scrolls.\r\n");
    return;
  }

  Character *victim;
  Object *obj = NULL;
  if (arg2.empty()) {
    victim = this;
  } else {
    if ((victim = get_char_room (arg2)) == NULL
      && (obj = get_obj_here (arg2)) == NULL) {
      send_to_char ("You can't find it.\r\n");
      return;
    }
  }

  act ("$n recites $p.", scroll, NULL, TO_ROOM);
  act ("You recite $p.", scroll, NULL, TO_CHAR);

  obj_cast_spell (scroll->value[1], scroll->value[0], this, victim, obj);
  obj_cast_spell (scroll->value[2], scroll->value[0], this, victim, obj);
  obj_cast_spell (scroll->value[3], scroll->value[0], this, victim, obj);

  scroll->extract_obj ();
  return;
}

void Character::do_brandish (std::string argument)
{
  Character *vch;
  Object *staff;

  if ((staff = get_eq_char (WEAR_HOLD)) == NULL) {
    send_to_char ("You hold nothing in your hand.\r\n");
    return;
  }

  if (staff->item_type != ITEM_STAFF) {
    send_to_char ("You can brandish only with a staff.\r\n");
    return;
  }

  int sn;
  if ((sn = staff->value[3]) < 0
    || sn >= MAX_SKILL || skill_table[sn].spell_fun == NULL) {
    bug_printf ("Do_brandish: bad sn %d.", sn);
    return;
  }

  wait_state (2 * PULSE_VIOLENCE);

  if (staff->value[2] > 0) {
    act ("$n brandishes $p.", staff, NULL, TO_ROOM);
    act ("You brandish $p.", staff, NULL, TO_CHAR);
    CharIter rch, next;
    for (rch = in_room->people.begin(); rch != in_room->people.end(); rch = next) {
      vch = *rch;
      next = ++rch;

      switch (skill_table[sn].target) {
      default:
        bug_printf ("Do_brandish: bad target for sn %d.", sn);
        return;

      case TAR_IGNORE:
        if (vch != this)
          continue;
        break;

      case TAR_CHAR_OFFENSIVE:
        if (is_npc () ? vch->is_npc () : !vch->is_npc ())
          continue;
        break;

      case TAR_CHAR_DEFENSIVE:
        if (is_npc () ? !vch->is_npc () : vch->is_npc ())
          continue;
        break;

      case TAR_CHAR_SELF:
        if (vch != this)
          continue;
        break;
      }

      obj_cast_spell (staff->value[3], staff->value[0], this, vch, NULL);
    }
  }

  if (--staff->value[2] <= 0) {
    act ("$n's $p blazes bright and is gone.", staff, NULL, TO_ROOM);
    act ("Your $p blazes bright and is gone.", staff, NULL, TO_CHAR);
    staff->extract_obj ();
  }

  return;
}

void Character::do_zap (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);
  if (arg.empty() && fighting == NULL) {
    send_to_char ("Zap whom or what?\r\n");
    return;
  }

  Object *wand;
  if ((wand = get_eq_char (WEAR_HOLD)) == NULL) {
    send_to_char ("You hold nothing in your hand.\r\n");
    return;
  }

  if (wand->item_type != ITEM_WAND) {
    send_to_char ("You can zap only with a wand.\r\n");
    return;
  }

  Character *victim;
  Object *obj = NULL;
  if (arg.empty()) {
    if (fighting != NULL) {
      victim = fighting;
    } else {
      send_to_char ("Zap whom or what?\r\n");
      return;
    }
  } else {
    if ((victim = get_char_room (arg)) == NULL
      && (obj = get_obj_here (arg)) == NULL) {
      send_to_char ("You can't find it.\r\n");
      return;
    }
  }

  wait_state (2 * PULSE_VIOLENCE);

  if (wand->value[2] > 0) {
    if (victim != NULL) {
      act ("$n zaps $N with $p.", wand, victim, TO_ROOM);
      act ("You zap $N with $p.", wand, victim, TO_CHAR);
    } else {
      act ("$n zaps $P with $p.", wand, obj, TO_ROOM);
      act ("You zap $P with $p.", wand, obj, TO_CHAR);
    }

    obj_cast_spell (wand->value[3], wand->value[0], this, victim, obj);
  }

  if (--wand->value[2] <= 0) {
    act ("$n's $p explodes into fragments.", wand, NULL, TO_ROOM);
    act ("Your $p explodes into fragments.", wand, NULL, TO_CHAR);
    wand->extract_obj ();
  }

  return;
}

void Character::do_steal (std::string argument)
{
  std::string arg1, arg2, buf;
  Character *victim;
  Object *obj;
  int percent;

  argument = one_argument (argument, arg1);
  argument = one_argument (argument, arg2);

  if (arg1.empty() || arg2.empty()) {
    send_to_char ("Steal what from whom?\r\n");
    return;
  }

  if ((victim = get_char_room (arg2)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (victim == this) {
    send_to_char ("That's pointless.\r\n");
    return;
  }

  wait_state (skill_table[gsn_steal].beats);
  percent = number_percent () + (victim->is_awake () ? 10 : -50);

  if (level + 5 < victim->level
    || victim->position == POS_FIGHTING || !victim->is_npc ()
    || (!is_npc () && percent > pcdata->learned[gsn_steal])) {
    /*
     * Failure.
     */
    send_to_char ("Oops.\r\n");
    act ("$n tried to steal from you.\r\n", NULL, victim, TO_VICT);
    act ("$n tried to steal from $N.\r\n", NULL, victim, TO_NOTVICT);
    buf = name + " is a bloody thief!";
    victim->do_shout (buf);
    if (!is_npc ()) {
      if (victim->is_npc ()) {
        multi_hit (victim, this, TYPE_UNDEFINED);
      } else {
        log_printf (buf.c_str());
        if (!IS_SET (actflags, PLR_THIEF)) {
          SET_BIT (actflags, PLR_THIEF);
          send_to_char ("*** You are now a THIEF!! ***\r\n");
          save_char_obj();
        }
      }
    }

    return;
  }

  if (!str_cmp (arg1, "coin")
    || !str_cmp (arg1, "coins")
    || !str_cmp (arg1, "gold")) {
    int amount;

    amount = victim->gold * number_range (1, 10) / 100;
    if (amount <= 0) {
      send_to_char ("You couldn't get any gold.\r\n");
      return;
    }

    gold += amount;
    victim->gold -= amount;
    buf = "Bingo!  You got " + itoa(amount, 10) + " gold coins.\r\n";
    send_to_char (buf);
    return;
  }

  if ((obj = victim->get_obj_carry (arg1)) == NULL) {
    send_to_char ("You can't find it.\r\n");
    return;
  }

  if (!can_drop_obj (obj)
    || IS_SET (obj->extra_flags, ITEM_INVENTORY)
    || obj->level > level) {
    send_to_char ("You can't pry it away.\r\n");
    return;
  }

  if (carry_number + obj->get_obj_number() > can_carry_n()) {
    send_to_char ("You have your hands full.\r\n");
    return;
  }

  if (carry_weight + obj->get_obj_weight() > can_carry_w()) {
    send_to_char ("You can't carry that much weight.\r\n");
    return;
  }

  obj->obj_from_char ();
  obj->obj_to_char (this);
  send_to_char ("Ok.\r\n");
  return;
}

void Character::do_buy (std::string argument)
{
  std::string arg;

  argument = one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Buy what?\r\n");
    return;
  }

  if (IS_SET (in_room->room_flags, ROOM_PET_SHOP)) {
    std::string buf;
    Character *pet;
    Room *pRoomIndexNext;
    Room *in_rm;

    if (is_npc ())
      return;

    pRoomIndexNext = get_room_index (in_room->vnum + 1);
    if (pRoomIndexNext == NULL) {
      bug_printf ("Do_buy: bad pet shop at vnum %d.", in_room->vnum);
      send_to_char ("Sorry, you can't buy that here.\r\n");
      return;
    }

    in_rm = in_room;
    in_room = pRoomIndexNext;
    pet = get_char_room (arg);
    in_room = in_rm;

    if (pet == NULL || !IS_SET (pet->actflags, ACT_PET)) {
      send_to_char ("Sorry, you can't buy that here.\r\n");
      return;
    }

    if (IS_SET (actflags, PLR_BOUGHT_PET)) {
      send_to_char ("You already bought one pet this level.\r\n");
      return;
    }

    if (gold < 10 * pet->level * pet->level) {
      send_to_char ("You can't afford it.\r\n");
      return;
    }

    if (level < pet->level) {
      send_to_char ("You're not ready for this pet.\r\n");
      return;
    }

    gold -= 10 * pet->level * pet->level;
    pet = pet->pIndexData->create_mobile();
    SET_BIT (actflags, PLR_BOUGHT_PET);
    SET_BIT (pet->actflags, ACT_PET);
    SET_BIT (pet->affected_by, AFF_CHARM);

    argument = one_argument (argument, arg);
    if (!arg.empty()) {
      buf = pet->name + " " + arg;
      pet->name = buf;
    }

    buf = pet->description + "A neck tag says 'I belong to " + name + "'.\r\n";
    pet->description = buf;

    pet->char_to_room(in_room);
    pet->add_follower(this);
    send_to_char ("Enjoy your pet.\r\n");
    act ("$n bought $N as a pet.", NULL, pet, TO_ROOM);
    return;
  } else {
    Character *keeper;
    Object *obj;
    int cost;

    if ((keeper = find_keeper (this)) == NULL)
      return;

    obj = keeper->get_obj_carry (arg);
    cost = get_cost (keeper, obj, true);

    if (cost <= 0 || !can_see_obj(obj)) {
      keeper->act ("$n tells you 'I don't sell that -- try 'list''.",
        NULL, this, TO_VICT);
      reply = keeper;
      return;
    }

    if (gold < cost) {
      keeper->act ("$n tells you 'You can't afford to buy $p'.",
        obj, this, TO_VICT);
      reply = keeper;
      return;
    }

    if (obj->level > level) {
      keeper->act ("$n tells you 'You can't use $p yet'.", obj, this, TO_VICT);
      reply = keeper;
      return;
    }

    if (carry_number + obj->get_obj_number() > can_carry_n()) {
      send_to_char ("You can't carry that many items.\r\n");
      return;
    }

    if (carry_weight + obj->get_obj_weight() > can_carry_w()) {
      send_to_char ("You can't carry that much weight.\r\n");
      return;
    }

    act ("$n buys $p.", obj, NULL, TO_ROOM);
    act ("You buy $p.", obj, NULL, TO_CHAR);
    gold -= cost;
    keeper->gold += cost;

    if (IS_SET (obj->extra_flags, ITEM_INVENTORY))
      obj = obj->pIndexData->create_object(obj->level);
    else
      obj->obj_from_char ();

    obj->obj_to_char (this);
    return;
  }
}

void Character::do_list (std::string argument)
{
  char buf[MAX_STRING_LENGTH];
  std::string buf1;

  if (IS_SET (in_room->room_flags, ROOM_PET_SHOP)) {
    Room *pRoomIndexNext;
    bool found;

    pRoomIndexNext = get_room_index (in_room->vnum + 1);
    if (pRoomIndexNext == NULL) {
      bug_printf ("Do_list: bad pet shop at vnum %d.", in_room->vnum);
      send_to_char ("You can't do that here.\r\n");
      return;
    }

    found = false;
    CharIter pet;
    for (pet = pRoomIndexNext->people.begin(); pet != pRoomIndexNext->people.end(); pet++) {
      if (IS_SET ((*pet)->actflags, ACT_PET)) {
        if (!found) {
          found = true;
          buf1.append("Pets for sale:\r\n");
        }
        snprintf (buf, sizeof buf, "[%2d] %8d - %s\r\n",
          (*pet)->level, 10 * (*pet)->level * (*pet)->level, (*pet)->short_descr.c_str());
        buf1.append(buf);
      }
    }
    if (!found)
      send_to_char ("Sorry, we're out of pets right now.\r\n");

    send_to_char (buf1);
    return;
  } else {
    std::string arg;
    Character *keeper;
    Object *obj;
    int cost;
    bool found;

    one_argument (argument, arg);

    if ((keeper = find_keeper (this)) == NULL)
      return;

    found = false;
    ObjIter o;
    for (o = keeper->carrying.begin(); o != keeper->carrying.end(); o++) {
      obj = *o;
      if (obj->wear_loc == WEAR_NONE && can_see_obj(obj)
        && (cost = get_cost (keeper, obj, true)) > 0
        && (arg.empty() || is_name (arg, obj->name))) {
        if (!found) {
          found = true;
          buf1.append("[Lv Price] Item\r\n");
        }

        snprintf (buf, sizeof buf, "[%2d %5d] %s.\r\n",
          obj->level, cost, capitalize (obj->short_descr).c_str());
        buf1.append(buf);
      }
    }

    if (!found) {
      if (arg.empty())
        send_to_char ("You can't buy anything here.\r\n");
      else
        send_to_char ("You can't buy that here.\r\n");
      return;
    }

    send_to_char (buf1);
    return;
  }
}

void Character::do_sell (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Sell what?\r\n");
    return;
  }

  Character *keeper;
  if ((keeper = find_keeper (this)) == NULL)
    return;

  Object *obj;
  if ((obj = get_obj_carry (arg)) == NULL) {
    keeper->act ("$n tells you 'You don't have that item'.",
      NULL, this, TO_VICT);
    reply = keeper;
    return;
  }

  if (!can_drop_obj (obj)) {
    send_to_char ("You can't let go of it.\r\n");
    return;
  }

  int cost;
  if ((cost = get_cost (keeper, obj, false)) <= 0) {
    keeper->act ("$n looks uninterested in $p.", obj, this, TO_VICT);
    return;
  }

  char buf[MAX_STRING_LENGTH];
  act ("$n sells $p.", obj, NULL, TO_ROOM);
  snprintf (buf, sizeof buf, "You sell $p for %d gold piece%s.",
    cost, cost == 1 ? "" : "s");
  act (buf, obj, NULL, TO_CHAR);
  gold += cost;
  keeper->gold -= cost;
  if (keeper->gold < 0)
    keeper->gold = 0;

  if (obj->item_type == ITEM_TRASH) {
    obj->extract_obj ();
  } else {
    obj->obj_from_char ();
    obj->obj_to_char (keeper);
  }

  return;
}

void Character::do_value (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Value what?\r\n");
    return;
  }

  Character *keeper;
  if ((keeper = find_keeper (this)) == NULL)
    return;

  Object *obj;
  if ((obj = get_obj_carry (arg)) == NULL) {
    keeper->act ("$n tells you 'You don't have that item'.",
      NULL, this, TO_VICT);
    reply = keeper;
    return;
  }

  if (!can_drop_obj (obj)) {
    send_to_char ("You can't let go of it.\r\n");
    return;
  }

  int cost;
  if ((cost = get_cost (keeper, obj, false)) <= 0) {
    keeper->act ("$n looks uninterested in $p.", obj, this, TO_VICT);
    return;
  }

  char buf[MAX_STRING_LENGTH];
  snprintf (buf, sizeof buf, "$n tells you 'I'll give you %d gold coins for $p'.", cost);
  keeper->act (buf, obj, this, TO_VICT);
  reply = keeper;

  return;
}

void Character::do_wizhelp (std::string argument)
{
  char buf[MAX_STRING_LENGTH];
  std::string buf1;

  int col = 0;
  for (int cmd = 0; cmd_table[cmd].name[0] != '\0'; cmd++) {
    if (cmd_table[cmd].level >= LEVEL_HERO
      && cmd_table[cmd].level <= get_trust ()) {
      snprintf (buf, sizeof buf, "%-12s", cmd_table[cmd].name);
      buf1.append(buf);
      if (++col % 6 == 0)
        buf1.append("\r\n");
    }
  }

  if (col % 6 != 0)
    buf1.append("\r\n");
  send_to_char (buf1);
  return;
}

void Character::do_bamfin (std::string argument)
{
  if (!is_npc ()) {
    smash_tilde (argument);
    pcdata->bamfin = argument;
    send_to_char ("Ok.\r\n");
  }
  return;
}

void Character::do_bamfout (std::string argument)
{
  if (!is_npc ()) {
    smash_tilde (argument);
    pcdata->bamfout = argument;
    send_to_char ("Ok.\r\n");
  }
  return;
}

void Character::do_deny (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);
  if (arg.empty()) {
    send_to_char ("Deny whom?\r\n");
    return;
  }

  Character *victim;
  if ((victim = get_char_world (arg)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (victim->is_npc ()) {
    send_to_char ("Not on NPC's.\r\n");
    return;
  }

  if (victim->get_trust () >= get_trust ()) {
    send_to_char ("You failed.\r\n");
    return;
  }

  SET_BIT (victim->actflags, PLR_DENY);
  victim->send_to_char ("You are denied access!\r\n");
  send_to_char ("OK.\r\n");
  victim->do_quit ("");

  return;
}

void Character::do_disconnect (std::string argument)
{
  // :WARNING: There is a bug in this routine!  The mud will crash if you
  // disconnect the descriptor that immediately follows yours in
  // descriptor_list.  close_socket() invalidates the iterator in
  // 'process input' in game_loop.
  // FIXED by adding deepdenext iterator

  std::string arg;

  one_argument (argument, arg);
  if (arg.empty()) {
    send_to_char ("Disconnect whom?\r\n");
    return;
  }

  Character *victim;
  if ((victim = get_char_world (arg)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (victim->desc == NULL) {
    act ("$N doesn't have a descriptor.", NULL, victim, TO_CHAR);
    return;
  }

  DescIter d = find(descriptor_list.begin(),descriptor_list.end(),victim->desc);
  if (d != descriptor_list.end()) {
    (*d)->close_socket();
    send_to_char ("Ok.\r\n");
    return;
  }

  bug_printf ("Do_disconnect: desc not found.");
  send_to_char ("Descriptor not found!\r\n");
  return;
}

void Character::do_pardon (std::string argument)
{
  std::string arg1, arg2;

  argument = one_argument (argument, arg1);
  argument = one_argument (argument, arg2);

  if (arg1.empty() || arg2.empty()) {
    send_to_char ("Syntax: pardon <character> <killer|thief>.\r\n");
    return;
  }

  Character *victim;
  if ((victim = get_char_world (arg1)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (victim->is_npc ()) {
    send_to_char ("Not on NPC's.\r\n");
    return;
  }

  if (!str_cmp (arg2, "killer")) {
    if (IS_SET (victim->actflags, PLR_KILLER)) {
      REMOVE_BIT (victim->actflags, PLR_KILLER);
      send_to_char ("Killer flag removed.\r\n");
      victim->send_to_char ("You are no longer a KILLER.\r\n");
    }
    return;
  }

  if (!str_cmp (arg2, "thief")) {
    if (IS_SET (victim->actflags, PLR_THIEF)) {
      REMOVE_BIT (victim->actflags, PLR_THIEF);
      send_to_char ("Thief flag removed.\r\n");
      victim->send_to_char ("You are no longer a THIEF.\r\n");
    }
    return;
  }

  send_to_char ("Syntax: pardon <character> <killer|thief>.\r\n");
  return;
}

void Character::do_echo (std::string argument)
{
  if (argument.empty()) {
    send_to_char ("Echo what?\r\n");
    return;
  }

  for (DescIter d = descriptor_list.begin();
    d != descriptor_list.end(); d++) {
    if ((*d)->connected == CON_PLAYING) {
      (*d)->character->send_to_char (argument + "\r\n");
    }
  }

  return;
}

void Character::do_recho (std::string argument)
{
  if (argument.empty()) {
    send_to_char ("Recho what?\r\n");
    return;
  }

  for (DescIter d = descriptor_list.begin();
    d != descriptor_list.end(); d++) {
    if ((*d)->connected == CON_PLAYING && (*d)->character->in_room == in_room) {
      (*d)->character->send_to_char (argument + "\r\n");
    }
  }

  return;
}

void Character::do_transfer (std::string argument)
{
  std::string arg1, arg2;

  argument = one_argument (argument, arg1);
  argument = one_argument (argument, arg2);

  if (arg1.empty()) {
    send_to_char ("Transfer whom (and where)?\r\n");
    return;
  }

  if (!str_cmp (arg1, "all")) {
    for (DescIter d = descriptor_list.begin();
      d != descriptor_list.end(); d++) {
      if ((*d)->connected == CON_PLAYING
        && (*d)->character != this
        && (*d)->character->in_room != NULL && can_see((*d)->character)) {
        char buf[MAX_STRING_LENGTH];
        snprintf (buf, sizeof buf, "%s %s", (*d)->character->name.c_str(), arg2.c_str());
        do_transfer (buf);
      }
    }
    return;
  }

  /*
   * Thanks to Grodyn for the optional location parameter.
   */
  Room *location;
  if (arg2.empty()) {
    location = in_room;
  } else {
    if ((location = find_location (this, arg2)) == NULL) {
      send_to_char ("No such location.\r\n");
      return;
    }

    if (location->is_private()) {
      send_to_char ("That room is private right now.\r\n");
      return;
    }
  }

  Character *victim;
  if ((victim = get_char_world (arg1)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (victim->in_room == NULL) {
    send_to_char ("They are in limbo.\r\n");
    return;
  }

  if (victim->fighting != NULL)
    victim->stop_fighting(true);
  victim->act ("$n disappears in a mushroom cloud.", NULL, NULL, TO_ROOM);
  victim->char_from_room();
  victim->char_to_room(location);
  victim->act ("$n arrives from a puff of smoke.", NULL, NULL, TO_ROOM);
  if (this != victim)
    act ("$n has transferred you.", NULL, victim, TO_VICT);
  victim->do_look ("auto");
  send_to_char ("Ok.\r\n");
}

void Character::do_at (std::string argument)
{
  std::string arg;

  argument = one_argument (argument, arg);

  if (arg.empty() || argument.empty()) {
    send_to_char ("At where what?\r\n");
    return;
  }

  Room *location;
  if ((location = find_location (this, arg)) == NULL) {
    send_to_char ("No such location.\r\n");
    return;
  }

  if (location->is_private()) {
    send_to_char ("That room is private right now.\r\n");
    return;
  }

  Room* original = in_room;
  char_from_room();
  char_to_room(location);
  interpret (argument);

  /*
   * See if 'this' still exists before continuing!
   * Handles 'at XXXX quit' case.
   */
  CharIter c;
  for (c = char_list.begin(); c != char_list.end(); c++) {
    if (*c == this) {
      char_from_room();
      char_to_room(original);
      break;
    }
  }

  return;
}

void Character::do_goto (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);
  if (arg.empty()) {
    send_to_char ("Goto where?\r\n");
    return;
  }

  Room *location;
  if ((location = find_location (this, arg)) == NULL) {
    send_to_char ("No such location.\r\n");
    return;
  }

  if (location->is_private()) {
    send_to_char ("That room is private right now.\r\n");
    return;
  }

  if (fighting != NULL)
    stop_fighting (true);
  if (!IS_SET (actflags, PLR_WIZINVIS)) {
    act ("$n $T.", NULL,
      (pcdata != NULL && !pcdata->bamfout.empty())
      ? pcdata->bamfout.c_str() : "leaves in a swirling mist", TO_ROOM);
  }

  char_from_room();
  char_to_room(location);

  if (!IS_SET (actflags, PLR_WIZINVIS)) {
    act ("$n $T.", NULL,
      (pcdata != NULL && !pcdata->bamfin.empty())
      ? pcdata->bamfin.c_str() : "appears in a swirling mist", TO_ROOM);
  }

  do_look ("auto");
  return;
}

void Character::do_rstat (std::string argument)
{
  std::string arg, buf1;

  one_argument (argument, arg);

  Room* location = arg.empty() ? in_room : find_location (this, arg);
  if (location == NULL) {
    send_to_char ("No such location.\r\n");
    return;
  }

  if (in_room != location && location->is_private()) {
    send_to_char ("That room is private right now.\r\n");
    return;
  }

  char buf[MAX_STRING_LENGTH];
  snprintf (buf, sizeof buf, "Name: '%s.'\r\nArea: '%s'.\r\n",
    location->name.c_str(), location->area->name.c_str());
  buf1.append(buf);

  snprintf (buf, sizeof buf,
    "Vnum: %d.  Sector: %d.  Light: %d.\r\n",
    location->vnum, location->sector_type, location->light);
  buf1.append(buf);

  snprintf (buf, sizeof buf,
    "Room flags: %d.\r\nDescription:\r\n%s",
    location->room_flags, location->description.c_str());
  buf1.append(buf);

  if (!location->extra_descr.empty()) {
    buf1.append("Extra description keywords: '");
    std::list<ExtraDescription *>::iterator ed;
    for (ed = location->extra_descr.begin(); ed != location->extra_descr.end(); ed++) {
      buf1.append((*ed)->keyword);
      buf1.append(" ");
    }
    if (buf1[buf1.size() - 1] == ' ')
      buf1.erase(buf1.size() - 1);
    buf1.append("'.\r\n");
  }

  buf1.append("Characters:");
  std::string tmp;
  CharIter rch;
  for (rch = location->people.begin(); rch != location->people.end(); rch++) {
    buf1.append(" ");
    one_argument ((*rch)->name, tmp);
    buf1.append(buf);
  }

  buf1.append(".\r\nObjects:   ");
  ObjIter o;
  for (o = location->contents.begin(); o != location->contents.end(); o++) {
    buf1.append(" ");
    one_argument ((*o)->name, tmp);
    buf1.append(buf);
  }
  buf1.append(".\r\n");

  for (int door = 0; door <= 5; door++) {
    Exit *pexit;

    if ((pexit = location->exit[door]) != NULL) {
      snprintf (buf, sizeof buf,
        "Door: %d.  To: %d.  Key: %d.  Exit flags: %d.\r\nKeyword: '%s'.  Description: %s",
        door,
        pexit->to_room != NULL ? pexit->to_room->vnum : 0,
        pexit->key,
        pexit->exit_info,
        pexit->keyword.c_str(),
        !pexit->description.empty() ? pexit->description.c_str() : "(none).\r\n");
      buf1.append(buf);
    }
  }

  send_to_char (buf1);
  return;
}

void Character::do_ostat (std::string argument)
{
  std::string arg, buf1;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Ostat what?\r\n");
    return;
  }

  Object *obj;
  if ((obj = get_obj_world (arg)) == NULL) {
    send_to_char ("Nothing like that in hell, earth, or heaven.\r\n");
    return;
  }

  char buf[MAX_STRING_LENGTH];
  snprintf (buf, sizeof buf, "Name: %s.\r\n", obj->name.c_str());
  buf1.append(buf);

  snprintf (buf, sizeof buf, "Vnum: %d.  Type: %s.\r\n",
    obj->pIndexData->vnum, obj->item_type_name().c_str());
  buf1.append(buf);

  snprintf (buf, sizeof buf, "Short description: %s.\r\nLong description: %s\r\n",
    obj->short_descr.c_str(), obj->description.c_str());
  buf1.append(buf);

  snprintf (buf, sizeof buf, "Wear bits: %d.  Extra bits: %s.\r\n",
    obj->wear_flags, extra_bit_name (obj->extra_flags).c_str());
  buf1.append(buf);

  snprintf (buf, sizeof buf, "Number: %d/%d.  Weight: %d/%d.\r\n",
    1, obj->get_obj_number(), obj->weight, obj->get_obj_weight());
  buf1.append(buf);

  snprintf (buf, sizeof buf, "Cost: %d.  Timer: %d.  Level: %d.\r\n",
    obj->cost, obj->timer, obj->level);
  buf1.append(buf);

  snprintf (buf, sizeof buf,
    "In room: %d.  In object: %s.  Carried by: %s.  Wear_loc: %d.\r\n",
    obj->in_room == NULL ? 0 : obj->in_room->vnum,
    obj->in_obj == NULL ? "(none)" : obj->in_obj->short_descr.c_str(),
    obj->carried_by == NULL ? "(none)" : obj->carried_by->name.c_str(),
    obj->wear_loc);
  buf1.append(buf);

  snprintf (buf, sizeof buf, "Values: %d %d %d %d.\r\n",
    obj->value[0], obj->value[1], obj->value[2], obj->value[3]);
  buf1.append(buf);

  if (!obj->extra_descr.empty() || !obj->pIndexData->extra_descr.empty()) {
    buf1.append("Extra description keywords: '");
    std::list<ExtraDescription *>::iterator ed;
    for (ed = obj->extra_descr.begin(); ed != obj->extra_descr.end(); ed++) {
      buf1.append((*ed)->keyword);
      buf1.append(" ");
    }
    for (ed = obj->pIndexData->extra_descr.begin(); ed != obj->pIndexData->extra_descr.end(); ed++) {
      buf1.append((*ed)->keyword);
      buf1.append(" ");
    }
    if (buf1[buf1.size() - 1] == ' ')
      buf1.erase(buf1.size() - 1);

    buf1.append("'.\r\n");
  }

  AffIter af;
  for (af = obj->affected.begin(); af != obj->affected.end(); af++) {
    snprintf (buf, sizeof buf, "Affects %s by %d.\r\n",
      affect_loc_name ((*af)->location).c_str(), (*af)->modifier);
    buf1.append(buf);
  }

  for (af = obj->pIndexData->affected.begin(); af != obj->pIndexData->affected.end(); af++) {
    snprintf (buf, sizeof buf, "Affects %s by %d.\r\n",
      affect_loc_name ((*af)->location).c_str(), (*af)->modifier);
    buf1.append(buf);
  }

  send_to_char (buf1);
  return;
}

void Character::do_mstat (std::string argument)
{
  std::string arg, buf1;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Mstat whom?\r\n");
    return;
  }

  Character *victim;
  if ((victim = get_char_world (arg)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  char buf[MAX_STRING_LENGTH];
  snprintf (buf, sizeof buf, "Name: %s.\r\n", victim->name.c_str());
  buf1.append(buf);

  snprintf (buf, sizeof buf, "Vnum: %d.  Sex: %s.  Room: %d.\r\n",
    victim->is_npc () ? victim->pIndexData->vnum : 0,
    victim->sex == SEX_MALE ? "male" :
    victim->sex == SEX_FEMALE ? "female" : "neutral",
    victim->in_room == NULL ? 0 : victim->in_room->vnum);
  buf1.append(buf);

  snprintf (buf, sizeof buf, "Str: %d.  Int: %d.  Wis: %d.  Dex: %d.  Con: %d.\r\n",
    victim->get_curr_str(), victim->get_curr_int(),
    victim->get_curr_wis(), victim->get_curr_dex(),
    victim->get_curr_con());
  buf1.append(buf);

  snprintf (buf, sizeof buf, "Hp: %d/%d.  Mana: %d/%d.  Move: %d/%d.  Practices: %d.\r\n",
    victim->hit, victim->max_hit,
    victim->mana, victim->max_mana,
    victim->move, victim->max_move, victim->practice);
  buf1.append(buf);

  snprintf (buf, sizeof buf,
    "Lv: %d.  Class: %d.  Align: %d.  AC: %d.  Gold: %d.  Exp: %d.\r\n",
    victim->level, victim->klass, victim->alignment,
    victim->get_ac(), victim->gold, victim->exp);
  buf1.append(buf);

  snprintf (buf, sizeof buf, "Hitroll: %d.  Damroll: %d.  Position: %d.  Wimpy: %d.\r\n",
    victim->get_hitroll(), victim->get_damroll(),
    victim->position, victim->wimpy);
  buf1.append(buf);

  if (!victim->is_npc ()) {
    snprintf (buf, sizeof buf, "Page Lines: %d.\r\n", victim->pcdata->pagelen);
    buf1.append(buf);
  }

  snprintf (buf, sizeof buf, "Fighting: %s.\r\n",
    victim->fighting ? victim->fighting->name.c_str() : "(none)");
  buf1.append(buf);

  if (!victim->is_npc ()) {
    snprintf (buf, sizeof buf,
      "Thirst: %d.  Full: %d.  Drunk: %d.  Saving throw: %d.\r\n",
      victim->pcdata->condition[COND_THIRST],
      victim->pcdata->condition[COND_FULL],
      victim->pcdata->condition[COND_DRUNK], victim->saving_throw);
    buf1.append(buf);
  }

  snprintf (buf, sizeof buf, "Carry number: %d.  Carry weight: %d.\r\n",
    victim->carry_number, victim->carry_weight);
  buf1.append(buf);

  snprintf (buf, sizeof buf, "Age: %d.  Played: %d.  Timer: %d.  Act: %d.\r\n",
    victim->get_age(), (int) victim->played, victim->timer, victim->actflags);
  buf1.append(buf);

  snprintf (buf, sizeof buf, "Master: %s.  Leader: %s.  Affected by: %s.\r\n",
    victim->master ? victim->master->name.c_str() : "(none)",
    victim->leader ? victim->leader->name.c_str() : "(none)",
    affect_bit_name (victim->affected_by).c_str());
  buf1.append(buf);

  snprintf (buf, sizeof buf, "Short description: %s.\r\nLong  description: %s",
    victim->short_descr.c_str(),
    !victim->long_descr.empty() ? victim->long_descr.c_str() : "(none).\r\n");
  buf1.append(buf);

  if (victim->is_npc () && victim->spec_fun != 0)
    buf1.append("Mobile has spec fun.\r\n");

  AffIter af;
  for (af = victim->affected.begin(); af != victim->affected.end(); af++) {
    snprintf (buf, sizeof buf,
      "Spell: '%s' modifies %s by %d for %d hours with bits %s.\r\n",
      skill_table[(int) (*af)->type].name,
      affect_loc_name ((*af)->location).c_str(),
      (*af)->modifier, (*af)->duration, affect_bit_name ((*af)->bitvector).c_str()
      );
    buf1.append(buf);
  }

  send_to_char (buf1);
  return;
}

void Character::do_mfind (std::string argument)
{
  std::string arg, buf1;

  one_argument (argument, arg);
  if (arg.empty()) {
    send_to_char ("Mfind whom?\r\n");
    return;
  }

  bool fAll = !str_cmp (arg, "all");
  bool found = false;
  int nMatch = 0;
  MobPrototype *pMobIndex;
  char buf[MAX_STRING_LENGTH];

  /*
   * Yeah, so iterating over all vnum's takes 10,000 loops.
   * Get_mob_index is fast, and I don't feel like threading another link.
   * Do you?
   * -- Furey
   */
  for (int vn = 0; nMatch < MobPrototype::top_mob; vn++) {
    if ((pMobIndex = get_mob_index (vn)) != NULL) {
      nMatch++;
      if (fAll || is_name (arg, pMobIndex->player_name)) {
        found = true;
        snprintf (buf, sizeof buf, "[%5d] %s\r\n",
          pMobIndex->vnum, capitalize (pMobIndex->short_descr).c_str());
        buf1.append(buf);
      }
    }
  }

  if (!found) {
    send_to_char ("Nothing like that in hell, earth, or heaven.\r\n");
    return;
  }

  send_to_char (buf1);
  return;
}

void Character::do_ofind (std::string argument)
{
  std::string arg, buf1;

  one_argument (argument, arg);
  if (arg.empty()) {
    send_to_char ("Ofind what?\r\n");
    return;
  }

  bool fAll = !str_cmp (arg, "all");
  bool found = false;
  int nMatch = 0;
  char buf[MAX_STRING_LENGTH];
  ObjectPrototype *pObjIndex;

  /*
   * Yeah, so iterating over all vnum's takes 10,000 loops.
   * Get_obj_index is fast, and I don't feel like threading another link.
   * Do you?
   * -- Furey
   */
  for (int vn = 0; nMatch < ObjectPrototype::top_obj; vn++) {
    if ((pObjIndex = get_obj_index (vn)) != NULL) {
      nMatch++;
      if (fAll || is_name (arg, pObjIndex->name)) {
        found = true;
        snprintf (buf, sizeof buf, "[%5d] %s\r\n",
          pObjIndex->vnum, capitalize (pObjIndex->short_descr).c_str());
        buf1.append(buf);
      }
    }
  }

  if (!found) {
    send_to_char ("Nothing like that in hell, earth, or heaven.\r\n");
    return;
  }

  send_to_char (buf1);
  return;
}

void Character::do_mwhere (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);
  if (arg.empty()) {
    send_to_char ("Mwhere whom?\r\n");
    return;
  }

  char buf[MAX_STRING_LENGTH];
  bool found = false;
  for (CharIter c = char_list.begin(); c != char_list.end(); c++) {
    if ((*c)->is_npc ()
      && (*c)->in_room != NULL && is_name (arg, (*c)->name)) {
      found = true;
      snprintf (buf, sizeof buf, "[%5d] %-28s [%5d] %s\r\n",
        (*c)->pIndexData->vnum,
        (*c)->short_descr.c_str(), (*c)->in_room->vnum, (*c)->in_room->name.c_str());
      send_to_char (buf);
    }
  }

  if (!found) {
    act ("You didn't find any $T.", NULL, arg.c_str(), TO_CHAR);
    return;
  }

  return;
}

void Character::do_reboo (std::string argument)
{
  send_to_char ("If you want to REBOOT, spell it out.\r\n");
  return;
}

void Character::do_reboot (std::string argument)
{
  std::string buf("Reboot by ");

  buf.append(name);
  buf.append(".\r\n");
  do_echo (buf);
  merc_down = true;
  return;
}

void Character::do_shutdow (std::string argument)
{
  send_to_char ("If you want to SHUTDOWN, spell it out.\r\n");
  return;
}

void Character::do_shutdown (std::string argument)
{
  std::string buf("Shutdown by ");

  buf.append(name);
  buf.append(".");
  append_file (SHUTDOWN_FILE, buf);
  buf.append("\r\n");
  do_echo (buf);
  merc_down = true;
  return;
}

void Character::do_switch (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Switch into whom?\r\n");
    return;
  }

  if (desc == NULL)
    return;

  if (desc->original != NULL) {
    send_to_char ("You are already switched.\r\n");
    return;
  }

  Character *victim;
  if ((victim = get_char_world (arg)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (victim == this) {
    send_to_char ("Ok.\r\n");
    return;
  }

  /*
   * Pointed out by Da Pub (What Mud)
   */
  if (!victim->is_npc ()) {
    send_to_char ("You cannot switch into a player!\r\n");
    return;
  }

  if (victim->desc != NULL) {
    send_to_char ("Character in use.\r\n");
    return;
  }

  desc->character = victim;
  desc->original = this;
  victim->desc = desc;
  desc = NULL;
  victim->send_to_char ("Ok.\r\n");
  return;
}

void Character::do_return (std::string argument)
{
  if (desc == NULL)
    return;

  if (desc->original == NULL) {
    send_to_char ("You aren't switched.\r\n");
    return;
  }

  send_to_char ("You return to your original body.\r\n");
  desc->character = desc->original;
  desc->original = NULL;
  desc->character->desc = desc;
  desc = NULL;
  return;
}

void Character::do_mload (std::string argument)
{
  std::string arg;
  MobPrototype *pMobIndex;
  Character *victim;

  one_argument (argument, arg);

  if (arg.empty() || !is_number (arg)) {
    send_to_char ("Syntax: mload <vnum>.\r\n");
    return;
  }

  if ((pMobIndex = get_mob_index (atoi (arg.c_str()))) == NULL) {
    send_to_char ("No mob has that vnum.\r\n");
    return;
  }

  victim = pMobIndex->create_mobile ();
  victim->char_to_room(in_room);
  act ("$n has created $N!", NULL, victim, TO_ROOM);
  send_to_char ("Ok.\r\n");
  return;
}

void Character::do_oload (std::string argument)
{
  std::string arg1, arg2;

  argument = one_argument (argument, arg1);
  argument = one_argument (argument, arg2);

  if (arg1.empty() || !is_number (arg1)) {
    send_to_char ("Syntax: oload <vnum> <level>.\r\n");
    return;
  }

  int lvl;
  if (arg2.empty()) {
    lvl = get_trust ();
  } else {
    /*
     * New feature from Alander.
     */
    if (!is_number (arg2)) {
      send_to_char ("Syntax: oload <vnum> <level>.\r\n");
      return;
    }
    lvl = atoi (arg2.c_str());
    if (lvl < 0 || lvl > get_trust ()) {
      send_to_char ("Limited to your trust level.\r\n");
      return;
    }
  }

  ObjectPrototype *pObjIndex;
  if ((pObjIndex = get_obj_index (atoi (arg1.c_str()))) == NULL) {
    send_to_char ("No object has that vnum.\r\n");
    return;
  }

  Object *obj = pObjIndex->create_object(lvl);
  if (obj->can_wear(ITEM_TAKE)) {
    obj->obj_to_char (this);
  } else {
    obj->obj_to_room (in_room);
    act ("$n has created $p!", obj, NULL, TO_ROOM);
  }
  send_to_char ("Ok.\r\n");
  return;
}

void Character::do_purge (std::string argument)
{
  std::string arg;
  Character *victim;
  Object *obj;

  one_argument (argument, arg);

  if (arg.empty()) {
    /* 'purge' */

    CharIter rch, rnext;
    for (rch = in_room->people.begin(); rch != in_room->people.end(); rch = rnext) {
      victim = *rch;
      rnext = ++rch;
      if (victim->is_npc () && victim != this)
        victim->extract_char (true);
    }

    ObjIter o, onext;
    for (o = in_room->contents.begin(); o != in_room->contents.end(); o = onext) {
      obj = *o;
      onext = ++o;
      obj->extract_obj ();
    }

    act ("$n purges the room!", NULL, NULL, TO_ROOM);
    send_to_char ("Ok.\r\n");
    return;
  }

  if ((victim = get_char_world (arg)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (!victim->is_npc ()) {
    send_to_char ("Not on PC's.\r\n");
    return;
  }

  act ("$n purges $N.", NULL, victim, TO_NOTVICT);
  victim->extract_char (true);
  return;
}

void Character::do_advance (std::string argument)
{
  std::string arg1, arg2;
  Character *victim;
  int lvl;

  argument = one_argument (argument, arg1);
  argument = one_argument (argument, arg2);

  if (arg1.empty() || arg2.empty() || !is_number (arg2)) {
    send_to_char ("Syntax: advance <char> <level>.\r\n");
    return;
  }

  if ((victim = get_char_room (arg1)) == NULL) {
    send_to_char ("That player is not here.\r\n");
    return;
  }

  if (victim->is_npc ()) {
    send_to_char ("Not on NPC's.\r\n");
    return;
  }

  if ((lvl = atoi (arg2.c_str())) < 1 || lvl > 40) {
    send_to_char ("Level must be 1 to 40.\r\n");
    return;
  }

  if (lvl > get_trust ()) {
    send_to_char ("Limited to your trust level.\r\n");
    return;
  }

  /*
   * Lower level:
   *   Reset to level 1.
   *   Then raise again.
   *   Currently, an imp can lower another imp.
   *   -- Swiftest
   */
  if (lvl <= victim->level) {
    int sn;

    send_to_char ("Lowering a player's level!\r\n");
    victim->send_to_char ("**** OOOOHHHHHHHHHH  NNNNOOOO ****\r\n");
    victim->level = 1;
    victim->exp = 1000;
    victim->max_hit = 10;
    victim->max_mana = 100;
    victim->max_move = 100;
    for (sn = 0; sn < MAX_SKILL; sn++)
      victim->pcdata->learned[sn] = 0;
    victim->practice = 0;
    victim->hit = victim->max_hit;
    victim->mana = victim->max_mana;
    victim->move = victim->max_move;
    victim->advance_level();
  } else {
    send_to_char ("Raising a player's level!\r\n");
    victim->send_to_char ("**** OOOOHHHHHHHHHH  YYYYEEEESSS ****\r\n");
  }

  for (int iLevel = victim->level; iLevel < lvl; iLevel++) {
    victim->send_to_char ("You raise a level!!  ");
    victim->level += 1;
    victim->advance_level();
  }
  victim->exp = 1000 * std::max (1, victim->level);
  victim->trust = 0;
  return;
}

void Character::do_trust (std::string argument)
{
  std::string arg1, arg2;
  Character *victim;
  int lvl;

  argument = one_argument (argument, arg1);
  argument = one_argument (argument, arg2);

  if (arg1.empty() || arg2.empty() || !is_number (arg2)) {
    send_to_char ("Syntax: trust <char> <level>.\r\n");
    return;
  }

  if ((victim = get_char_room (arg1)) == NULL) {
    send_to_char ("That player is not here.\r\n");
    return;
  }

  if ((lvl = atoi (arg2.c_str())) < 0 || lvl > 40) {
    send_to_char ("Level must be 0 (reset) or 1 to 40.\r\n");
    return;
  }

  if (lvl > get_trust ()) {
    send_to_char ("Limited to your trust.\r\n");
    return;
  }

  victim->trust = lvl;
  return;
}

void Character::do_restore (std::string argument)
{
  std::string arg;
  Character *victim;

  one_argument (argument, arg);
  if (arg.empty()) {
    send_to_char ("Restore whom?\r\n");
    return;
  }

  if ((victim = get_char_world (arg)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  victim->hit = victim->max_hit;
  victim->mana = victim->max_mana;
  victim->move = victim->max_move;
  victim->update_pos();
  act ("$n has restored you.", NULL, victim, TO_VICT);
  send_to_char ("Ok.\r\n");
  return;
}

void Character::do_freeze (std::string argument)
{
  std::string arg;
  Character *victim;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Freeze whom?\r\n");
    return;
  }

  if ((victim = get_char_world (arg)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (victim->is_npc ()) {
    send_to_char ("Not on NPC's.\r\n");
    return;
  }

  if (victim->get_trust () >= get_trust ()) {
    send_to_char ("You failed.\r\n");
    return;
  }

  if (IS_SET (victim->actflags, PLR_FREEZE)) {
    REMOVE_BIT (victim->actflags, PLR_FREEZE);
    victim->send_to_char ("You can play again.\r\n");
    send_to_char ("FREEZE removed.\r\n");
  } else {
    SET_BIT (victim->actflags, PLR_FREEZE);
    victim->send_to_char ("You can't do ANYthing!\r\n");
    send_to_char ("FREEZE set.\r\n");
  }

  victim->save_char_obj();

  return;
}

void Character::do_noemote (std::string argument)
{
  std::string arg;
  Character *victim;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Noemote whom?\r\n");
    return;
  }

  if ((victim = get_char_world (arg)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (victim->is_npc ()) {
    send_to_char ("Not on NPC's.\r\n");
    return;
  }

  if (victim->get_trust () >= get_trust ()) {
    send_to_char ("You failed.\r\n");
    return;
  }

  if (IS_SET (victim->actflags, PLR_NO_EMOTE)) {
    REMOVE_BIT (victim->actflags, PLR_NO_EMOTE);
    victim->send_to_char ("You can emote again.\r\n");
    send_to_char ("NO_EMOTE removed.\r\n");
  } else {
    SET_BIT (victim->actflags, PLR_NO_EMOTE);
    victim->send_to_char ("You can't emote!\r\n");
    send_to_char ("NO_EMOTE set.\r\n");
  }

  return;
}

void Character::do_notell (std::string argument)
{
  std::string arg;
  Character *victim;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Notell whom?");
    return;
  }

  if ((victim = get_char_world (arg)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (victim->is_npc ()) {
    send_to_char ("Not on NPC's.\r\n");
    return;
  }

  if (victim->get_trust () >= get_trust ()) {
    send_to_char ("You failed.\r\n");
    return;
  }

  if (IS_SET (victim->actflags, PLR_NO_TELL)) {
    REMOVE_BIT (victim->actflags, PLR_NO_TELL);
    victim->send_to_char ("You can tell again.\r\n");
    send_to_char ("NO_TELL removed.\r\n");
  } else {
    SET_BIT (victim->actflags, PLR_NO_TELL);
    victim->send_to_char ("You can't tell!\r\n");
    send_to_char ("NO_TELL set.\r\n");
  }

  return;
}

void Character::do_silence (std::string argument)
{
  std::string arg;
  Character *victim;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Silence whom?");
    return;
  }

  if ((victim = get_char_world (arg)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (victim->is_npc ()) {
    send_to_char ("Not on NPC's.\r\n");
    return;
  }

  if (victim->get_trust () >= get_trust ()) {
    send_to_char ("You failed.\r\n");
    return;
  }

  if (IS_SET (victim->actflags, PLR_SILENCE)) {
    REMOVE_BIT (victim->actflags, PLR_SILENCE);
    victim->send_to_char ("You can use channels again.\r\n");
    send_to_char ("SILENCE removed.\r\n");
  } else {
    SET_BIT (victim->actflags, PLR_SILENCE);
    victim->send_to_char ("You can't use channels!\r\n");
    send_to_char ("SILENCE set.\r\n");
  }

  return;
}

void Character::do_peace (std::string argument)
{
  CharIter rch;
  for (rch = in_room->people.begin(); rch != in_room->people.end(); rch++) {
    if ((*rch)->fighting != NULL)
      (*rch)->stop_fighting (true);
  }

  send_to_char ("Ok.\r\n");
  return;
}

void Character::do_ban (std::string argument)
{
  std::string buf;
  std::string arg;

  if (is_npc ())
    return;

  one_argument (argument, arg);

  if (arg.empty()) {
    buf = "Banned sites:\r\n";
    for (std::list<Ban*>::iterator p = ban_list.begin(); p != ban_list.end(); p++) {
      buf.append((*p)->name);
      buf.append("\r\n");
    }
    send_to_char (buf);
    return;
  }

  for (std::list<Ban*>::iterator p = ban_list.begin(); p != ban_list.end(); p++) {
    if (!str_cmp (arg, (*p)->name)) {
      send_to_char ("That site is already banned!\r\n");
      return;
    }
  }

  Ban *pban = new Ban(arg);
  ban_list.push_back(pban);
  send_to_char ("Ok.\r\n");
  return;
}

void Character::do_allow (std::string argument)
{
  std::string arg;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Remove which site from the ban list?\r\n");
    return;
  }

  std::list<Ban*>::iterator next, curr;
  for (std::list<Ban*>::iterator pban = ban_list.begin();
    pban != ban_list.end(); pban = next) {
    curr = pban;
    next = ++pban;
    if (!str_cmp (arg, (*curr)->name)) {
      delete *curr;
      ban_list.erase(curr);
      send_to_char ("Ok.\r\n");
      return;
    }
  }

  send_to_char ("Site is not banned.\r\n");
  return;
}

void Character::do_wizlock (std::string argument)
{
  wizlock = !wizlock;

  if (wizlock)
    send_to_char ("Game wizlocked.\r\n");
  else
    send_to_char ("Game un-wizlocked.\r\n");

  return;
}

void Character::do_slookup (std::string argument)
{
  char buf[MAX_STRING_LENGTH];
  std::string arg;
  int sn;

  one_argument (argument, arg);
  if (arg.empty()) {
    send_to_char ("Slookup what?\r\n");
    return;
  }

  if (!str_cmp (arg, "all")) {
    std::string buf1;
    for (sn = 0; sn < MAX_SKILL; sn++) {
      if (skill_table[sn].name == NULL)
        break;
      snprintf (buf, sizeof buf, "Sn: %4d Slot: %4d Skill/spell: '%s'\r\n",
        sn, skill_table[sn].slot, skill_table[sn].name);
      buf1.append(buf);
    }
    send_to_char (buf1);
  } else {
    if ((sn = skill_lookup (arg)) < 0) {
      send_to_char ("No such skill or spell.\r\n");
      return;
    }

    snprintf (buf, sizeof buf, "Sn: %4d Slot: %4d Skill/spell: '%s'\r\n",
      sn, skill_table[sn].slot, skill_table[sn].name);
    send_to_char (buf);
  }

  return;
}

void Character::do_sset (std::string argument)
{
  std::string arg1, arg2, arg3;
  Character *victim;
  int value;
  int sn;
  bool fAll;

  argument = one_argument (argument, arg1);
  argument = one_argument (argument, arg2);
  argument = one_argument (argument, arg3);

  if (arg1.empty() || arg2.empty() || arg3.empty()) {
    send_to_char ("Syntax: sset <victim> <skill> <value>\r\n");
    send_to_char ("or:     sset <victim> all     <value>\r\n");
    send_to_char ("Skill being any skill or spell.\r\n");
    return;
  }

  if ((victim = get_char_world (arg1)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (victim->is_npc ()) {
    send_to_char ("Not on NPC's.\r\n");
    return;
  }

  fAll = !str_cmp (arg2, "all");
  sn = 0;
  if (!fAll && (sn = skill_lookup (arg2)) < 0) {
    send_to_char ("No such skill or spell.\r\n");
    return;
  }

  /*
   * Snarf the value.
   */
  if (!is_number (arg3)) {
    send_to_char ("Value must be numeric.\r\n");
    return;
  }

  value = atoi (arg3.c_str());
  if (value < 0 || value > 100) {
    send_to_char ("Value range is 0 to 100.\r\n");
    return;
  }

  if (fAll) {
    for (sn = 0; sn < MAX_SKILL; sn++) {
      if (skill_table[sn].name != NULL)
        victim->pcdata->learned[sn] = value;
    }
  } else {
    victim->pcdata->learned[sn] = value;
  }

  return;
}

void Character::do_mset (std::string argument)
{
  std::string arg1, arg2, arg3;
  char buf[MAX_STRING_LENGTH];
  Character *victim;
  int value, max;

  smash_tilde (argument);
  argument = one_argument (argument, arg1);
  argument = one_argument (argument, arg2);
  arg3 = argument;

  if (arg1.empty() || arg2.empty() || arg3.empty()) {
    send_to_char ("Syntax: mset <victim> <field>  <value>\r\n");
    send_to_char ("or:     mset <victim> <string> <value>\r\n");
    send_to_char ("\r\n");
    send_to_char ("Field being one of:\r\n");
    send_to_char ("  str int wis dex con sex class level\r\n");
    send_to_char ("  gold hp mana move practice align\r\n");
    send_to_char ("  thirst drunk full");
    send_to_char ("\r\n");
    send_to_char ("String being one of:\r\n");
    send_to_char ("  name short long description title spec\r\n");
    return;
  }

  if ((victim = get_char_world (arg1)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  /*
   * Snarf the value (which need not be numeric).
   */
  value = is_number (arg3) ? atoi (arg3.c_str()) : -1;

  /*
   * Set something.
   */
  if (!str_cmp (arg2, "str")) {
    if (victim->is_npc ()) {
      send_to_char ("Not on NPC's.\r\n");
      return;
    }

    if (class_table[klass].attr_prime == APPLY_STR)
      max = 25;
    else
      max = 18;

    if (value < 3 || value > max) {
      snprintf (buf, sizeof buf, "Strength range is 3 to %d.\r\n", max);
      send_to_char (buf);
      return;
    }

    victim->pcdata->perm_str = value;
    return;
  }

  if (!str_cmp (arg2, "int")) {
    if (victim->is_npc ()) {
      send_to_char ("Not on NPC's.\r\n");
      return;
    }

    if (class_table[klass].attr_prime == APPLY_INT)
      max = 25;
    else
      max = 18;

    if (value < 3 || value > max) {
      snprintf (buf, sizeof buf, "Intelligence range is 3 to %d.\r\n", max);
      send_to_char (buf);
      return;
    }

    victim->pcdata->perm_int = value;
    return;
  }

  if (!str_cmp (arg2, "wis")) {
    if (victim->is_npc ()) {
      send_to_char ("Not on NPC's.\r\n");
      return;
    }

    if (class_table[klass].attr_prime == APPLY_WIS)
      max = 25;
    else
      max = 18;

    if (value < 3 || value > max) {
      snprintf (buf, sizeof buf, "Wisdom range is 3 to %d.\r\n", max);
      send_to_char (buf);
      return;
    }

    victim->pcdata->perm_wis = value;
    return;
  }

  if (!str_cmp (arg2, "dex")) {
    if (victim->is_npc ()) {
      send_to_char ("Not on NPC's.\r\n");
      return;
    }

    if (class_table[klass].attr_prime == APPLY_DEX)
      max = 25;
    else
      max = 18;

    if (value < 3 || value > max) {
      snprintf (buf, sizeof buf, "Dexterity range is 3 to %d.\r\n", max);
      send_to_char (buf);
      return;
    }

    victim->pcdata->perm_dex = value;
    return;
  }

  if (!str_cmp (arg2, "con")) {
    if (victim->is_npc ()) {
      send_to_char ("Not on NPC's.\r\n");
      return;
    }

    if (class_table[klass].attr_prime == APPLY_CON)
      max = 25;
    else
      max = 18;

    if (value < 3 || value > max) {
      snprintf (buf, sizeof buf, "Constitution range is 3 to %d.\r\n", max);
      send_to_char (buf);
      return;
    }

    victim->pcdata->perm_con = value;
    return;
  }

  if (!str_cmp (arg2, "sex")) {
    if (value < 0 || value > 2) {
      send_to_char ("Sex range is 0 to 2.\r\n");
      return;
    }
    victim->sex = value;
    return;
  }

  if (!str_cmp (arg2, "class")) {
    if (value < 0 || value >= CLASS_MAX) {
      char buf[MAX_STRING_LENGTH];

      snprintf (buf, sizeof buf, "Class range is 0 to %d.\n", CLASS_MAX - 1);
      send_to_char (buf);
      return;
    }
    victim->klass = value;
    return;
  }

  if (!str_cmp (arg2, "level")) {
    if (!victim->is_npc ()) {
      send_to_char ("Not on PC's.\r\n");
      return;
    }

    if (value < 0 || value > 50) {
      send_to_char ("Level range is 0 to 50.\r\n");
      return;
    }
    victim->level = value;
    return;
  }

  if (!str_cmp (arg2, "gold")) {
    victim->gold = value;
    return;
  }

  if (!str_cmp (arg2, "hp")) {
    if (value < -10 || value > 30000) {
      send_to_char ("Hp range is -10 to 30,000 hit points.\r\n");
      return;
    }
    victim->max_hit = value;
    return;
  }

  if (!str_cmp (arg2, "mana")) {
    if (value < 0 || value > 30000) {
      send_to_char ("Mana range is 0 to 30,000 mana points.\r\n");
      return;
    }
    victim->max_mana = value;
    return;
  }

  if (!str_cmp (arg2, "move")) {
    if (value < 0 || value > 30000) {
      send_to_char ("Move range is 0 to 30,000 move points.\r\n");
      return;
    }
    victim->max_move = value;
    return;
  }

  if (!str_cmp (arg2, "practice")) {
    if (value < 0 || value > 100) {
      send_to_char ("Practice range is 0 to 100 sessions.\r\n");
      return;
    }
    victim->practice = value;
    return;
  }

  if (!str_cmp (arg2, "align")) {
    if (value < -1000 || value > 1000) {
      send_to_char ("Alignment range is -1000 to 1000.\r\n");
      return;
    }
    victim->alignment = value;
    return;
  }

  if (!str_cmp (arg2, "thirst")) {
    if (victim->is_npc ()) {
      send_to_char ("Not on NPC's.\r\n");
      return;
    }

    if (value < 0 || value > 100) {
      send_to_char ("Thirst range is 0 to 100.\r\n");
      return;
    }

    victim->pcdata->condition[COND_THIRST] = value;
    return;
  }

  if (!str_cmp (arg2, "drunk")) {
    if (victim->is_npc ()) {
      send_to_char ("Not on NPC's.\r\n");
      return;
    }

    if (value < 0 || value > 100) {
      send_to_char ("Drunk range is 0 to 100.\r\n");
      return;
    }

    victim->pcdata->condition[COND_DRUNK] = value;
    return;
  }

  if (!str_cmp (arg2, "full")) {
    if (victim->is_npc ()) {
      send_to_char ("Not on NPC's.\r\n");
      return;
    }

    if (value < 0 || value > 100) {
      send_to_char ("Full range is 0 to 100.\r\n");
      return;
    }

    victim->pcdata->condition[COND_FULL] = value;
    return;
  }

  if (!str_cmp (arg2, "name")) {
    if (!victim->is_npc ()) {
      send_to_char ("Not on PC's.\r\n");
      return;
    }

    victim->name = arg3;
    return;
  }

  if (!str_cmp (arg2, "short")) {
    victim->short_descr = arg3;
    return;
  }

  if (!str_cmp (arg2, "long")) {
    victim->long_descr = arg3;
    return;
  }

  if (!str_cmp (arg2, "title")) {
    if (victim->is_npc ()) {
      send_to_char ("Not on NPC's.\r\n");
      return;
    }

    victim->set_title(arg3);
    return;
  }

  if (!str_cmp (arg2, "spec")) {
    if (!victim->is_npc ()) {
      send_to_char ("Not on PC's.\r\n");
      return;
    }

    if ((victim->spec_fun = spec_lookup (arg3)) == 0) {
      send_to_char ("No such spec fun.\r\n");
      return;
    }

    return;
  }

  /*
   * Generate usage message.
   */
  do_mset ("");
  return;
}

void Character::do_oset (std::string argument)
{
  std::string arg1, arg2, arg3;
  Object *obj;
  int value;

  smash_tilde (argument);
  argument = one_argument (argument, arg1);
  argument = one_argument (argument, arg2);
  arg3 = argument;

  if (arg1.empty() || arg2.empty() || arg3.empty()) {
    send_to_char ("Syntax: oset <object> <field>  <value>\r\n");
    send_to_char ("or:     oset <object> <string> <value>\r\n");
    send_to_char ("\r\n");
    send_to_char ("Field being one of:\r\n");
    send_to_char ("  value0 value1 value2 value3\r\n");
    send_to_char ("  extra wear level weight cost timer\r\n");
    send_to_char ("\r\n");
    send_to_char ("String being one of:\r\n");
    send_to_char ("  name short long ed\r\n");
    return;
  }

  if ((obj = get_obj_world (arg1)) == NULL) {
    send_to_char ("Nothing like that in hell, earth, or heaven.\r\n");
    return;
  }

  /*
   * Snarf the value (which need not be numeric).
   */
  value = atoi (arg3.c_str());

  /*
   * Set something.
   */
  if (!str_cmp (arg2, "value0") || !str_cmp (arg2, "v0")) {
    obj->value[0] = value;
    return;
  }

  if (!str_cmp (arg2, "value1") || !str_cmp (arg2, "v1")) {
    obj->value[1] = value;
    return;
  }

  if (!str_cmp (arg2, "value2") || !str_cmp (arg2, "v2")) {
    obj->value[2] = value;
    return;
  }

  if (!str_cmp (arg2, "value3") || !str_cmp (arg2, "v3")) {
    obj->value[3] = value;
    return;
  }

  if (!str_cmp (arg2, "extra")) {
    obj->extra_flags = value;
    return;
  }

  if (!str_cmp (arg2, "wear")) {
    obj->wear_flags = value;
    return;
  }

  if (!str_cmp (arg2, "level")) {
    obj->level = value;
    return;
  }

  if (!str_cmp (arg2, "weight")) {
    obj->weight = value;
    return;
  }

  if (!str_cmp (arg2, "cost")) {
    obj->cost = value;
    return;
  }

  if (!str_cmp (arg2, "timer")) {
    obj->timer = value;
    return;
  }

  if (!str_cmp (arg2, "name")) {
    obj->name = arg3;
    return;
  }

  if (!str_cmp (arg2, "short")) {
    obj->short_descr = arg3;
    return;
  }

  if (!str_cmp (arg2, "long")) {
    obj->description = arg3;
    return;
  }

  if (!str_cmp (arg2, "ed")) {
    ExtraDescription *ed;

    argument = one_argument (argument, arg3);
    if (argument.empty()) {
      send_to_char ("Syntax: oset <object> ed <keyword> <string>\r\n");
      return;
    }

    ed = new ExtraDescription();

    ed->keyword = arg3;
    ed->description = argument;
    obj->extra_descr.push_back(ed);
    return;
  }

  /*
   * Generate usage message.
   */
  do_oset ("");
  return;
}

void Character::do_rset (std::string argument)
{
  std::string arg1, arg2, arg3;
  Room *location;
  int value;

  smash_tilde (argument);
  argument = one_argument (argument, arg1);
  argument = one_argument (argument, arg2);
  arg3 = argument;

  if (arg1.empty() || arg2.empty() || arg3.empty()) {
    send_to_char ("Syntax: rset <location> <field> value\r\n");
    send_to_char ("\r\n");
    send_to_char ("Field being one of:\r\n");
    send_to_char ("  flags sector\r\n");
    return;
  }

  if ((location = find_location (this, arg1)) == NULL) {
    send_to_char ("No such location.\r\n");
    return;
  }

  /*
   * Snarf the value.
   */
  if (!is_number (arg3)) {
    send_to_char ("Value must be numeric.\r\n");
    return;
  }
  value = atoi (arg3.c_str());

  /*
   * Set something.
   */
  if (!str_cmp (arg2, "flags")) {
    location->room_flags = value;
    return;
  }

  if (!str_cmp (arg2, "sector")) {
    location->sector_type = value;
    return;
  }

  /*
   * Generate usage message.
   */
  do_rset ("");
  return;
}

void Character::do_users (std::string argument)
{
  char buf[MAX_STRING_LENGTH];
  char buf2[MAX_STRING_LENGTH];
  int count;

  count = 0;
  buf[0] = '\0';
  buf2[0] = '\0';
  for (DescIter d = descriptor_list.begin();
    d != descriptor_list.end(); d++) {
    if ((*d)->character != NULL && can_see((*d)->character)) {
      count++;
      snprintf (buf + strlen(buf), sizeof(buf) - strlen(buf), "[%3d %2d] %s@%s\r\n",
        (*d)->descriptor,
        (*d)->connected,
        (*d)->original ? (*d)->original->name.c_str() :
        (*d)->character ? (*d)->character->name.c_str() : "(none)", (*d)->host.c_str());
    }
  }

  snprintf (buf2, sizeof buf2, "%d user%s\r\n", count, count == 1 ? "" : "s");
  strncat (buf, buf2, sizeof buf - sizeof buf2);
  send_to_char (buf);
  return;
}

/*
 * Thanks to Grodyn for pointing out bugs in this function.
 */
void Character::do_force (std::string argument)
{
  std::string arg;
  int trst;
  int cmd;

  argument = one_argument (argument, arg);

  if (arg.empty() || argument.empty()) {
    send_to_char ("Force whom to do what?\r\n");
    return;
  }

  /*
   * Look for command in command table.
   */
  trst = get_trust ();
  for (cmd = 0; cmd_table[cmd].name[0] != '\0'; cmd++) {
    if (argument[0] == cmd_table[cmd].name[0]
      && !str_prefix (argument, cmd_table[cmd].name)
      && (cmd_table[cmd].level > trst && cmd_table[cmd].level != 41)) {
      send_to_char ("You cant even do that yourself!\r\n");
      return;
    }
  }

  if (!str_cmp (arg, "all")) {
    Character *vch;
    CharIter c, next;
    for (c = char_list.begin(); c != char_list.end(); c = next) {
      vch = *c;
      next = ++c;
      if (!vch->is_npc () && vch->get_trust () < get_trust ()) {
        MOBtrigger = false;
        act ("$n forces you to '$t'.", argument.c_str(), vch, TO_VICT);
        vch->interpret (argument);
      }
    }
  } else {
    Character *victim;

    if ((victim = get_char_world (arg)) == NULL) {
      send_to_char ("They aren't here.\r\n");
      return;
    }

    if (victim == this) {
      send_to_char ("Aye aye, right away!\r\n");
      return;
    }

    if (victim->get_trust () >= get_trust ()) {
      send_to_char ("Do it yourself!\r\n");
      return;
    }

    MOBtrigger = false;
    act ("$n forces you to '$t'.", argument.c_str(), victim, TO_VICT);
    victim->interpret (argument);
  }

  send_to_char ("Ok.\r\n");
  return;
}

/*
 * New routines by Dionysos.
 */
void Character::do_invis (std::string argument)
{
  if (is_npc ())
    return;

  if (IS_SET (actflags, PLR_WIZINVIS)) {
    REMOVE_BIT (actflags, PLR_WIZINVIS);
    act ("$n slowly fades into existence.", NULL, NULL, TO_ROOM);
    send_to_char ("You slowly fade back into existence.\r\n");
  } else {
    SET_BIT (actflags, PLR_WIZINVIS);
    act ("$n slowly fades into thin air.", NULL, NULL, TO_ROOM);
    send_to_char ("You slowly vanish into thin air.\r\n");
  }

  return;
}

void Character::do_holylight (std::string argument)
{
  if (is_npc ())
    return;

  if (IS_SET (actflags, PLR_HOLYLIGHT)) {
    REMOVE_BIT (actflags, PLR_HOLYLIGHT);
    send_to_char ("Holy light mode off.\r\n");
  } else {
    SET_BIT (actflags, PLR_HOLYLIGHT);
    send_to_char ("Holy light mode on.\r\n");
  }

  return;
}

/* Wizify and Wizbit sent in by M. B. King */
void Character::do_wizify (std::string argument)
{
  std::string arg1;
  Character *victim;

  argument = one_argument (argument, arg1);
  if (arg1.empty()) {
    send_to_char ("Syntax: wizify <name>\r\n");
    return;
  }
  if ((victim = get_char_world (arg1)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }
  if (victim->is_npc ()) {
    send_to_char ("Not on mobs.\r\n");
    return;
  }
  victim->wizbit = !victim->wizbit;
  if (victim->wizbit) {
    act ("$N wizified.\r\n", NULL, victim, TO_CHAR);
    act ("$n has wizified you!\r\n", NULL, victim, TO_VICT);
  } else {
    act ("$N dewizzed.\r\n", NULL, victim, TO_CHAR);
    act ("$n has dewizzed you!\r\n", NULL, victim, TO_VICT);
  }

  victim->do_save ("");
  return;
}

/* Idea from Talen of Vego's do_where command */
void Character::do_owhere (std::string argument)
{
  char buf[MAX_STRING_LENGTH];
  std::string arg;
  bool found = false;
  Object *in_obj;
  int obj_counter = 1;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("Syntax:  owhere <object>.\r\n");
    return;
  } else {
    ObjIter o;
    for (o = object_list.begin(); o != object_list.end(); o++) {
      if (!can_see_obj(*o) || !is_name (arg, (*o)->name))
        continue;

      found = true;

      for (in_obj = *o; in_obj->in_obj != NULL; in_obj = in_obj->in_obj);

      if (in_obj->carried_by != NULL) {
        snprintf (buf, sizeof buf, "[%2d] %s carried by %s.\r\n", obj_counter,
          (*o)->short_descr.c_str(), in_obj->carried_by->describe_to(this).c_str());
      } else {
        snprintf (buf, sizeof buf, "[%2d] %s in %s.\r\n", obj_counter,
          (*o)->short_descr.c_str(), (in_obj->in_room == NULL) ?
          "somewhere" : in_obj->in_room->name.c_str());
      }

      obj_counter++;
      buf[0] = toupper (buf[0]);
      send_to_char (buf);
    }
  }

  if (!found)
    send_to_char ("Nothing like that in hell, earth, or heaven.\r\n");

  return;
}

/* This routine transfers between alpha and numeric forms of the
 *  mob_prog bitvector types. It allows the words to show up in mpstat to
 *  make it just a hair bit easier to see what a mob should be doing.
 */
char *mprog_type_to_name (int type)
{
  switch (type) {
  case IN_FILE_PROG:
    return "in_file_prog";
  case ACT_PROG:
    return "act_prog";
  case SPEECH_PROG:
    return "speech_prog";
  case RAND_PROG:
    return "rand_prog";
  case FIGHT_PROG:
    return "fight_prog";
  case HITPRCNT_PROG:
    return "hitprcnt_prog";
  case DEATH_PROG:
    return "death_prog";
  case ENTRY_PROG:
    return "entry_prog";
  case GREET_PROG:
    return "greet_prog";
  case ALL_GREET_PROG:
    return "all_greet_prog";
  case GIVE_PROG:
    return "give_prog";
  case BRIBE_PROG:
    return "bribe_prog";
  default:
    return "ERROR_PROG";
  }
}

/* A trivial rehack of do_mstat.  This doesnt show all the data, but just
 * enough to identify the mob and give its basic condition.  It does however,
 * show the MOBprograms which are set.
 */
void Character::do_mpstat (std::string argument)
{
  char buf[MAX_STRING_LENGTH];
  std::string arg;
  MobProgram *mprg;
  Character *victim;

  one_argument (argument, arg);

  if (arg.empty()) {
    send_to_char ("MobProg stat whom?\r\n");
    return;
  }

  if ((victim = get_char_world (arg)) == NULL) {
    send_to_char ("They aren't here.\r\n");
    return;
  }

  if (!victim->is_npc ()) {
    send_to_char ("Only Mobiles can have Programs!\r\n");
    return;
  }

  if (!(victim->pIndexData->progtypes)) {
    send_to_char ("That Mobile has no Programs set.\r\n");
    return;
  }

  snprintf (buf, sizeof buf, "Name: %s.  Vnum: %d.\r\n",
    victim->name.c_str(), victim->pIndexData->vnum);
  send_to_char (buf);

  snprintf (buf, sizeof buf, "Short description: %s.\r\nLong  description: %s",
    victim->short_descr.c_str(),
    !victim->long_descr.empty() ? victim->long_descr.c_str() : "(none).\r\n");
  send_to_char (buf);

  snprintf (buf, sizeof buf, "Hp: %d/%d.  Mana: %d/%d.  Move: %d/%d. \r\n",
    victim->hit, victim->max_hit,
    victim->mana, victim->max_mana, victim->move, victim->max_move);
  send_to_char (buf);

  snprintf (buf, sizeof buf,
    "Lv: %d.  Class: %d.  Align: %d.  AC: %d.  Gold: %d.  Exp: %d.\r\n",
    victim->level, victim->klass, victim->alignment,
    victim->get_ac(), victim->gold, victim->exp);
  send_to_char (buf);

  for (mprg = victim->pIndexData->mobprogs; mprg != NULL; mprg = mprg->next) {
    snprintf (buf, sizeof buf, ">%s %s\r\n%s\r\n",
      mprog_type_to_name (mprg->type), mprg->arglist.c_str(), mprg->comlist.c_str());
    send_to_char (buf);
  }

  return;

}

/* prints the argument to all the rooms aroud the mobile */
void Character::do_mpasound (std::string argument)
{

  Room *was_in_rm;
  int door;

  if (!is_npc ()) {
    send_to_char ("Huh?\r\n");
    return;
  }

  if (argument.empty()) {
    bug_printf ("Mpasound - No argument from vnum %d.", pIndexData->vnum);
    return;
  }

  was_in_rm = in_room;
  for (door = 0; door <= 5; door++) {
    Exit *pexit;

    if ((pexit = was_in_rm->exit[door]) != NULL
      && pexit->to_room != NULL && pexit->to_room != was_in_rm) {
      in_room = pexit->to_room;
      MOBtrigger = false;
      act (argument, NULL, NULL, TO_ROOM);
    }
  }

  in_room = was_in_rm;
  return;

}

/* lets the mobile kill any player or mobile without murder*/
void Character::do_mpkill (std::string argument)
{
  std::string arg;
  Character *victim;

  if (!is_npc ()) {
    send_to_char ("Huh?\r\n");
    return;
  }

  one_argument (argument, arg);

  if (arg.empty()) {
    bug_printf ("MpKill - No argument from vnum %d.", pIndexData->vnum);
    return;
  }

  if ((victim = get_char_room (arg)) == NULL) {
    bug_printf ("MpKill - Victim not in room from vnum %d.", pIndexData->vnum);
    return;
  }

  if (victim == this) {
    bug_printf ("MpKill - Bad victim to attack from vnum %d.", pIndexData->vnum);
    return;
  }

  if (is_affected (AFF_CHARM) && master == victim) {
    bug_printf ("MpKill - Charmed mob attacking master from vnum %d.",
      pIndexData->vnum);
    return;
  }

  if (position == POS_FIGHTING) {
    bug_printf ("MpKill - Already fighting from vnum %d", pIndexData->vnum);
    return;
  }

  multi_hit (this, victim, TYPE_UNDEFINED);
  return;
}

/* lets the mobile destroy an object in its inventory
   it can also destroy a worn object and it can destroy
   items using all.xxxxx or just plain all of them */
void Character::do_mpjunk (std::string argument)
{
  std::string arg;
  Object *obj;

  if (!is_npc ()) {
    send_to_char ("Huh?\r\n");
    return;
  }

  one_argument (argument, arg);

  if (arg.empty()) {
    bug_printf ("Mpjunk - No argument from vnum %d.", pIndexData->vnum);
    return;
  }

  if (str_cmp (arg, "all") && str_prefix ("all.", arg)) {
    if ((obj = get_obj_wear (arg)) != NULL) {
      unequip_char(obj);
      obj->extract_obj ();
      return;
    }
    if ((obj = get_obj_carry (arg)) == NULL)
      return;
    obj->extract_obj ();
  } else {
    ObjIter o, onext;
    for (o = carrying.begin(); o != carrying.end(); o = onext) {
      obj = *o;
      onext = ++o;
      if (arg[3] == '\0' || is_name (&arg[4], obj->name)) {
        if (obj->wear_loc != WEAR_NONE)
          unequip_char(obj);
        obj->extract_obj ();
      }
    }
  }

  return;

}

/* prints the message to everyone in the room other than the mob and victim */
void Character::do_mpechoaround (std::string argument)
{
  std::string arg;
  Character *victim;

  if (!is_npc ()) {
    send_to_char ("Huh?\r\n");
    return;
  }

  argument = one_argument (argument, arg);

  if (arg.empty()) {
    bug_printf ("Mpechoaround - No argument from vnum %d.", pIndexData->vnum);
    return;
  }

  if (!(victim = get_char_room (arg))) {
    bug_printf ("Mpechoaround - Victim does not exist from vnum %d.",
      pIndexData->vnum);
    return;
  }

  act (argument, NULL, victim, TO_NOTVICT);
  return;
}

/* prints the message to only the victim */
void Character::do_mpechoat (std::string argument)
{
  std::string arg;
  Character *victim;

  if (!is_npc ()) {
    send_to_char ("Huh?\r\n");
    return;
  }

  argument = one_argument (argument, arg);

  if (arg.empty() || argument.empty()) {
    bug_printf ("Mpechoat - No argument from vnum %d.", pIndexData->vnum);
    return;
  }

  if (!(victim = get_char_room (arg))) {
    bug_printf ("Mpechoat - Victim does not exist from vnum %d.",
      pIndexData->vnum);
    return;
  }

  act (argument, NULL, victim, TO_VICT);
  return;
}

/* prints the message to the room at large */
void Character::do_mpecho (std::string argument)
{
  if (!is_npc ()) {
    send_to_char ("Huh?\r\n");
    return;
  }

  if (argument.empty()) {
    bug_printf ("Mpecho - Called w/o argument from vnum %d.", pIndexData->vnum);
    return;
  }

  act (argument, NULL, NULL, TO_ROOM);
  return;

}

/* lets the mobile load an item or mobile.  All items
are loaded into inventory.  you can specify a level with
the load object portion as well. */
void Character::do_mpmload (std::string argument)
{
  std::string arg;
  MobPrototype *pMobIndex;
  Character *victim;

  if (!is_npc ()) {
    send_to_char ("Huh?\r\n");
    return;
  }

  one_argument (argument, arg);

  if (arg.empty() || !is_number (arg)) {
    bug_printf ("Mpmload - Bad vnum as arg from vnum %d.", pIndexData->vnum);
    return;
  }

  if ((pMobIndex = get_mob_index (atoi (arg.c_str()))) == NULL) {
    bug_printf ("Mpmload - Bad mob vnum from vnum %d.", pIndexData->vnum);
    return;
  }

  victim = pMobIndex->create_mobile ();
  victim->char_to_room(in_room);
  return;
}

void Character::do_mpoload (std::string argument)
{
  std::string arg1, arg2;
  ObjectPrototype *pObjIndex;
  Object *obj;
  int lvl;

  if (!is_npc ()) {
    send_to_char ("Huh?\r\n");
    return;
  }

  argument = one_argument (argument, arg1);
  argument = one_argument (argument, arg2);

  if (arg1.empty() || !is_number (arg1)) {
    bug_printf ("Mpoload - Bad syntax from vnum %d.", pIndexData->vnum);
    return;
  }

  if (arg2.empty()) {
    lvl = get_trust ();
  } else {
    /*
     * New feature from Alander.
     */
    if (!is_number (arg2)) {
      bug_printf ("Mpoload - Bad syntax from vnum %d.", pIndexData->vnum);
      return;
    }
    lvl = atoi (arg2.c_str());
    if (lvl < 0 || lvl > get_trust ()) {
      bug_printf ("Mpoload - Bad level from vnum %d.", pIndexData->vnum);
      return;
    }
  }

  if ((pObjIndex = get_obj_index (atoi (arg1.c_str()))) == NULL) {
    bug_printf ("Mpoload - Bad vnum arg from vnum %d.", pIndexData->vnum);
    return;
  }

  obj = pObjIndex->create_object (lvl);
  if (obj->can_wear(ITEM_TAKE)) {
    obj->obj_to_char (this);
  } else {
    obj->obj_to_room (in_room);
  }

  return;
}

/* lets the mobile purge all objects and other npcs in the room,
   or purge a specified object or mob in the room.  It can purge
   itself, but this had best be the last command in the MOBprogram
   otherwise ugly stuff will happen */
void Character::do_mppurge (std::string argument)
{
  std::string arg;
  Character *victim;
  Object *obj;

  if (!is_npc ()) {
    send_to_char ("Huh?\r\n");
    return;
  }

  one_argument (argument, arg);

  if (arg.empty()) {
    /* 'purge' */

    CharIter rch, rnext;
    for (rch = in_room->people.begin(); rch != in_room->people.end(); rch = rnext) {
      victim = *rch;
      rnext = ++rch;
      if (victim->is_npc () && victim != this)
        victim->extract_char (true);
    }

    ObjIter o, onext;
    for (o = in_room->contents.begin(); o != in_room->contents.end(); o = onext) {
      obj = *o;
      onext = ++o;
      obj->extract_obj ();
    }

    return;
  }

  if ((victim = get_char_room (arg)) == NULL) {
    if ((obj = get_obj_here (arg))) {
      obj->extract_obj ();
    } else {
      bug_printf ("Mppurge - Bad argument from vnum %d.", pIndexData->vnum);
    }
    return;
  }

  if (!victim->is_npc ()) {
    bug_printf ("Mppurge - Purging a PC from vnum %d.", pIndexData->vnum);
    return;
  }

  victim->extract_char (true);
  return;
}

/* lets the mobile goto any location it wishes that is not private */
void Character::do_mpgoto (std::string argument)
{
  std::string arg;
  Room *location;

  if (!is_npc ()) {
    send_to_char ("Huh?\r\n");
    return;
  }

  one_argument (argument, arg);
  if (arg.empty()) {
    bug_printf ("Mpgoto - No argument from vnum %d.", pIndexData->vnum);
    return;
  }

  if ((location = find_location (this, arg)) == NULL) {
    bug_printf ("Mpgoto - No such location from vnum %d.", pIndexData->vnum);
    return;
  }

  if (fighting != NULL)
    stop_fighting (true);

  char_from_room();
  char_to_room(location);

  return;
}

/* lets the mobile do a command at another location. Very useful */
void Character::do_mpat (std::string argument)
{
  std::string arg;
  Room *location;
  Room *original;

  if (!is_npc ()) {
    send_to_char ("Huh?\r\n");
    return;
  }

  argument = one_argument (argument, arg);

  if (arg.empty() || argument.empty()) {
    bug_printf ("Mpat - Bad argument from vnum %d.", pIndexData->vnum);
    return;
  }

  if ((location = find_location (this, arg)) == NULL) {
    bug_printf ("Mpat - No such location from vnum %d.", pIndexData->vnum);
    return;
  }

  original = in_room;
  char_from_room();
  char_to_room(location);
  interpret (argument);

  /*
   * See if 'this' still exists before continuing!
   * Handles 'at XXXX quit' case.
   */
  for (CharIter c = char_list.begin(); c != char_list.end(); c++) {
    if (*c == this) {
      char_from_room();
      char_to_room(original);
      break;
    }
  }

  return;
}

/* lets the mobile transfer people.  the all argument transfers
   everyone in the current room to the specified location */
void Character::do_mptransfer (std::string argument)
{
  std::string arg1, arg2;
  Room *location;
  Character *victim;

  if (!is_npc ()) {
    send_to_char ("Huh?\r\n");
    return;
  }
  argument = one_argument (argument, arg1);
  argument = one_argument (argument, arg2);

  if (arg1.empty()) {
    bug_printf ("Mptransfer - Bad syntax from vnum %d.", pIndexData->vnum);
    return;
  }

  if (!str_cmp (arg1, "all")) {
    for (DescIter d = descriptor_list.begin(); d != descriptor_list.end(); d++) {
      if ((*d)->connected == CON_PLAYING
        && (*d)->character != this
        && (*d)->character->in_room != NULL && can_see((*d)->character)) {
        char buf[MAX_STRING_LENGTH];
        snprintf (buf, sizeof buf, "%s %s", (*d)->character->name.c_str(), arg2.c_str());
        do_transfer (buf);
      }
    }
    return;
  }

  /*
   * Thanks to Grodyn for the optional location parameter.
   */
  if (arg2.empty()) {
    location = in_room;
  } else {
    if ((location = find_location (this, arg2)) == NULL) {
      bug_printf ("Mptransfer - No such location from vnum %d.",
        pIndexData->vnum);
      return;
    }

    if (location->is_private()) {
      bug_printf ("Mptransfer - Private room from vnum %d.", pIndexData->vnum);
      return;
    }
  }

  if ((victim = get_char_world (arg1)) == NULL) {
    bug_printf ("Mptransfer - No such person from vnum %d.", pIndexData->vnum);
    return;
  }

  if (victim->in_room == NULL) {
    bug_printf ("Mptransfer - Victim in Limbo from vnum %d.", pIndexData->vnum);
    return;
  }

  if (victim->fighting != NULL)
    victim->stop_fighting (true);

  victim->char_from_room();
  victim->char_to_room(location);

  return;
}

/* lets the mobile force someone to do something.  must be mortal level
   and the all argument only affects those in the room with the mobile */
void Character::do_mpforce (std::string argument)
{
  std::string arg;

  if (!is_npc ()) {
    send_to_char ("Huh?\r\n");
    return;
  }

  argument = one_argument (argument, arg);

  if (arg.empty() || argument.empty()) {
    bug_printf ("Mpforce - Bad syntax from vnum %d.", pIndexData->vnum);
    return;
  }

  if (!str_cmp (arg, "all")) {
    Character *vch;

    CharIter c, next;
    for (c = char_list.begin(); c != char_list.end(); c = next) {
      vch = *c;
      next = ++c;
      if (vch->in_room == in_room && vch->get_trust () < get_trust ()
        && can_see(vch)) {
        vch->interpret (argument);
      }
    }
  } else {
    Character *victim;

    if ((victim = get_char_room (arg)) == NULL) {
      bug_printf ("Mpforce - No such victim from vnum %d.", pIndexData->vnum);
      return;
    }

    if (victim == this) {
      bug_printf ("Mpforce - Forcing oneself from vnum %d.", pIndexData->vnum);
      return;
    }

    victim->interpret (argument);
  }

  return;
}

/*
 * Deal with sockets that haven't logged in yet.
 */
void Descriptor::nanny (std::string argument)
{
  std::string buf;
  char cbuf[MAX_STRING_LENGTH];  // Needed for Windows crypt
  Character *ch;
  char *pwdnew;
  char *p;
  int iClass;
  int lines;
  int notes;
  bool fOld;

  incomm.erase();
  argument.erase(0, argument.find_first_not_of(" "));

  ch = character;

  switch (connected) {

  default:
    bug_printf ("Nanny: bad connected %d.", connected);
    close_socket();
    return;

  case CON_GET_NAME:
    if (argument.empty()) {
      close_socket();
      return;
    }

    argument[0] = toupper(argument[0]);
    if (!check_parse_name (argument)) {
      write_to_buffer ("Illegal name, try another.\r\nName: ");
      return;
    }

    fOld = load_char_obj (argument);
    ch = character;

    if (IS_SET (ch->actflags, PLR_DENY)) {
      log_printf ("Denying access to %s@%s.", argument.c_str(), host.c_str());
      write_to_buffer ("You are denied access.\r\n");
      close_socket();
      return;
    }

    if (check_reconnect (argument, false)) {
      fOld = true;
    } else {
      if (wizlock && !ch->is_hero() && !ch->wizbit) {
        write_to_buffer ("The game is wizlocked.\r\n");
        close_socket();
        return;
      }
    }

    if (fOld) {
      /* Old player */
      write_to_buffer ("Password: ");
      write_to_buffer (echo_off_str);
      connected = CON_GET_OLD_PASSWORD;
    } else {
      /* New player */
      /* New characters with same name fix by Salem's Lot */
      if (check_playing (ch->name))
        return;
      buf = "Did I get that right, " + argument + " (Y/N)? ";
      write_to_buffer (buf);
      connected = CON_CONFIRM_NEW_NAME;
    }
    break;

  case CON_GET_OLD_PASSWORD:
    write_to_buffer ("\r\n");

    strncpy(cbuf,argument.c_str(), sizeof cbuf);
    if (strcmp (crypt (cbuf, ch->pcdata->pwd.c_str()), ch->pcdata->pwd.c_str())) {
      write_to_buffer ("Wrong password.\r\n");
      close_socket();
      return;
    }

    write_to_buffer (echo_on_str);

    if (check_reconnect (ch->name, true))
      return;

    if (check_playing (ch->name))
      return;

    log_printf ("%s@%s has connected.", ch->name.c_str(), host.c_str());
    lines = ch->pcdata->pagelen;
    ch->pcdata->pagelen = 20;
    if (ch->is_hero())
      ch->do_help ("imotd");
    ch->do_help ("motd");
    ch->pcdata->pagelen = lines;
    connected = CON_READ_MOTD;
    break;

  case CON_CONFIRM_NEW_NAME:
    switch (argument[0]) {
    case 'y':
    case 'Y':
      buf = "New character.\r\nGive me a password for " + ch->name + ": " + echo_off_str;
      write_to_buffer (buf);
      connected = CON_GET_NEW_PASSWORD;
      break;

    case 'n':
    case 'N':
      write_to_buffer ("Ok, what IS it, then? ");
      delete character;
      character = NULL;
      connected = CON_GET_NAME;
      break;

    default:
      write_to_buffer ("Please type Yes or No? ");
      break;
    }
    break;

  case CON_GET_NEW_PASSWORD:
    write_to_buffer ("\r\n");

    if (argument.size() < 5) {
      write_to_buffer (
        "Password must be at least five characters long.\r\nPassword: ");
      return;
    }

    strncpy(cbuf,argument.c_str(), sizeof cbuf);
    pwdnew = crypt (cbuf, ch->name.c_str());
    for (p = pwdnew; *p != '\0'; p++) {
      if (*p == '~') {
        write_to_buffer (
          "New password not acceptable, try again.\r\nPassword: ");
        return;
      }
    }

    ch->pcdata->pwd = pwdnew;
    write_to_buffer ("Please retype password: ");
    connected = CON_CONFIRM_NEW_PASSWORD;
    break;

  case CON_CONFIRM_NEW_PASSWORD:
    write_to_buffer ("\r\n");

    strncpy(cbuf,argument.c_str(), sizeof cbuf);
    if (strcmp (crypt (cbuf, ch->pcdata->pwd.c_str()), ch->pcdata->pwd.c_str())) {
      write_to_buffer ("Passwords don't match.\r\nRetype password: ");
      connected = CON_GET_NEW_PASSWORD;
      return;
    }

    write_to_buffer (echo_on_str);
    write_to_buffer ("What is your sex (M/F/N)? ");
    connected = CON_GET_NEW_SEX;
    break;

  case CON_GET_NEW_SEX:
    switch (argument[0]) {
    case 'm':
    case 'M':
      ch->sex = SEX_MALE;
      break;
    case 'f':
    case 'F':
      ch->sex = SEX_FEMALE;
      break;
    case 'n':
    case 'N':
      ch->sex = SEX_NEUTRAL;
      break;
    default:
      write_to_buffer ("That's not a sex.\r\nWhat IS your sex? ");
      return;
    }

    buf = "Select a class [";
    for (iClass = 0; iClass < CLASS_MAX; iClass++) {
      if (iClass > 0)
        buf.append(" ");
      buf.append(class_table[iClass].who_name);
    }
    buf.append("]: ");
    write_to_buffer (buf);
    connected = CON_GET_NEW_CLASS;
    break;

  case CON_GET_NEW_CLASS:
    for (iClass = 0; iClass < CLASS_MAX; iClass++) {
      if (!str_cmp (argument, class_table[iClass].who_name)) {
        ch->klass = iClass;
        break;
      }
    }

    if (iClass == CLASS_MAX) {
      write_to_buffer ("That's not a class.\r\nWhat IS your class? ");
      return;
    }

    log_printf ("%s@%s new player.", ch->name.c_str(), host.c_str());
    write_to_buffer ("\r\n");
    ch->pcdata->pagelen = 20;
    ch->prompt = "<%hhp %mm %vmv> ";
    ch->do_help ("motd");
    connected = CON_READ_MOTD;
    break;

  case CON_READ_MOTD:
    char_list.push_back(ch);
    connected = CON_PLAYING;

    ch->send_to_char
      ("\r\nWelcome to Merc Diku Mud.  May your visit here be ... Mercenary.\r\n");

    if (ch->level == 0) {
      Object *obj;

      switch (class_table[ch->klass].attr_prime) {
      case APPLY_STR:
        ch->pcdata->perm_str = 16;
        break;
      case APPLY_INT:
        ch->pcdata->perm_int = 16;
        break;
      case APPLY_WIS:
        ch->pcdata->perm_wis = 16;
        break;
      case APPLY_DEX:
        ch->pcdata->perm_dex = 16;
        break;
      case APPLY_CON:
        ch->pcdata->perm_con = 16;
        break;
      }

      ch->level = 1;
      ch->exp = 1000;
      ch->hit = ch->max_hit;
      ch->mana = ch->max_mana;
      ch->move = ch->max_move;
      buf = "the ";
      buf.append(title_table[ch->klass][ch->level][ch->sex == SEX_FEMALE ? 1 : 0]);
      ch->set_title(buf);

      obj = get_obj_index(OBJ_VNUM_SCHOOL_BANNER)->create_object(0);
      obj->obj_to_char (ch);
      ch->equip_char (obj, WEAR_LIGHT);

      obj = get_obj_index(OBJ_VNUM_SCHOOL_VEST)->create_object(0);
      obj->obj_to_char (ch);
      ch->equip_char (obj, WEAR_BODY);

      obj = get_obj_index(OBJ_VNUM_SCHOOL_SHIELD)->create_object(0);
      obj->obj_to_char (ch);
      ch->equip_char (obj, WEAR_SHIELD);

      obj = get_obj_index(class_table[ch->klass].weapon)->create_object(0);
      obj->obj_to_char (ch);
      ch->equip_char (obj, WEAR_WIELD);

      ch->char_to_room(get_room_index (ROOM_VNUM_SCHOOL));
    } else if (ch->in_room != NULL) {
      ch->char_to_room(ch->in_room);
    } else if (ch->is_immortal()) {
      ch->char_to_room(get_room_index (ROOM_VNUM_CHAT));
    } else {
      ch->char_to_room(get_room_index (ROOM_VNUM_TEMPLE));
    }

    ch->act ("$n has entered the game.", NULL, NULL, TO_ROOM);
    ch->do_look ("auto");
    /* check for new notes */
    notes = 0;

    for (std::list<Note*>::iterator p = note_list.begin();
      p != note_list.end(); p++)
      if (is_note_to (ch, *p) && str_cmp (ch->name, (*p)->sender)
        && (*p)->date_stamp > ch->last_note)
        notes++;

    if (notes == 1)
      ch->send_to_char ("\r\nYou have one new note waiting.\r\n");
    else if (notes > 1) {
      buf = "\r\nYou have " + itoa(notes, 10) + " new notes waiting.\r\n";
      ch->send_to_char (buf);
    }

    break;
  }

  return;
}

/*
 * Transfer one line from input buffer to input line.
 */
void Descriptor::read_from_buffer ()
{
  int i, j, k;

  /*
   * Hold horses if pending command already.
   */
  if (!incomm.empty())
    return;

  /*
   * Look for at least one new line.
   */
  for (i = 0; inbuf[i] != '\n' && inbuf[i] != '\r'; i++) {
    if (inbuf[i] == '\0')
      return;
  }

  /*
   * Canonical input processing.
   */
  for (i = 0, k = 0; inbuf[i] != '\n' && inbuf[i] != '\r'; i++) {
    if (k >= MAX_INPUT_LENGTH - 2) {
      write_to_descriptor (descriptor, "Line too long.\r\n", 0);

      /* skip the rest of the line */
      for (; inbuf[i] != '\0'; i++) {
        if (inbuf[i] == '\n' || inbuf[i] == '\r')
          break;
      }
      inbuf[i] = '\n';
      inbuf[i + 1] = '\0';
      break;
    }

    if (inbuf[i] == '\b' && k > 0) {
      --k;
    } else if ( ((unsigned)inbuf[i] <= 0177)
      && isprint (inbuf[i])) {
      incomm.append(1, inbuf[i]);
      k++;
    }
  }

  /*
   * Finish off the line.
   */
  if (k == 0) {
    incomm.append(" ");
    k++;
  }

  /*
   * Deal with bozos with #repeat 1000 ...
   */
  if (k > 1 || incomm[0] == '!') {
    if (incomm[0] != '!' && incomm != inlast) {
      repeat = 0;
    } else {
      if (++repeat >= 20) {
        log_printf ("%s input spamming!", host.c_str());
        write_to_descriptor (descriptor,
          "\r\n*** PUT A LID ON IT!!! ***\r\n", 0);
        incomm = "quit";
      }
    }
  }

  /*
   * Do '!' substitution.
   */
  if (incomm[0] == '!')
    incomm = inlast;
  else
    inlast = incomm;

  /*
   * Shift the input buffer.
   */
  while (inbuf[i] == '\n' || inbuf[i] == '\r')
    i++;
  for (j = 0; (inbuf[j] = inbuf[i + j]) != '\0'; j++);
  return;
}

/*
 * Bust a prompt (player settable prompt)
 * coded by Morgenes for Aldara Mud
 */
void bust_a_prompt (Character * ch)
{
  std::string buf;
  char buf2[MAX_STRING_LENGTH];
  std::string::iterator str;

  if (ch->prompt.empty()) {
    ch->send_to_char ("\r\n\r\n");
    return;
  }

  str = ch->prompt.begin();
  while (str != ch->prompt.end()) {
    if (*str != '%') {
      buf.append(1,*str);
      str++;
      continue;
    }
    ++str;
    switch (*str) {
    default:
      buf.append(" ");
      break;
    case 'h':
      snprintf (buf2, sizeof buf2, "%d", ch->hit);
      buf.append(buf2);
      break;
    case 'H':
      snprintf (buf2, sizeof buf2, "%d", ch->max_hit);
      buf.append(buf2);
      break;
    case 'm':
      snprintf (buf2, sizeof buf2, "%d", ch->mana);
      buf.append(buf2);
      break;
    case 'M':
      snprintf (buf2, sizeof buf2, "%d", ch->max_mana);
      buf.append(buf2);
      break;
    case 'v':
      snprintf (buf2, sizeof buf2, "%d", ch->move);
      buf.append(buf2);
      break;
    case 'V':
      snprintf (buf2, sizeof buf2, "%d", ch->max_move);
      buf.append(buf2);
      break;
    case 'x':
      snprintf (buf2, sizeof buf2, "%d", ch->exp);
      buf.append(buf2);
      break;
    case 'g':
      snprintf (buf2, sizeof buf2, "%d", ch->gold);
      buf.append(buf2);
      break;
    case 'a':
      if (ch->level < 5)
        snprintf (buf2, sizeof buf2, "%d", ch->alignment);
      else
        snprintf (buf2, sizeof buf2, "%s", ch->is_good () ? "good" : ch->is_evil () ?
          "evil" : "neutral");
      buf.append(buf2);
      break;
    case 'r':
      if (ch->in_room != NULL)
        buf.append(ch->in_room->name);
      else
        buf.append(" ");
      break;
    case 'R':
      if (ch->is_immortal() && ch->in_room != NULL)
        snprintf (buf2, sizeof buf2, "%d", ch->in_room->vnum);
      else
        snprintf (buf2, sizeof buf2, " ");
      buf.append(buf2);
      break;
    case 'z':
      if (ch->is_immortal() && ch->in_room != NULL)
        buf.append(ch->in_room->area->name);
      else
        buf.append(" ");
      break;
    case '%':
      buf.append("%%");
      break;
    }
    ++str;
  }
  ch->desc->write_to_buffer (buf);
  return;
}

/*
 * Low level output function.
 */
bool Descriptor::process_output (bool fPrompt)
{
  /*
   * Bust a prompt.
   */
  if (fPrompt && !merc_down && connected == CON_PLAYING) {
    if (showstr_point)
      write_to_buffer (
        "[Please type (c)ontinue, (r)efresh, (b)ack, (h)elp, (q)uit, or RETURN]:  ");
    else {
      Character *ch;

      ch = original ? original : character;
      if (IS_SET (ch->actflags, PLR_BLANK))
        write_to_buffer ("\r\n");

      if (IS_SET (ch->actflags, PLR_PROMPT))
        bust_a_prompt (ch);

      if (IS_SET (ch->actflags, PLR_TELNET_GA))
        write_to_buffer (go_ahead_str);
    }
  }

  /*
   * Short-circuit if nothing to write.
   */
  if (outbuf.empty())
    return true;

  /*
   * OS-dependent output.
   */
  if (!write_to_descriptor (descriptor, outbuf.c_str(), outbuf.size())) {
    outbuf.erase();
    return false;
  } else {
    outbuf.erase();
    return true;
  }
}

void Descriptor::close_socket ()
{
  Character *ch;

  if (!outbuf.empty())
    process_output(false);

  if ((ch = character) != NULL) {
    log_printf ("Closing link to %s.", ch->name.c_str());
    if (connected == CON_PLAYING) {
      ch->act ("$n has lost $s link.", NULL, NULL, TO_ROOM);
      ch->desc = NULL;
    } else {
      delete character;
    }
  }

  deepdenext = descriptor_list.erase(
     find(descriptor_list.begin(),descriptor_list.end(),this));
  closesocket (descriptor);
  delete this;
  return;
}

bool Descriptor::read_from_descriptor ()
{
  unsigned int iStart;

  /* Hold horses if pending command already. */
  if (!incomm.empty())
    return true;

  /* Check for overflow. */
  iStart = strlen (inbuf);
  if (iStart >= sizeof (inbuf) - 10) {
    log_printf ("%s input overflow!", host.c_str());
    write_to_descriptor (descriptor,
      "\r\n*** PUT A LID ON IT!!! ***\r\n", 0);
    return false;
  }

  /* Snarf input. */
  for (;;) {
    int nRead;

    nRead = recv (descriptor, inbuf + iStart,
      sizeof (inbuf) - 10 - iStart, 0);
    if (nRead > 0) {
      iStart += nRead;
      if (inbuf[iStart - 1] == '\n' || inbuf[iStart - 1] == '\r')
        break;
    } else if (nRead == 0) {
      log_printf ("EOF encountered on read.");
      return false;
    } else if (GETERROR == EWOULDBLOCK)
      break;
    else {
      perror ("Read_from_descriptor");
      return false;
    }
  }

  inbuf[iStart] = '\0';
  return true;
}

void new_descriptor (SOCKET control)
{
  char buf[MAX_STRING_LENGTH];
  Descriptor *dnew;
  struct sockaddr_in sock;
  struct hostent *from;
  SOCKET desc;
#ifndef WIN32
  socklen_t size;
#else
  int size;
  unsigned long flags = 1;
#endif

  size = sizeof (sock);
  getsockname (control, (struct sockaddr *) &sock, &size);
  if ((desc = accept (control, (struct sockaddr *) &sock, &size)) == INVALID_SOCKET) {
    perror ("New_descriptor: accept");
    return;
  }
#if !defined(FNDELAY)
#define FNDELAY O_NDELAY
#endif

#ifdef WIN32
  if (ioctlsocket (desc, FIONBIO, &flags)) {
#else
  if (fcntl (desc, F_SETFL, FNDELAY) == -1) {
#endif
    perror ("New_descriptor: fcntl: FNDELAY");
    return;
  }

  /*
   * Cons a new descriptor.
   */
  dnew = new Descriptor(desc);

  size = sizeof (sock);
  if (getpeername (desc, (struct sockaddr *) &sock, &size) < 0) {
    perror ("New_descriptor: getpeername");
    dnew->host = "(unknown)";
  } else {
    /*
     * Would be nice to use inet_ntoa here but it takes a struct arg,
     * which ain't very compatible between gcc and system libraries.
     */
    int addr;

    addr = ntohl (sock.sin_addr.s_addr);
    snprintf (buf, sizeof buf, "%d.%d.%d.%d",
      (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
      (addr >> 8) & 0xFF, (addr) & 0xFF);
    log_printf ("Sock.sinaddr:  %s", buf);
    from = gethostbyaddr ((char *) &sock.sin_addr,
      sizeof (sock.sin_addr), AF_INET);
    dnew->host = from ? from->h_name : buf;
  }

  /*
   * Swiftest: I added the following to ban sites.  I don't
   * endorse banning of sites, but Copper has few descriptors now
   * and some people from certain sites keep abusing access by
   * using automated 'autodialers' and leaving connections hanging.
   *
   * Furey: added suffix check by request of Nickel of HiddenWorlds.
   */
  for (std::list<Ban*>::iterator pban = ban_list.begin();
    pban != ban_list.end(); pban++) {
    if (str_suffix ((*pban)->name, dnew->host)) {
      write_to_descriptor (desc,
        "Your site has been banned from this Mud.\r\n", 0);
      closesocket (desc);
      delete dnew;
      return;
    }
  }

  /*
   * Init descriptor data.
   */
  descriptor_list.push_back(dnew);

  /*
   * Send the greeting.
   */
  {
    if (help_greeting[0] == '.')
      dnew->write_to_buffer (help_greeting.substr(1));
    else
      dnew->write_to_buffer (help_greeting);
  }

  return;
}

void game_loop (SOCKET control)
{
  static struct timeval null_time;
  struct timeval last_time;

#ifndef WIN32
  signal (SIGPIPE, SIG_IGN);
#endif
  gettimeofday (&last_time, NULL);
  current_time = (time_t) last_time.tv_sec;

  /* Main loop */
  while (!merc_down) {
    fd_set in_set;
    fd_set out_set;
    fd_set exc_set;
#ifdef WIN32
    fd_set dummy_set;
#endif
    SOCKET maxdesc;

    /*
     * Poll all active descriptors.
     */
    FD_ZERO (&in_set);
    FD_ZERO (&out_set);
    FD_ZERO (&exc_set);
    FD_SET (control, &in_set);
#ifdef WIN32
    FD_ZERO (&dummy_set);
    FD_SET (control, &dummy_set);
#endif
    maxdesc = control;
    DescIter d;
    for (d = descriptor_list.begin(); d != descriptor_list.end(); d++) {
      maxdesc = std::max (maxdesc, (*d)->descriptor);
      FD_SET ((*d)->descriptor, &in_set);
      FD_SET ((*d)->descriptor, &out_set);
      FD_SET ((*d)->descriptor, &exc_set);
    }

    if (select (maxdesc + 1, &in_set, &out_set, &exc_set, &null_time) == SOCKET_ERROR) {
      fatal_printf ("Game_loop: select: poll");
    }

    /*
     * New connection?
     */
    if (FD_ISSET (control, &in_set))
      new_descriptor (control);

    /*
     * Kick out the freaky folks.
     */
    for (d = descriptor_list.begin(); d != descriptor_list.end(); d = deepdenext) {
      Descriptor* d_this = *d;
      deepdenext = ++d;
      if (FD_ISSET (d_this->descriptor, &exc_set)) {
        FD_CLR (d_this->descriptor, &in_set);
        FD_CLR (d_this->descriptor, &out_set);
        if (d_this->character)
          d_this->character->save_char_obj();
        d_this->outbuf.erase();
        d_this->close_socket();
      }
    }

    /*
     * Process input.
     */
    for (d = descriptor_list.begin(); d != descriptor_list.end(); d = deepdenext) {
      Descriptor* d_this = *d;
      deepdenext = ++d;
      d_this->fcommand = false;

      if (FD_ISSET (d_this->descriptor, &in_set)) {
        if (d_this->character != NULL)
          d_this->character->timer = 0;
        if (!d_this->read_from_descriptor()) {
          FD_CLR (d_this->descriptor, &out_set);
          if (d_this->character != NULL)
            d_this->character->save_char_obj();
          d_this->outbuf.erase();
          d_this->close_socket();
          continue;
        }
      }

      if (d_this->character != NULL && d_this->character->wait > 0) {
        --d_this->character->wait;
        continue;
      }

      d_this->read_from_buffer();
      if (!d_this->incomm.empty()) {
        d_this->fcommand = true;
        if (d_this->character)
          d_this->character->stop_idling();

        if (d_this->connected == CON_PLAYING)
          if (d_this->showstr_point)
            d_this->show_string (d_this->incomm);
          else
            d_this->character->interpret (d_this->incomm);
        else
          d_this->nanny (d_this->incomm);

      }
    }

    /*
     * Autonomous game motion.
     */
    update_handler ();

    /*
     * Output.
     */
    for (d = descriptor_list.begin(); d != descriptor_list.end(); d = deepdenext) {
      Descriptor* d_this = *d;
      deepdenext = ++d;
      if ((d_this->fcommand || !d_this->outbuf.empty())
        && FD_ISSET (d_this->descriptor, &out_set)) {
        if (!d_this->process_output(true)) {
          if (d_this->character != NULL)
            d_this->character->save_char_obj();
          d_this->outbuf.erase();
          d_this->close_socket();
        }
      }
    }

    /*
     * Synchronize to a clock.
     * Sleep( last_time + 1/PULSE_PER_SECOND - now ).
     * Careful here of signed versus unsigned arithmetic.
     */
    {
      struct timeval now_time;
      long secDelta;
      long usecDelta;

      gettimeofday (&now_time, NULL);
      usecDelta = ((int) last_time.tv_usec) - ((int) now_time.tv_usec)
        + 1000000 / PULSE_PER_SECOND;
      secDelta = ((int) last_time.tv_sec) - ((int) now_time.tv_sec);
      while (usecDelta < 0) {
        usecDelta += 1000000;
        secDelta -= 1;
      }

      while (usecDelta >= 1000000) {
        usecDelta -= 1000000;
        secDelta += 1;
      }

      if (secDelta > 0 || (secDelta == 0 && usecDelta > 0)) {
        struct timeval stall_time;

        stall_time.tv_usec = usecDelta;
        stall_time.tv_sec = secDelta;
#ifdef WIN32   /* windows select demands a valid fd_set */
        if (select (0, NULL, NULL, &dummy_set, &stall_time) == SOCKET_ERROR) {
#else
        if (select (0, NULL, NULL, NULL, &stall_time) == SOCKET_ERROR) {
#endif
          fatal_printf ("Game_loop: select: stall");
        }
      }
    }

    gettimeofday (&last_time, NULL);
    current_time = (time_t) last_time.tv_sec;
  }

  return;
}

/*
 * Big mama top level function.
 */
void boot_db (void)
{
  /*
   * Init some data space stuff.
   */
  fBootDb = true;

  /*
   * Seed random number generator.
   */
  OS_SRAND (time (NULL));

  /*
   * Set time and weather.
   */
  {
    long lhour, lday, lmonth;

    lhour = (current_time - 650336715)
      / (PULSE_TICK / PULSE_PER_SECOND);
    time_info.hour = lhour % 24;
    lday = lhour / 24;
    time_info.day = lday % 35;
    lmonth = lday / 35;
    time_info.month = lmonth % 17;
    time_info.year = lmonth / 17;

    if (time_info.hour < 5)
      weather_info.sunlight = SUN_DARK;
    else if (time_info.hour < 6)
      weather_info.sunlight = SUN_RISE;
    else if (time_info.hour < 19)
      weather_info.sunlight = SUN_LIGHT;
    else if (time_info.hour < 20)
      weather_info.sunlight = SUN_SET;
    else
      weather_info.sunlight = SUN_DARK;

    weather_info.change = 0;
    weather_info.mmhg = 960;
    if (time_info.month >= 7 && time_info.month <= 12)
      weather_info.mmhg += number_range (1, 50);
    else
      weather_info.mmhg += number_range (1, 80);

    if (weather_info.mmhg <= 980)
      weather_info.sky = SKY_LIGHTNING;
    else if (weather_info.mmhg <= 1000)
      weather_info.sky = SKY_RAINING;
    else if (weather_info.mmhg <= 1020)
      weather_info.sky = SKY_CLOUDY;
    else
      weather_info.sky = SKY_CLOUDLESS;

  }

  /*
   * Assign gsn's for skills which have them.
   */
  for (int sn = 0; sn < MAX_SKILL; sn++) {
    if (skill_table[sn].pgsn != NULL)
      *skill_table[sn].pgsn = sn;
  }

  /*
   * Read in all the area files.
   */
  std::ifstream fpList;
  std::ifstream fp;

  fpList.open (AREA_LIST, std::ifstream::in | std::ifstream::binary);
  if (!fpList.is_open()) {
    fatal_printf (AREA_LIST);
  }

  for (;;) {
    strArea = fread_word (fpList);
    if (strArea[0] == '$')
      break;

    fp.open (strArea.c_str(), std::ifstream::in | std::ifstream::binary);
    if (!fp.is_open()) {
      fatal_printf (strArea.c_str());
    }
    fpArea = &fp;
    for (;;) {
      std::string word;

      if (fread_letter (fp) != '#') {
        fatal_printf ("Boot_db: # not found.");
      }

      word = fread_word (fp);

      if (word[0] == '$')
        break;
      else if (!str_cmp (word, "AREA"))
        load_area (fp);
      else if (!str_cmp (word, "HELPS"))
        load_helps (fp);
      else if (!str_cmp (word, "MOBILES"))
        load_mobiles (fp);
      else if (!str_cmp (word, "MOBPROGS"))
        load_mobprogs (fp);
      else if (!str_cmp (word, "OBJECTS"))
        load_objects (fp);
      else if (!str_cmp (word, "RESETS"))
        load_resets (fp);
      else if (!str_cmp (word, "ROOMS"))
        load_rooms (fp);
      else if (!str_cmp (word, "SHOPS"))
        load_shops (fp);
      else if (!str_cmp (word, "SPECIALS"))
        load_specials (fp);
      else {
        fatal_printf ("Boot_db: bad section name.");
      }
    }

    fp.close();
    fpArea = NULL;
  }
  fpList.close();

  /*
   * Fix up exits.
   * Declare db booting over.
   * Reset all areas once.
   * Load up the notes file.
   * Set the MOBtrigger.
   */
  fix_exits ();
  fBootDb = false;
  area_update ();
  load_notes ();
  MOBtrigger = true;

  return;
}

int init_server_socket (int port)
{
  SOCKET fd;

  if ((fd = socket (AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
    fatal_printf("Init_socket: socket");
  }

  int x = 1;
  if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (char *) &x, sizeof (x)) == SOCKET_ERROR) {
    closesocket (fd);
    fatal_printf ("Init_socket: SO_REUSEADDR");
  }

#ifndef SO_DONTLINGER
  struct linger ld;
  ld.l_onoff = 1;
  ld.l_linger = 1000;
  if (setsockopt (fd, SOL_SOCKET, SO_DONTLINGER, (char *) &ld, sizeof (ld)) == SOCKET_ERROR) {
    closesocket (fd);
    fatal_printf ("Init_socket: SO_DONTLINGER");
  }
#endif

  static struct sockaddr_in sa_zero;
  struct sockaddr_in sa;
  sa = sa_zero;
  sa.sin_family = AF_INET;
  sa.sin_port = htons (port);

  if (bind (fd, (struct sockaddr *) &sa, sizeof (sa)) < 0) {
    closesocket (fd);
    fatal_printf ("Init_socket: bind");
  }

  if (listen (fd, 3) < 0) {
    closesocket (fd);
    fatal_printf ("Init_socket: listen");
  }

  return fd;
}

int main (int argc, char **argv)
{
  struct timeval now_time;

  // Init time.
  gettimeofday (&now_time, NULL);
  current_time = (time_t) now_time.tv_sec;
  str_boot_time = ctime (&current_time);

  if(sqlite3_open("murk.db", &database)) {
    fatal_printf("Can't open database: %s.", sqlite3_errmsg(database));
  }

  WIN32STARTUP

  // Get the port number.
  int port = 1234;
  if (argc > 1) {
    if (!is_number (argv[1])) {
      fatal_printf ("Usage: %s [port #]");
    } else if ((port = atoi (argv[1])) <= 1024) {
      fatal_printf("Port number must be above 1024.");
    }
  }

  // Run the game.
  SOCKET control = init_server_socket (port);
  boot_db ();
  log_printf ("Merc is ready to rock on port %d.", port);
  game_loop (control);

  // Normal exit
  closesocket (control);
  log_printf ("Normal termination of game.");
  WIN32CLEANUP
  sqlite3_close(database);
  return 0;
}
