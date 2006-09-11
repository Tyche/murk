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

#ifndef OS_HPP
#define OS_HPP

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
std::string itoa(int value, int base);

/*-----------------------------------------------------------------------*/
/* WINDOWS DEFINITIONS SECTION                                           */
/*-----------------------------------------------------------------------*/
#ifdef WIN32                    /* Windows portability */
#if defined _MSC_VER || defined __DMC__
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
#if defined __DMC__
#define snprintf _snprintf
#endif

void gettimeofday (struct timeval *tp, struct timezone *tzp);
char *crypt (char *pw, const char *salt);

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

#endif // OS_HPP

