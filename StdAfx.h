// stdafx.h : include file for standard system include files,
//  or project specific include files that are used frequently, but
//      are changed infrequently
//

#if !defined(AFX_STDAFX_H__19C8A1A8_AF59_49CD_BB3D_28C8FC8967E5__INCLUDED_)
#define AFX_STDAFX_H__19C8A1A8_AF59_49CD_BB3D_28C8FC8967E5__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers

#include <stdio.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>

#pragma comment(lib,"ws2_32")

#include "SocketHeader.h"

// TODO: reference additional headers your program requires here

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_STDAFX_H__19C8A1A8_AF59_49CD_BB3D_28C8FC8967E5__INCLUDED_)
