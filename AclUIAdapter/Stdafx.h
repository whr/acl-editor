// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently,
// but are changed infrequently

#pragma once

#define _WIN32_WINNT 0x500
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <aclui.h>
#include <aclapi.h>
#include <string>

typedef std::basic_string<wchar_t> wstring;
typedef std::basic_string<char> string;
