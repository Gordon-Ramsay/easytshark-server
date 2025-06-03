#pragma once
#ifdef _WIN32
#include <windows.h>
#include <cstdio>
#include <string>
#include <fcntl.h>
#include <iostream>
#endif

#ifdef _WIN32
typedef DWORD PID_T;
#else
typedef pid_t PID_T;
#endif

class ProcessUtil {
public:
    static FILE* PopenEx(std::string command, PID_T* pidOut = nullptr);
    static int Kill(PID_T pid);
    static bool Exec(std::string cmdline);
};
