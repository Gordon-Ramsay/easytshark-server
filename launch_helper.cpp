// launch_helper.cpp
#include <windows.h>
#include <stdio.h>
#include <string>


// 替换命令行中 "tshark_server_helper.exe" 为 "tshark_server.exe"
std::string ReplaceCommandLineExecutable() {
    std::string cmdLine = GetCommandLineA();
    std::string from = "tshark_server_helper.exe";
    std::string to = "tshark_server.exe";

    size_t pos = cmdLine.find(from);
    if (pos != std::string::npos) {
        cmdLine.replace(pos, from.length(), to);
    }

    return cmdLine;
}

int main(int argc, char* argv[]) {

    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // 创建进程时手动设置 CREATE_BREAKAWAY_FROM_JOB
    if (CreateProcessA(
        NULL,
        (LPSTR)ReplaceCommandLineExecutable().c_str(),
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB | CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    else {
        printf("创建进程失败: %lu\n", GetLastError());
    }

    return 0;
}