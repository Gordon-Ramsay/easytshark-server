#pragma once
#include <map>
#include <string>
#include <memory>
#include <thread>

#ifdef _WIN32
#include <windows.h>
typedef DWORD PID_T;
#else
typedef pid_t PID_T;
#endif

class AdapterMonitorInfo {
public:
    AdapterMonitorInfo() {
        monitorTsharkPipe = nullptr;
        tsharkPid = 0;
    }

    std::string adapterName;                            // 网卡名称
    std::map<long, long> flowTrendData;                 // 流量趋势数据
    std::shared_ptr<std::thread> monitorThread;         // 负责监控该网卡输出的线程
    FILE* monitorTsharkPipe;                            // 线程与tshark通信的管道
    PID_T tsharkPid;                                    // 负责捕获该网卡数据的tshark进程PID
};
