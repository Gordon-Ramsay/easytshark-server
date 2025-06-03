#pragma once
#include "tshark_datatype.h"
#include "utils/process_util.h"
#include "adapter_monitor_info.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "utils/ip2region_util.h"
#include "utils/translate_util.hpp"
#include "loguru/loguru.hpp"
#include "tshark_database.h"
#include <regex>


#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <set>
#include <string>
#include <thread>
#include <mutex>

class TsharkManager {

public:
    TsharkManager(std::string workDir);
    ~TsharkManager();

    // 分析数据包文件
    bool analysisFile(std::string filePath);

    // 打印所有数据包的信息
    void printAllPackets();

    // 获取指定编号数据包的十六进制数据
    bool getPacketHexData(uint32_t frameNumber, std::vector<unsigned char> &data);

    std::vector<AdapterInfo> getNetworkAdapters();
    
    // 开始抓包
	bool startCapture(std::string adapterName);

	// 停止抓包
	bool stopCapture();	

    // 开始监控所有网卡流量统计数据
    void startMonitorAdaptersFlowTrend();

    // 停止监控所有网卡流量统计数据
    void stopMonitorAdaptersFlowTrend();

    // 获取所有网卡流量统计数据
    void getAdaptersFlowTrendData(std::map<std::string, std::map<long, long>>& flowTrendData);

    // 获取指定数据包的详情内容
    bool getPacketDetailInfo(uint32_t frameNumber, std::string &result);
    uint32_t getAllPacketsCount();
private:
    // 解析每一行
    bool parseLine(std::string line, std::shared_ptr<Packet> packet);

private:

    std::string tsharkPath;
    std::string editcapPath;
    IP2RegionUtil ip2RegionUtil;
    TranslateUtil translator;

    // 当前分析的文件路径
    std::string currentFilePath;

    // 分析得到的所有数据包信息，key是数据包ID，value是数据包信息指针，方便根据编号获取指定数据包信息
    std::unordered_map<uint32_t, std::shared_ptr<Packet>> allPackets;

    // 在线采集数据包的工作线程
    void captureWorkThreadEntry(std::string adapterName);

    // 在线分析线程
    std::shared_ptr<std::thread> captureWorkThread;

    // 是否停止抓包的标记
    bool stopFlag;

    // 在线抓包的tshark进程PID
    PID_T captureTsharkPid = 0;

    // 后台流量趋势监控信息
    std::map<std::string, AdapterMonitorInfo> adapterFlowTrendMonitorMap;

    // 访问上面流量趋势数据的锁
    std::recursive_mutex adapterFlowTrendMapLock;
    
    // 网卡流量监控的开始时间
    long adapterFlowTrendMonitorStartTime = 0;

     // 网卡流量监控工作线程
    void adapterFlowTrendMonitorThreadEntry(std::string adapterName);

    // 等待存储入库的数据
    std::vector<std::shared_ptr<Packet>> packetsTobeStore;

    // 访问待存储数据的锁
    std::mutex storeLock;

    // 存储线程，负责将获取到的数据包和会话信息存储入库
    std::shared_ptr<std::thread> storageThread;

    // 数据库存储
    std::shared_ptr<TsharkDatabase> storage;

    // 存储线程入口函数
    void storageThreadEntry();

    void processPacket(std::shared_ptr<Packet> packet);
};