#include "tshark_manager.h"
#include "utils/misc_util.hpp"

#ifdef _WIN32
// 使用宏来处理Windows和Unix的不同popen实现
#define popen _popen
#define pclose _pclose
#endif

std::map<uint8_t, std::string> ipProtoMap = {
    {1, "ICMP"},
    {2, "IGMP"},
    {6, "TCP"},
    {17, "UDP"},
    {47, "GRE"},
    {50, "ESP"},
    {51, "AH"},
    {88, "EIGRP"},
    {89, "OSPF"},
    {132, "SCTP"}
};

TsharkManager::TsharkManager(std::string workDir) {
    this->workDir = workDir;
    this->tsharkPath = "F:/Wireshark/tshark.exe";
    this->editcapPath = "F:/Wireshark/editcap.exe";
    std::string xdbPath = workDir + "/third_library/ip2region/ip2region.xdb";
    storage = std::make_shared<TsharkDatabase>(workDir + "/mytshark.db");
    IP2RegionUtil::init(xdbPath);
}

TsharkManager::~TsharkManager() {
    IP2RegionUtil::uninit();
}

bool TsharkManager::analysisFile(std::string filePath) {

    reset();

    // 统一转换为标准的pcap格式
    currentFilePath = MiscUtil::getPcapNameByCurrentTimestamp();
    if (!convertToPcap(filePath, currentFilePath)) {
        LOG_F(ERROR, "convert to pcap failed");
        return false;
    }

    std::vector<std::string> tsharkArgs = {
            tsharkPath,
            "-r", currentFilePath.c_str(),
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "frame.len",
            "-e", "frame.cap_len",
            "-e", "eth.src",
            "-e", "eth.dst",
            "-e", "ip.src",
            "-e", "ipv6.src",
            "-e", "ip.dst",
            "-e", "ipv6.dst",
            "-e", "ip.proto",
            "-e", "ipv6.nxt",
            "-e", "tcp.srcport",
            "-e", "udp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.dstport",
            "-e", "_ws.col.Protocol",
            "-e", "_ws.col.Info",
    };

    std::string command;
    for (auto arg : tsharkArgs) {
        command += arg;
        command += " ";
    }

    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        std::cerr << "Failed to run tshark command!" << std::endl;
        return false;
    }

    // 先启动存储线程
    stopFlag = false;
    storageThread = std::make_shared<std::thread>(&TsharkManager::storageThreadEntry, this);

    // 当前处理的报文在文件中的偏移，第一个报文的偏移就是全局文件头24(也就是sizeof(PcapHeader))字节
    uint32_t file_offset = sizeof(PcapHeader);
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        if (!parseLine(buffer, packet)) {
            LOG_F(ERROR, buffer);
            assert(false); // 增加错误断言，及时发现错误
        }

        // 计算当前报文的偏移，然后记录在Packet对象中
        packet->file_offset = file_offset + sizeof(PacketHeader);

        // 更新偏移游标
        file_offset = file_offset + sizeof(PacketHeader) + packet->cap_len;

        // 获取IP地理位置
        packet->src_location = IP2RegionUtil::getIpLocation(packet->src_ip);
        packet->dst_location = IP2RegionUtil::getIpLocation(packet->dst_ip);

        processPacket(packet);
    }

    pclose(pipe);

    // 等待存储线程退出
    stopFlag = true;
    storageThread->join();
    storageThread.reset();

    // 记录当前分析的文件路径
    currentFilePath = filePath;

    LOG_F(INFO, "分析完成，数据包总数：%zu", allPackets.size());

    return true;
}

bool TsharkManager::parseLine(std::string line, std::shared_ptr<Packet> packet) {
    if (line.back() == '\n') {
        line.pop_back();
    }
    std::stringstream ss(line);
    std::string field;
    std::vector<std::string> fields;

    size_t start = 0, end;
    while ((end = line.find('\t', start)) != std::string::npos) {
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(line.substr(start)); // 添加最后一个子串


    // 字段顺序：
    // 0: frame.number
    // 1: frame.time_epoch
    // 2: frame.len
    // 3: frame.cap_len
    // 4: eth.src
    // 5: eth.dst
    // 6: ip.src
    // 7: ipv6.src
    // 8: ip.dst
    // 9: ipv6.dst
    // 10: ip.proto
    // 11: ipv6.nxt
    // 12: tcp.srcport
    // 13: udp.srcport
    // 14: tcp.dstport
    // 15: udp.dstport
    // 16: _ws.col.Protocol
    // 17: _ws.col.Info

    if (fields.size() >= 18) {
        packet->frame_number = std::stoi(fields[0]);
        packet->time = std::stod(fields[1]);
        packet->len = std::stoi(fields[2]);
        packet->cap_len = std::stoi(fields[3]);
        packet->src_mac = fields[4];
        packet->dst_mac = fields[5];
        packet->src_ip = fields[6].empty() ? fields[7] : fields[6];
        packet->dst_ip = fields[8].empty() ? fields[9] : fields[8];
        
        if (!fields[10].empty() || !fields[11].empty()) {
            uint8_t transProtoNumber = std::stoi(fields[10].empty() ? fields[11] : fields[10]);
            if (ipProtoMap.find(transProtoNumber) != ipProtoMap.end()) {
                packet->trans_proto = ipProtoMap[transProtoNumber];
            }
        }

        if (!fields[12].empty() || !fields[13].empty()) {
            packet->src_port = std::stoi(fields[12].empty() ? fields[13] : fields[12]);
        }

        if (!fields[14].empty() || !fields[15].empty()) {
            packet->dst_port = std::stoi(fields[14].empty() ? fields[15] : fields[14]);
        }
        packet->protocol = fields[16];
        packet->info = fields[17];

        return true;
    }
    else {
        return false;
    }
}

void TsharkManager::printAllPackets() {

    for (auto pair : allPackets) {

        std::shared_ptr<Packet> packet = pair.second;

        // 构建JSON对象
        rapidjson::Document pktObj;
        rapidjson::Document::AllocatorType& allocator = pktObj.GetAllocator();
        pktObj.SetObject();

        pktObj.AddMember("frame_number", packet->frame_number, allocator);
        pktObj.AddMember("timestamp", packet->time, allocator);
        pktObj.AddMember("src_mac", rapidjson::Value(packet->src_mac.c_str(), allocator), allocator);
        pktObj.AddMember("dst_mac", rapidjson::Value(packet->dst_mac.c_str(), allocator), allocator);
        pktObj.AddMember("src_ip", rapidjson::Value(packet->src_ip.c_str(), allocator), allocator);
        pktObj.AddMember("src_location", rapidjson::Value(packet->src_location.c_str(), allocator), allocator);
        pktObj.AddMember("src_port", packet->src_port, allocator);
        pktObj.AddMember("dst_ip", rapidjson::Value(packet->dst_ip.c_str(), allocator), allocator);
        pktObj.AddMember("dst_location", rapidjson::Value(packet->dst_location.c_str(), allocator), allocator);
        pktObj.AddMember("dst_port", packet->dst_port, allocator);
        pktObj.AddMember("protocol", rapidjson::Value(packet->protocol.c_str(), allocator), allocator);
        pktObj.AddMember("info", rapidjson::Value(packet->info.c_str(), allocator), allocator);
        pktObj.AddMember("file_offset", packet->file_offset, allocator);
        pktObj.AddMember("cap_len", packet->cap_len, allocator);
        pktObj.AddMember("len", packet->len, allocator);

        // 序列化为 JSON 字符串
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        pktObj.Accept(writer);

        // 打印JSON输出
        LOG_F(INFO, buffer.GetString());
    }
    LOG_F(INFO, "Total packets: %d", allPackets.size());
}

bool TsharkManager::getPacketHexData(uint32_t frameNumber, std::vector<unsigned char> &data) {
    auto it = allPackets.find(frameNumber);
    if (it == allPackets.end()) {
        return false;
    }

    std::shared_ptr<Packet> packet = it->second;

    // 读取文件中的数据
    std::ifstream file(currentFilePath, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << currentFilePath << std::endl;
        return false;
    }

    file.seekg(packet->file_offset, std::ios::beg);
    if (!file) { // 检查 seekg 是否成功
        std::cerr << "Failed to seek to offset: " << packet->file_offset << std::endl;
        return false; // 如果 seekg 失败，返回 false
    }

    data.resize(packet->cap_len); // 调整 buffer 的大小以容纳 length 个字节
    file.read(reinterpret_cast<char*>(data.data()), packet->cap_len); // 从文件中读取 length 个字节到 buffer

    if (!file) { // 检查读取是否成功
        std::cerr << "Failed to read " << packet->cap_len << " bytes from file" << std::endl;
        return false; // 如果读取失败，返回 false
    }

    return true;
}

// std::vector<AdapterInfo> TsharkManager::getNetworkAdapters() {
//     // 需要过滤掉的虚拟网卡
//     std::set<std::string> specialInterfaces = { "sshdump", "ciscodump", "udpdump", "randpkt" };

//     // 枚举到的网卡列表
//     std::vector<AdapterInfo> interfaces;

//     // 启动 tshark -D 命令
//     std::string cmd = tsharkPath + " -D";
//     FILE* pipe = popen(cmd.c_str(), "r");
//     if (!pipe) {
//         throw std::runtime_error("Failed to run tshark command.");
//     }

//     // 使用正则表达式匹配网卡信息
//     std::regex interfaceRegex(R"(^(\d+)\.\s+([^\s]+)\s+\([^\)]+\)$)");
//     char buffer[1024];

//     while (fgets(buffer, sizeof(buffer), pipe)) {
//         std::string line(buffer);
//         std::smatch match;

//         if (std::regex_search(line, match, interfaceRegex)) {
//             std::string interfaceName = match[2];
//             if (specialInterfaces.find(interfaceName) != specialInterfaces.end()) {
//                 continue;
//             }

//             AdapterInfo adapterInfo;
//             adapterInfo.id = std::stoi(match[1]);
//             adapterInfo.name = interfaceName;
//             adapterInfo.remark = match[3];

//             interfaces.push_back(adapterInfo);
//         } else {
//             LOG_F(WARNING, "Unmatched line: %s", line.c_str());
//         }
//     }

//     pclose(pipe);

//     return interfaces;
// }

std::vector<AdapterInfo> TsharkManager::getNetworkAdapters() {
    // 需要过滤掉的虚拟网卡，这些不是真实的网卡。tshark -D命令可能会输出这些，把它过滤掉
    std::set<std::string> specialInterfaces = { "sshdump", "ciscodump", "udpdump", "randpkt" };

    // 枚举到的网卡列表
    std::vector<AdapterInfo> interfaces;

    // 准备一个buffer缓冲区，来读取tshark -D每一行的内容
    char buffer[256] = { 0 };
    std::string result;

    // 启动tshark -D命令
    std::string cmd = tsharkPath + " -D";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("Failed to run tshark command.");
    }

    // 读取tshark输出
    while (fgets(buffer, 256, pipe) != nullptr) {
        result += buffer;
    }

    // 解析tshark的输出，输出格式为：
    // 1. \Device\NPF_{xxxxxx} (网卡描述)
    std::istringstream stream(result);
    std::string line;
    int index = 1;
    while (std::getline(stream, line)) {
        // 通过空格拆分字段
        int startPos = line.find(' ');
        if (startPos != std::string::npos) {
            int endPos = line.find(' ', startPos + 1);
            std::string interfaceName;
            if (endPos != std::string::npos) {
                interfaceName = line.substr(startPos + 1, endPos - startPos - 1);
            }
            else {
                interfaceName = line.substr(startPos + 1);
            }

            // 滤掉特殊网卡
            if (specialInterfaces.find(interfaceName) != specialInterfaces.end()) {
                continue;
            }

            AdapterInfo adapterInfo;
            adapterInfo.name = interfaceName;
            adapterInfo.id = index++;

			// 定位到括号，把括号里面的备注内容提取出来
            if (line.find("(") != std::string::npos && line.find(")") != std::string::npos) {
                adapterInfo.remark = line.substr(line.find("(") + 1, line.find(")") - line.find("(") - 1);
            }

            interfaces.push_back(adapterInfo);
        }
    }

    pclose(pipe);

    return interfaces;
}

bool TsharkManager::startCapture(std::string adapterName) {

    LOG_F(INFO, "即将开始抓包，网卡：%s", adapterName.c_str());

    // 关闭停止标记
    stopFlag = false;
	// 启动抓包线程
    captureWorkThread = std::make_shared<std::thread>(&TsharkManager::captureWorkThreadEntry, this, "\"" + adapterName + "\"");
    // 启动存储线程
    storageThread = std::make_shared<std::thread>(&TsharkManager::storageThreadEntry, this);

    return true;
}

void TsharkManager::captureWorkThreadEntry(std::string adapterName) {

    std::string captureFile = "capture.pcap";
    std::vector<std::string> tsharkArgs = {
            tsharkPath,
            "-i", adapterName.c_str(),
            "-w", captureFile,               // 默认将采集到的数据包写入到这个文件下
            "-F", "pcap",                    // 指定存储的格式为PCAP格式
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "frame.len",
            "-e", "frame.cap_len",
            "-e", "eth.src",
            "-e", "eth.dst",
            "-e", "ip.src",
            "-e", "ipv6.src",
            "-e", "ip.dst",
            "-e", "ipv6.dst",
            "-e", "tcp.srcport",
            "-e", "udp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.dstport",
            "-e", "_ws.col.Protocol",
            "-e", "_ws.col.Info",
            "-e", "ip.proto",
            "-e", "ipv6.nxt",
    };

    std::string command;
    for (auto arg : tsharkArgs) {
        command += arg;
        command += " ";
    }

    FILE* pipe = ProcessUtil::PopenEx(command.c_str(), &captureTsharkPid);
    if (!pipe) {
        LOG_F(ERROR, "Failed to run tshark command!");
        return;
    }

    char buffer[4096];

    // 当前处理的报文在文件中的偏移，第一个报文的偏移就是全局文件头24(也就是sizeof(PcapHeader))字节
    uint32_t file_offset = sizeof(PcapHeader);
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr && !stopFlag) {
        std::string line = buffer;
        if (line.find("Capturing on") != std::string::npos) {
            continue;
        }

        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        if (!parseLine(line, packet)) {
            LOG_F(ERROR, buffer);
            assert(false);
        }

        // 计算当前报文的偏移，然后记录在Packet对象中
        packet->file_offset = file_offset + sizeof(PacketHeader);

        // 更新偏移游标
        file_offset = file_offset + sizeof(PacketHeader) + packet->cap_len;

        // 获取IP地理位置
        packet->src_location = IP2RegionUtil::getIpLocation(packet->src_ip);
        packet->dst_location = IP2RegionUtil::getIpLocation(packet->dst_ip);

        processPacket(packet);
    }

    pclose(pipe);

    // 记录当前分析的文件路径
    currentFilePath = captureFile;
}

// 停止抓包
bool TsharkManager::stopCapture() {

    LOG_F(INFO, "即将停止抓包");
    stopFlag = true;
    ProcessUtil::Kill(captureTsharkPid);

    // 等待抓包处理线程退出
    captureWorkThread->join();
    captureWorkThread.reset();

    // 等待存储线程退出
    storageThread->join();
    storageThread.reset();

    return true;
}

// 开始监控所有网卡流量统计数据
void TsharkManager::startMonitorAdaptersFlowTrend() {

    std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);

    adapterFlowTrendMonitorStartTime = time(nullptr);

    // 第一步：获取网卡列表
    std::vector<AdapterInfo> adapterList = getNetworkAdapters();

    // 第二步：每个网卡启动一个线程，统计对应网卡的数据
    for (auto adapter : adapterList) {

        adapterFlowTrendMonitorMap.insert(std::make_pair<>(adapter.name, AdapterMonitorInfo()));
        AdapterMonitorInfo& monitorInfo = adapterFlowTrendMonitorMap.at(adapter.name);

        monitorInfo.monitorThread = std::make_shared<std::thread>(&TsharkManager::adapterFlowTrendMonitorThreadEntry, this, adapter.name);
        if (monitorInfo.monitorThread == nullptr) {
            LOG_F(ERROR, "监控线程创建失败，网卡名：%s", adapter.name.c_str());
        } else {
            LOG_F(INFO, "监控线程创建成功，网卡名：%s，monitorThread: %p", adapter.name.c_str(), monitorInfo.monitorThread.get());
        }
    }
}

// 获取指定网卡的流量趋势数据
void TsharkManager::adapterFlowTrendMonitorThreadEntry(std::string adapterName) {
    adapterFlowTrendMapLock.lock();
    if (adapterFlowTrendMonitorMap.find(adapterName) == adapterFlowTrendMonitorMap.end()) {
        adapterFlowTrendMapLock.unlock();
        return;
    }
    adapterFlowTrendMapLock.unlock();

    char buffer[256] = { 0 };
    std::map<long, long>& trafficPerSecond = adapterFlowTrendMonitorMap[adapterName].flowTrendData;

    // Tshark命令，指定网卡，实时捕获时间戳和数据包长度
    std::string tsharkCmd = tsharkPath + " -i \"" + adapterName + "\" -T fields -e frame.time_epoch -e frame.len";

    LOG_F(INFO, "启动网卡流量监控: %s", tsharkCmd.c_str());

    PID_T tsharkPid = 0;
    FILE* pipe = ProcessUtil::PopenEx(tsharkCmd.c_str(), &tsharkPid);
    if (!pipe) {
        throw std::runtime_error("Failed to run tshark command.");
    }

    // 将管道保存起来
    adapterFlowTrendMapLock.lock();
    adapterFlowTrendMonitorMap[adapterName].monitorTsharkPipe = pipe;
    adapterFlowTrendMonitorMap[adapterName].tsharkPid = tsharkPid;
    adapterFlowTrendMapLock.unlock();

    // 逐行读取tshark输出
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::string line(buffer);
        std::istringstream iss(line);
        std::string timestampStr, lengthStr;

        if (line.find("Capturing") != std::string::npos || line.find("captured") != std::string::npos) {
            continue;
        }

        // 解析每行的时间戳和数据包长度
        if (!(iss >> timestampStr >> lengthStr)) {
            continue;
        }

        try {
            // 转换时间戳为long类型，秒数部分
            long timestamp = static_cast<long>(std::stod(timestampStr));

            // 转换数据包长度为long类型
            long packetLength = std::stol(lengthStr);

            // 每秒的字节数累加
            trafficPerSecond[timestamp] += packetLength;

            // 如果trafficPerSecond超过300秒，则删除最早的数据，始终只存储最近300秒的数据
            while (trafficPerSecond.size() > 300) {
                // 访问并删除最早的时间戳数据
                auto it = trafficPerSecond.begin();
                LOG_F(INFO, "Removing old data for second: %ld, Traffic: %ld bytes", it->first, it->second);
                trafficPerSecond.erase(it);
            }
        }
        catch (const std::exception& e) {
            // 处理转换错误
            LOG_F(ERROR, "Error parsing tshark output: %s", line.c_str());
        }
    }

    LOG_F(INFO, "adapterFlowTrendMonitorThreadEntry 已结束");
}

// 停止监控所有网卡流量统计数据
void TsharkManager::stopMonitorAdaptersFlowTrend() {

    std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);

    // 先杀死对应的tshark进程
    for (auto adapterPipePair : adapterFlowTrendMonitorMap) {
        ProcessUtil::Kill(adapterPipePair.second.tsharkPid);
    }

    // 然后关闭管道
    for (auto adapterPipePair : adapterFlowTrendMonitorMap) {

        // 然后关闭管道
        pclose(adapterPipePair.second.monitorTsharkPipe);

        // 最后等待对应线程退出
        adapterPipePair.second.monitorThread->join();

        LOG_F(INFO, "网卡：%s 流量监控已停止", adapterPipePair.first.c_str());
    }

    // 清空记录的流量趋势数据
    adapterFlowTrendMonitorMap.clear();
}

// 获取所有网卡流量统计数据
void TsharkManager::getAdaptersFlowTrendData(std::map<std::string, std::map<long, long>>& flowTrendData) {

    long timeNow = time(nullptr);

    // 数据从最左边冒出来
    // 一开始：以最开始监控时间为左起点，终点为未来300秒
    // 随着时间推移，数据逐渐填充完这300秒
    // 超过300秒之后，结束节点就是当前，开始节点就是当前-300
    long startWindow = timeNow - adapterFlowTrendMonitorStartTime > 300 ? timeNow - 300 : adapterFlowTrendMonitorStartTime;
    long endWindow = timeNow - adapterFlowTrendMonitorStartTime > 300 ? timeNow : adapterFlowTrendMonitorStartTime + 300;

    adapterFlowTrendMapLock.lock();
    for (auto adapterPipePair : adapterFlowTrendMonitorMap) {
        flowTrendData.insert(std::make_pair<>(adapterPipePair.first, std::map<long, long>()));

        // 从当前时间戳向前倒推300秒，构造map
        for (long t = startWindow; t <= endWindow; t++) {
            // 如果trafficPerSecond中存在该时间戳，则使用已有数据；否则填充为0
            if (adapterPipePair.second.flowTrendData.find(t) != adapterPipePair.second.flowTrendData.end()) {
                flowTrendData[adapterPipePair.first][t] = adapterPipePair.second.flowTrendData.at(t);
            } else {
                flowTrendData[adapterPipePair.first][t] = 0;
            }
        }
    }

    adapterFlowTrendMapLock.unlock();
}

// 获取指定数据包的详情内容
bool TsharkManager::getPacketDetailInfo(uint32_t frameNumber, std::string &result) {

    // 先通过editcap将这一帧数据包从文件中摘出来，然后再获取详情，这样会快一些
    std::string tmpFilePath = MiscUtil::getDefaultDataDir() + MiscUtil::getRandomString(10) + ".pcap";
    std::string splitCmd = editcapPath + " -r " + currentFilePath + " " + tmpFilePath + " " + std::to_string(frameNumber) + "-" + std::to_string(frameNumber);
    if (!ProcessUtil::Exec(splitCmd)) {
        LOG_F(ERROR, "Error in executing command: %s", splitCmd.c_str());
        remove(tmpFilePath.c_str());
        return false;
    }

    // 通过tshark获取指定数据包详细信息，输出格式为XML
    // 启动'tshark -r ${currentFilePath} -T pdml'命令，获取指定数据包的详情
    std::string cmd = tsharkPath + " -r " + tmpFilePath + " -T pdml";
    std::unique_ptr<FILE, decltype(&pclose)> pipe(ProcessUtil::PopenEx(cmd.c_str()), pclose);
    if (!pipe) {
        std::cout << "Failed to run tshark command." << std::endl;
        remove(tmpFilePath.c_str());
        return false;
    }

    // 读取tshark输出
    char buffer[8192] = { 0 };
    std::string tsharkResult;
    setvbuf(pipe.get(), NULL, _IOFBF, sizeof(buffer));
    int count = 0;
    while (fgets(buffer, sizeof(buffer) - 1, pipe.get()) != nullptr) {
        tsharkResult += buffer;
        memset(buffer, 0, sizeof(buffer));
    }

    remove(tmpFilePath.c_str());

    // 将xml内容转换为JSON
    rapidjson::Document detailJson;
    if (!MiscUtil::xml2JSON(tsharkResult, detailJson)) {
        LOG_F(ERROR, "XML转JSON失败");
        return false;
    }

    // 字段翻译
    translator.translateShowNameFields(detailJson["pdml"]["packet"][0]["proto"], detailJson.GetAllocator());

    // 序列化为 JSON 字符串
    rapidjson::StringBuffer stringBuffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(stringBuffer);
    detailJson.Accept(writer);

    // 设置数据包详情结果
    result = stringBuffer.GetString();

    return true;
}

// 负责存储数据包和会话信息的存储线程函数
void TsharkManager::storageThreadEntry() {

    // 改进版（异常安全+性能优化）
    auto storageWork = [this]() {
        // 使用 RAII 锁自动管理（异常安全）
        std::lock_guard<std::mutex> lock(storeLock);
        
        // 拷贝数据快速释放锁
        auto packetsToProcess = std::move(packetsTobeStore);
        packetsTobeStore.clear(); // 清空原队列

        auto sessionsToProcess = std::move(sessionSetTobeStore);
        sessionSetTobeStore.clear(); // 清空原会话映射
        
        // 释放锁后执行耗时操作
        storeLock.unlock(); 
        
        if (!packetsToProcess.empty()) {
            storage->storePackets(packetsToProcess);
        }

        if (!sessionsToProcess.empty()) {
            storage->storeAndUpdateSessions(sessionsToProcess);
        }
        
        // 可选：添加流控机制避免堆积
        if (packetsTobeStore.size() > MAX_SID_SIZE) {
            LOG_F(WARNING,"待存储队列过长: %zu", packetsTobeStore.size());
        }

        if (sessionSetTobeStore.size() > MAX_SID_SIZE) {
            LOG_F(WARNING,"待存储会话队列过长: %zu", sessionSetTobeStore.size());
        }  
    };

    // 只要停止标记没有点亮，存储线程就要一直存在
    while (!stopFlag) {
        storageWork();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // 稍等一下最后再执行一次，防止有遗漏的数据未入库
    std::this_thread::sleep_for(std::chrono::seconds(1));
    storageWork();
}

// 处理每一个数据包
void TsharkManager::processPacket(std::shared_ptr<Packet> packet) {

    // 将分析的数据包插入保存起来
    allPackets.insert(std::make_pair<>(packet->frame_number, packet));

    // 等待入库
    storeLock.lock();
    packetsTobeStore.push_back(packet);
    storeLock.unlock();

    if (packet->trans_proto == "TCP" || packet->trans_proto == "UDP") {

        // 创建五元组
        FiveTuple tuple{ packet->src_ip, packet->dst_ip, packet->src_port, packet->dst_port, packet->trans_proto };

        // 将数据包加入到相应会话的列表中，并更新统计信息
        std::shared_ptr<Session> session;
        if (sessionMap.find(tuple) == sessionMap.end()) {
            // 新的会话，初始化会话信息
            session = std::make_shared<Session>();
            session->session_id = sessionMap.size() + 1;        // 通过序号来分配ID
            session->ip1 = packet->src_ip;
            session->ip2 = packet->dst_ip;
            session->ip1_location = packet->src_location;
            session->ip2_location = packet->dst_location;
            session->ip1_port = packet->src_port;
            session->ip2_port = packet->dst_port;
            session->start_time = packet->time;
            session->end_time = packet->time;
            session->trans_proto = packet->trans_proto;
            if (packet->protocol != "TCP" && packet->protocol != "UDP") {
                session->app_proto = packet->protocol;
            }

            sessionMap.insert(std::make_pair(tuple, session));
        }
        else {
            // 旧的会话，更新会话信息
            session = sessionMap[tuple];
            session->end_time = packet->time;
            if (packet->protocol != "TCP" && packet->protocol != "UDP") {
                session->app_proto = packet->protocol;
            }
        }

        // 共同的字段更新
        {
            session->packet_count++;
            session->total_bytes += packet->len;
            packet->belong_session_id = session->session_id;
        }

        // 统计双方的交互数据
        if (session->ip1 == packet->src_ip) {
            session->ip1_send_packets_count++;
            session->ip1_send_bytes_count += packet->len;
        }
        else {
            session->ip2_send_packets_count++;
            session->ip2_send_bytes_count += packet->len;
        }

        storeLock.lock();
        // 将数据包加入到会话中
        sessionSetTobeStore.insert(session);
        storeLock.unlock();
    }
}

void TsharkManager::queryPackets(QueryCondition& queryConditon, std::vector<std::shared_ptr<Packet>> &packets) {
    storage->queryPackets(queryConditon, packets);
}

void TsharkManager::querySessions(QueryCondition& condition, std::vector<std::shared_ptr<Session>>& sessionList) {
    storage->querySessions(condition, sessionList);
}

// 将数据包格式转换为旧的pcap格式
bool TsharkManager::convertToPcap(const std::string& inputFile, const std::string& outputFile) {
    // 构建 editcap 命令，将 pcapng 转换为 pcap 格式
    std::string command = editcapPath + " -F pcap " + inputFile + " " + outputFile;
    if (!ProcessUtil::Exec(command)) {
        LOG_F(ERROR, "Failed to convert to pcap format, command: %s", command.c_str());
        return false;
    }

    LOG_F(INFO, "Successfully converted %s to %s in pcap format", inputFile.c_str(), outputFile.c_str());
    return true;
}

void TsharkManager::reset() {

    LOG_F(INFO, "reset called");

    // 如果还在抓包或者分析文件，将其停止
    if (workStatus == STATUS_CAPTURING) {
        stopCapture();
    }
    else if (workStatus == STATUS_MONITORING) {
        stopMonitorAdaptersFlowTrend();
    }

    workStatus = STATUS_IDLE;
    captureTsharkPid = 0;
    stopFlag = true;


    allPackets.clear();
    packetsTobeStore.clear();
    sessionSetTobeStore.clear();


    if (captureWorkThread) {
        captureWorkThread->join();
        captureWorkThread.reset();
    }
    if (storageThread) {
        storageThread->join();
        storageThread.reset();
    }

    // 删除之前的数据，重新开始
    remove(currentFilePath.c_str());
    currentFilePath = "";

    // 重置数据库
    storage.reset();    // 析构旧的对象，关闭旧数据库文件的占用
    std::string dbFullPath = this->workDir + "/mytshark.db";
    remove(dbFullPath.c_str());
    storage = std::make_shared<TsharkDatabase>(dbFullPath);
}

WORK_STATUS TsharkManager::getWorkStatus() {
    std::unique_lock<std::recursive_mutex> lock(workStatusLock);
    return workStatus;
}

// 打印所有会话的信息
void TsharkManager::printAllSessions() {
    for (auto& item : sessionMap) {
        rapidjson::Document doc(kObjectType);
        item.second->toJsonObj(doc, doc.GetAllocator());

        // 序列化为 JSON 字符串
        rapidjson::StringBuffer buffer;
        rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
        doc.Accept(writer);

        // 打印JSON输出
        std::cout << buffer.GetString() << std::endl;
    }
}
