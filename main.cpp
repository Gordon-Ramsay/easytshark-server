#include "tshark_manager.h"
#include <filesystem> // C++17 文件系统库
namespace fs = std::filesystem;

bool InitLog(int argc, char* argv[]) {
    loguru::init(argc, argv);
    loguru::add_file("log.txt", loguru::Append, loguru::Verbosity_MAX);
    LOG_F(INFO, "Log file initialized successfully.");
    return true;
}

int main(int argc, char* argv[]) {

    // 设置控制台环境编码为UTF-8格式，防止打印输出的内容乱码
    setlocale(LC_ALL, "zh_CN.UTF-8");

    InitLog(argc, argv);

    TsharkManager tsharkManager("F:/cppProject/tsharkwithui");

{   // 抓取指定网卡数据包
    tsharkManager.startCapture("\\Device\\NPF_{BD18A809-4793-43BC-A0FD-788A3633A983}");

    // 主线程进入命令等待停止抓包
    std::string input;
    while (true) {
        std::cout << "请输入q退出抓包: ";
        std::cin >> input;
        if (input == "q") {
            tsharkManager.stopCapture();
            break;
        }
    }

    // 打印所有捕获到的数据包信息
    tsharkManager.printAllPackets();
}

// {// 监控网卡流量
//     // 启动监控
//     tsharkManager.startMonitorAdaptersFlowTrend();

//     // 睡眠10秒，等待监控网卡数据
//     std::this_thread::sleep_for(std::chrono::seconds(10));

//     // 读取监控到的数据
//     std::map<std::string, std::map<long, long>> trendData;
//     tsharkManager.getAdaptersFlowTrendData(trendData);

//     // 停止监控
//     tsharkManager.stopMonitorAdaptersFlowTrend();

//     // 把获取到的数据打印输出
//     rapidjson::Document resDoc;
//     rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
//     resDoc.SetObject();
//     rapidjson::Value dataObject(rapidjson::kObjectType);
//     for (const auto &adaptorItem : trendData) {
//         rapidjson::Value adaptorDataList(rapidjson::kArrayType);
//         for (const auto &timeItem : adaptorItem.second) {
//             rapidjson::Value timeObj(rapidjson::kObjectType);
//             timeObj.AddMember("time", (unsigned int)timeItem.first, allocator);
//             timeObj.AddMember("bytes", (unsigned int)timeItem.second, allocator);
//             adaptorDataList.PushBack(timeObj, allocator);
//         }

//         dataObject.AddMember(rapidjson::StringRef(adaptorItem.first.c_str()), adaptorDataList, allocator);
//     }

//     resDoc.AddMember("data", dataObject, allocator);

//     // 序列化为 JSON 字符串
//     rapidjson::StringBuffer buffer;
//     rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
//     resDoc.Accept(writer);

//     LOG_F(INFO, "网卡流量监控数据: %s", buffer.GetString());
// }

{   // 分析指定的pcap文件
    std::string pcapFilePath = "";
    std::cout << "请输入要分析的pcap文件路径: ";
    std::cin >> pcapFilePath;
    if (tsharkManager.analysisFile(pcapFilePath)) {
        LOG_F(INFO, "分析文件成功: %s", pcapFilePath.c_str());
    } else {
        LOG_F(ERROR, "分析文件失败: %s", pcapFilePath.c_str());
    }

    std::cout<<"请输入要获取详情的数据包编号（1-"<<tsharkManager.getAllPacketsCount()<<"）: ";

    uint32_t frameNumber;
    std::cin >> frameNumber;

    std::string packetDetail;
    if (tsharkManager.getPacketDetailInfo(frameNumber, packetDetail)) {
        LOG_F(INFO, "数据包详情: %s", packetDetail.c_str());
    } else {
        LOG_F(ERROR, "获取数据包详情失败，可能是编号错误");
    }

    // 保存到本地文件（当前目录）
    std::string filename = std::to_string(frameNumber) + ".json";

    try {
        std::ofstream outFile(filename);
        if (outFile.is_open()) {
            outFile << packetDetail;
            outFile.close();
            LOG_F(INFO, "数据包详情已保存到文件: %s", filename.c_str());
        } else {
            LOG_F(ERROR, "无法创建文件: %s", filename.c_str());
        }
    } catch (const std::exception& e) {
        LOG_F(ERROR, "保存文件时出错: %s (错误: %s)", filename.c_str(), e.what());
    } catch (...) {
        LOG_F(ERROR, "未知错误发生在保存文件: %s", filename.c_str());
    }
}

    return 0;
}