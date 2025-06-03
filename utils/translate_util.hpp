#include "rapidjson/document.h"
#include <map>


class TranslateUtil {

private:
    std::map<std::string, std::string> translationMap = {
        {"General information", "常规信息"},
        {"Frame Number", "帧编号"},
        {"Captured Length", "捕获长度"},
        {"Captured Time", "捕获时间"},
        {"Section number", "节号"},
        {"Interface id", "接口 id"},
        {"Interface name", "接口名称"},
        {"Encapsulation type", "封装类型"},
        {"Arrival Time", "到达时间"},
        {"UTC Arrival Time", "UTC到达时间"},
        {"Epoch Arrival Time", "纪元到达时间"},
        {"Time shift for this packet", "该数据包的时间偏移"},
        {"Time delta from previous captured frame", "与上一个捕获帧的时间差"},
        {"Time delta from previous displayed frame", "与上一个显示帧的时间差"},
        {"Time since reference or first frame", "自参考帧或第一帧以来的时间"},
        {"Frame Number", "帧编号"},
        {"Frame Length", "帧长度"},
        {"Capture Length", "捕获长度"},
        {"Frame is marked", "帧标记"},
        {"Frame is ignored", "帧忽略"},
        {"Frame", "帧"},
        {"Protocols in frame", "帧中的协议"},
        {"Ethernet II", "以太网 II"},
        {"Destination", "目的地址"},
        {"Address Resolution Protocol", "ARP地址解析地址"},
        {"Address (resolved)", "地址（解析后）"},
        {"Type", "类型"},
        {"Stream index", "流索引"},
        {"Internet Protocol Version 4", "互联网协议版本 4"},
        {"Internet Protocol Version 6", "互联网协议版本 6"},
        {"Internet Control Message Protocol", "互联网控制消息协议ICMP"},
        {"Version", "版本"},
        {"Header Length", "头部长度"},
        {"Differentiated Services Field", "差分服务字段"},
        {"Total Length", "总长度"},
        {"Identification", "标识符"},
        {"Flags", "标志"},
        {"Time to Live", "生存时间"},
        {"Transmission Control Protocol", "TCP传输控制协议"},
        {"User Datagram Protocol", "UDP用户数据包协议"},
        {"Domain Name System", "DNS域名解析系统"},
        {"Header Checksum", "头部校验和"},
        {"Header checksum status", "校验和状态"},
        {"Source Address", "源地址"},
        {"Destination Address", "目的地址"},
        {"Source Port", "源端口"},
        {"Destination Port", "目的端口"},
        {"Next Sequence Number", "下一个序列号"},
        {"Sequence Number", "序列号"},
        {"Acknowledgment Number", "确认号"},
        {"Acknowledgment number", "确认号"},
        {"TCP Segment Len", "TCP段长度"},
        {"Conversation completeness", "会话完整性"},
        {"Window size scaling factor", "窗口缩放因子"},
        {"Calculated window size", "计算窗口大小"},
        {"Window", "窗口"},
        {"Urgent Pointer", "紧急指针"},
        {"Checksum:", "校验和:"},
        {"TCP Option - Maximum segment size", "TCP选项 - 最大段大小"},
        {"Kind", "种类"},
        {"MSS Value", "MSS值"},
        {"TCP Option - Window scale", "TCP选项 - 窗口缩放"},
        {"Shift count", "移位计数"},
        {"Multiplier", "倍数"},
        {"TCP Option - Timestamps", "TCP选项 - 时间戳"},
        {"TCP Option - SACK permitted", "TCP选项 - SACK 允许"},
        {"TCP Option - End of Option List", "TCP选项 - 选项列表结束"},
        {"Options", "选项"},
        {"TCP Option - No-Operation", "TCP选项 - 无操作"},
        {"Timestamps", "时间戳"},
        {"Time since first frame in this TCP stream", "自第一帧以来的时间"},
        {"Time since previous frame in this TCP stream", "与上一个帧的时间差"},
        {"Protocol:", "协议:"},
        {"Source:", "源地址:"},
        {"Length:", "长度:"},
        {"Checksum status", "校验和状态"},
        {"Checksum Status", "校验和状态"},
        {"TCP payload", "TCP载荷"},
        {"UDP payload", "UDP载荷"},
        {"Hypertext Transfer Protocol", "超文本传输协议HTTP"},
        {"Transport Layer Security", "传输层安全协议TLS"}
    };
public:
    // 递归翻译 showname 字段
    void translateShowNameFields(rapidjson::Value& value, rapidjson::Document::AllocatorType& allocator) {
        // 如果是对象，检查并翻译 showname 字段
        if (value.IsObject()) {
            if (value.HasMember("showname") && value["showname"].IsString()) {
                std::string showname = value["showname"].GetString();

                // 遍历 translationMap 查找静态部分并替换
                for (const auto& pair : translationMap) {
                    const std::string& key = pair.first;
                    const std::string& translation = pair.second;

                    // 检查字段A中是否包含translationMap中的key（静态部分）
                    if (showname.find(key) == 0) {
                        // 替换静态部分
                        showname.replace(0, key.length(), translation);
                        value["showname"].SetString(showname.c_str(), allocator);
                        break;
                    }
                }
            }
            else if (value.HasMember("show") && value["show"].IsString()) {
                std::string showname = value["show"].GetString();

                // 遍历 translationMap 查找静态部分并替换
                for (const auto& pair : translationMap) {
                    const std::string& key = pair.first;
                    const std::string& translation = pair.second;

                    // 检查字段A中是否包含translationMap中的key（静态部分）
                    if (showname.find(key) == 0) {
                        // 替换静态部分
                        showname.replace(0, key.length(), translation);
                        value["show"].SetString(showname.c_str(), allocator);
                        break;
                    }
                }
            }

            // 如果有 "field" 字段，递归处理
            if (value.HasMember("field") && value["field"].IsArray()) {
                // 直接引用 "field" 数组中的每个元素进行递归翻译
                rapidjson::Value& fieldArray = value["field"];
                for (auto& field : fieldArray.GetArray()) {
                    translateShowNameFields(field, allocator);  // 递归处理每个 field
                }
            }
        }
        // 如果是数组，递归遍历每个元素
        else if (value.IsArray()) {
            for (auto& item : value.GetArray()) {
                translateShowNameFields(item, allocator);  // 递归处理每个元素
            }
        }
    }
};