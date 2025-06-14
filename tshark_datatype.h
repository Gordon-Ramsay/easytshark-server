#pragma once
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <cstdint>
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

class BaseDataObject {
public:
    // 将对象转换为JSON Value，用于转换为JSON格式输出
    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const = 0;
};

class Packet{
public:
    int frame_number;
    double time;
    uint32_t cap_len;
    uint32_t len;
    std::string src_mac;
    std::string dst_mac;
    std::string src_ip;
    std::string src_location;
    uint16_t src_port;
    std::string dst_ip;
    std::string dst_location;
    uint16_t dst_port;
    std::string trans_proto;       // 传输层协议
    std::string protocol;
    std::string info;
    uint32_t file_offset;
    uint32_t belong_session_id;    // 所属的会话ID，为0表示不属于任何会话

    void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        rapidjson::Value pktObj(rapidjson::kObjectType);
        obj.AddMember("frame_number", frame_number, allocator);
        obj.AddMember("timestamp", time, allocator);
        obj.AddMember("src_mac", rapidjson::Value(src_mac.c_str(), allocator), allocator);
        obj.AddMember("dst_mac", rapidjson::Value(dst_mac.c_str(), allocator), allocator);
        obj.AddMember("src_ip", rapidjson::Value(src_ip.c_str(), allocator), allocator);
        obj.AddMember("src_location", rapidjson::Value(src_location.c_str(), allocator), allocator);
        obj.AddMember("src_port", src_port, allocator);
        obj.AddMember("dst_ip", rapidjson::Value(dst_ip.c_str(), allocator), allocator);
        obj.AddMember("dst_location", rapidjson::Value(dst_location.c_str(), allocator), allocator);
        obj.AddMember("dst_port", dst_port, allocator);
        obj.AddMember("protocol", rapidjson::Value(protocol.c_str(), allocator), allocator);
        obj.AddMember("len", len, allocator);
        obj.AddMember("cap_len", cap_len, allocator);
        obj.AddMember("protocol", rapidjson::Value(protocol.c_str(), allocator), allocator);
        obj.AddMember("info", rapidjson::Value(info.c_str(), allocator), allocator);
        obj.AddMember("file_offset", file_offset, allocator);
    }
};


// 会话信息
class Session : public BaseDataObject {
public:
    uint32_t session_id;
    std::string ip1;
    uint16_t ip1_port;
    std::string ip1_location;
    std::string ip2;
    uint16_t ip2_port;
    std::string ip2_location;
    std::string trans_proto;
    std::string app_proto;
    double start_time;
    double end_time;
    uint32_t ip1_send_packets_count;   // ip1发送的数据包数
    uint32_t ip1_send_bytes_count;     // ip1发送的字节数
    uint32_t ip2_send_packets_count;   // ip2发送的数据包数
    uint32_t ip2_send_bytes_count;     // ip2发送的字节数
    uint32_t packet_count;           // 数据包数量
    uint32_t total_bytes;            // 总字节数、

    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        obj.AddMember("session_id", session_id, allocator);
        obj.AddMember("ip1", rapidjson::Value(ip1.c_str(), allocator), allocator);
        obj.AddMember("ip1_port", ip1_port, allocator);
        obj.AddMember("ip1_location", rapidjson::Value(ip1_location.c_str(), allocator), allocator);
        obj.AddMember("ip2", rapidjson::Value(ip2.c_str(), allocator), allocator);
        obj.AddMember("ip2_port", ip2_port, allocator);
        obj.AddMember("ip2_location", rapidjson::Value(ip2_location.c_str(), allocator), allocator);
        obj.AddMember("trans_proto", rapidjson::Value(trans_proto.c_str(), allocator), allocator);
        obj.AddMember("app_proto", rapidjson::Value(app_proto.c_str(), allocator), allocator);
        obj.AddMember("start_time", start_time, allocator);
        obj.AddMember("end_time", end_time, allocator);
        obj.AddMember("ip1_send_packets_count", ip1_send_packets_count, allocator);
        obj.AddMember("ip1_send_bytes_count", ip1_send_bytes_count, allocator);
        obj.AddMember("ip2_send_packets_count", ip2_send_packets_count, allocator);
        obj.AddMember("ip2_send_bytes_count", ip2_send_bytes_count, allocator);
        obj.AddMember("packet_count", packet_count, allocator);
        obj.AddMember("total_bytes", total_bytes, allocator);
    }
};

// 定义五元组
class FiveTuple {
public:
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    std::string trans_proto;

    // 重载比较操作符，用于 unordered_map 的键比较，确保会话对称性
    bool operator==(const FiveTuple& other) const {
        return ((src_ip == other.src_ip && dst_ip == other.dst_ip && src_port == other.src_port && dst_port == other.dst_port)
                || (src_ip == other.dst_ip && dst_ip == other.src_ip && src_port == other.dst_port && dst_port == other.src_port))
                && trans_proto == other.trans_proto;
    }
};


// 定义哈希函数，确保会话对称性
class FiveTupleHash {
public:
    std::size_t operator()(const FiveTuple& tuple) const {
        std::hash<std::string> hashFn;
        std::size_t h1 = hashFn(tuple.src_ip);
        std::size_t h2 = hashFn(tuple.dst_ip);
        std::size_t h3 = std::hash<uint16_t>()(tuple.src_port);
        std::size_t h4 = std::hash<uint16_t>()(tuple.dst_port);

        // 返回源和目的地址/端口的哈希组合，支持对称性
        std::size_t directHash = h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3);
        std::size_t reverseHash = h2 ^ (h1 << 1) ^ (h4 << 2) ^ (h3 << 3);

        // 确保无论是正向还是反向，都会返回相同的哈希值
        return directHash ^ reverseHash ^ tuple.trans_proto[0];
    }
};

// PCAP全局文件头
struct PcapHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

// 每一个数据报文前面的头
struct PacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t len;
};

// 网卡信息
struct AdapterInfo {
    int id;
    std::string name;
    std::string remark;
};

// 查询条件
class QueryCondition {
public:
    std::string ip;
    uint16_t port = 0;
    std::string proto;

    uint32_t session_id = 0;
};

