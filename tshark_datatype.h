#pragma once
#ifndef TSHARK_DATATYPE_H
#define TSHARK_DATATYPE_H
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <cstdint>
#include <set>
#include <string>
#include <map>
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "utils/misc_util.hpp"

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

// IP通信统计信息
struct IPStatsInfo : public BaseDataObject {
    std::string ip;
    std::string location;
    double earliest_time = 0.0;
    double latest_time = 0.0;
    std::set<int> ports;
    std::set<std::string> protocols; // 通信协议集合（包括transProto与appProto）

    // 数据统计
    int total_sent_packets = 0;
    int total_recv_packets = 0;
    int total_sent_bytes = 0;
    int total_recv_bytes = 0;
    int tcp_session_count = 0;
    int udp_session_count = 0;

    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        obj.AddMember("ip", rapidjson::Value(ip.c_str(), allocator), allocator);
        obj.AddMember("location", rapidjson::Value(location.c_str(), allocator), allocator);
        std::string s_protocols = MiscUtil::convertSetToString(protocols, ',');
        obj.AddMember("proto", rapidjson::Value(s_protocols.c_str(), allocator), allocator);

        rapidjson::Value portsValue;
        portsValue.SetArray();
        for (auto port : ports) {
            portsValue.PushBack(rapidjson::Value(port), allocator);
        }
        obj.AddMember("ports", portsValue, allocator);

        obj.AddMember("earliest_time", earliest_time, allocator);
        obj.AddMember("latest_time", latest_time, allocator);
        obj.AddMember("total_sent_packets", total_sent_packets, allocator);
        obj.AddMember("total_recv_packets", total_recv_packets, allocator);
        obj.AddMember("total_sent_bytes", total_sent_bytes, allocator);
        obj.AddMember("total_recv_bytes", total_recv_bytes, allocator);
        obj.AddMember("tcp_session_count", tcp_session_count, allocator);
        obj.AddMember("udp_session_count", udp_session_count, allocator);
    }
};

// 协议统计信息
struct ProtoStatsInfo : public BaseDataObject {

    std::string proto;
    int total_packets = 0;
    int total_bytes = 0;
    int session_count = 0;
    std::string proto_description;

    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        obj.AddMember("proto", rapidjson::Value(proto.c_str(), allocator), allocator);
        obj.AddMember("total_packets", total_packets, allocator);
        obj.AddMember("total_bytes", total_bytes, allocator);
        obj.AddMember("session_count", session_count, allocator);
        obj.AddMember("proto_description", rapidjson::Value(proto_description.c_str(), allocator), allocator);
    }
};

// 区域统计信息
struct RegionStatsInfo : public BaseDataObject {

    std::string region;
    int total_packets = 0;
    int total_bytes = 0;
    int session_count = 0;
    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        obj.AddMember("region", rapidjson::Value(region.c_str(), allocator), allocator);
        obj.AddMember("total_packets", total_packets, allocator);
        obj.AddMember("total_bytes", total_bytes, allocator);
        obj.AddMember("session_count", session_count, allocator);
    }
};

// 数据流条目结构
class DataStreamItem : public BaseDataObject {
public:
    std::string hexData;
    std::string srcNode;
    std::string dstNode;

    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        obj.AddMember("hexData", rapidjson::Value(hexData.c_str(), allocator), allocator);
        obj.AddMember("srcNode", rapidjson::Value(srcNode.c_str(), allocator), allocator);
        obj.AddMember("dstNode", rapidjson::Value(dstNode.c_str(), allocator), allocator);
    }
};

// 数据流统计信息
class DataStreamCountInfo : public BaseDataObject {
public:
    uint32_t totalPacketCount = 0;
    std::string node0;
    uint32_t node0PacketCount = 0;
    uint32_t node0BytesCount = 0;
    std::string node1;
    uint32_t node1PacketCount = 0;
    uint32_t node1BytesCount = 0;

    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        obj.AddMember("totalPacketCount", totalPacketCount, allocator);

        obj.AddMember("node0", rapidjson::Value(node0.c_str(), allocator), allocator);
        obj.AddMember("node0PacketCount", node0PacketCount, allocator);
        obj.AddMember("node0BytesCount", node0BytesCount, allocator);

        obj.AddMember("node1", rapidjson::Value(node1.c_str(), allocator), allocator);
        obj.AddMember("node1PacketCount", node1PacketCount, allocator);
        obj.AddMember("node1BytesCount", node1BytesCount, allocator);
    }
};

class ProtoList {
public:
    ProtoList() {
        protocolMap = {
            {"TCP", "传输控制协议，构建在IP之上，提供可靠、有序、无差错的数据传输，并具备流量与拥塞控制能力。"},
            {"UDP", "用户数据报协议，面向无连接，传输速度快但不保证可靠性，适用于实时应用和少量数据传输。"},
            {"HTTP", "超文本传输协议，常用于浏览器与服务器之间的网页数据传输，基于请求-响应模式进行通信。"},
            {"HTTPS", "加密版HTTP，通过TLS或SSL建立安全信道，保护传输数据的完整性与机密性，广泛用于网站登录与支付。"},
            {"DNS", "域名系统协议，用于将域名解析为IP地址，支持正向解析与反向解析，维护互联网主机命名体系。"},
            {"TLS", "传输层安全协议，为应用层数据提供加密与完整性校验，通常用于HTTPS等场景确保通信安全。"},
            {"SSL", "安全套接字层协议，TLS 的前身，曾被广泛用于加密数据传输，现多被TLS替代但在部分场景仍可见。"},
            {"ARP", "地址解析协议，用于在局域网中通过IP地址获取对应的MAC地址，在以太网环境下尤为重要。"},
            {"ICMP", "互联网控制报文协议，传输差错与控制信息，例如ping和traceroute等诊断工具依赖其回显与报文功能。"},
            {"DHCP", "动态主机配置协议，用于自动分配IP地址、网关、DNS等网络配置信息，大幅简化网络管理。"},
            {"FTP", "文件传输协议，使用TCP作为底层协议，可在客户端与服务器之间进行文件的上传与下载操作。"},
            {"SSH", "安全外壳协议，为远程登录与其他网络服务提供安全加密通道，常用于替代Telnet进行安全操作。"},
            {"Telnet", "早期的远程登录协议，缺乏加密，通信内容明文传输，已逐渐被SSH等更安全的协议取代。"},
            {"SMTP", "简单邮件传输协议，用于在邮件服务器之间或邮件客户端与服务器之间发送电子邮件。"},
            {"POP", "邮局协议，用户从邮件服务器获取邮件后默认会将其本地化，常见版本为POP3，使用简单且高效。"},
            {"IMAP", "Internet邮件访问协议，支持在服务器端管理邮件，客户端可与服务器保持同步并进行多文件夹操作。"},
            {"LDAP", "轻量级目录访问协议，主要用于查询和修改目录服务信息，常见于企业级用户/权限管理系统。"},
            {"NTP", "网络时间协议，通过UDP实现的时间同步服务，保证各网络设备间时间的一致性。"},
            {"SNMP", "简单网络管理协议，用于集中监控和管理网络设备，常收集设备CPU、内存、接口流量等信息。"},
            {"RIP", "路由信息协议，距离矢量路由协议的一种，使用跳数作为路由度量，适用于小规模网络环境。"},
            {"OSPF", "开放最短路径优先协议，链路状态路由协议之一，支持大型网络和区域划分，收敛速度快。"},
            {"BGP", "边界网关协议，用于跨自治系统（AS）间的路由信息交换，是互联网的核心路由协议。"},
            {"PPTP", "点对点隧道协议，基于PPP封装的数据隧道技术之一，常用于VPN连接但安全性较弱。"},
            {"L2TP", "第二层隧道协议，与IPSec结合使用时可提供更安全的VPN隧道，广泛应用于远程访问场景。"},
            {"GRE", "通用路由封装协议，用于在不同网络之间封装各类第三层协议，常见于隧道与VPN场景。"},
            {"IPsec", "IP安全协议套件，通过加密与认证保障IP层数据的机密性与完整性，多用于VPN部署与安全通信。"},
            {"SCTP", "流控制传输协议，面向消息传输，支持多宿主与多流，常在电信及实时信令传输场景使用。"},
            {"RTSP", "实时流协议，适合控制多媒体流传输，常与RTP/RTCP配合使用，实现点播与直播功能。"},
            {"RTP", "实时传输协议，用于在网络上传输音视频流，结合RTCP进行传输质量控制，常见于会议系统。"},
            {"RTCP", "实时传输控制协议，与RTP协作用于监控传输质量、统计QoS等，为流媒体传输提供反馈机制。"},
            {"TFTP", "简单文件传输协议，基于UDP，通常用于在网络设备中传输配置文件或在PXE启动过程中下载镜像。"},
            {"Gopher", "一种早期的文档检索与发布协议，使用分层菜单结构访问信息资源，在万维网发展后逐渐式微。"},
            {"TLSv1", "TLS协议的一个早期版本，提供数据加密与完整性校验，兼容性与安全性兼顾。"},
            {"TLSv1.2", "TLS协议的一个较常用版本，提供数据加密与完整性校验，兼容性与安全性兼顾。"},
            {"TLSv1.3", "TLS协议的最新主流版本，引入零RTT握手与更安全的加密套件，提升网络通信的效率与安全性。"},
            {"QUIC", "谷歌提出的基于UDP的传输协议，集成TLS加密，提升HTTP/3等应用在弱网络环境下的性能表现。"},
            {"RADIUS", "远程身份验证拨号用户服务，采用UDP封装，集中管理网络用户的认证、授权与计费信息。"},
            {"Diameter", "RADIUS 的升级版，提供更丰富的消息与扩展特性，常用于电信运营商计费、认证与策略控制。"},
            {"NetBIOS", "网络基本输入输出系统，为局域网内计算机提供名字解析与会话服务，常见于Windows网络。"},
            {"SMB", "服务器消息块协议，用于在Windows网络中共享文件、打印机和其他资源，也称CIFS。"},
            {"CIFS", "通用Internet文件系统，SMB协议的前期版本，主要用于远程文件访问与资源共享。"},
            {"Kerberos", "网络身份认证协议，使用对称密钥与票据机制，为客户端与服务器之间的通信提供安全验证。"},
            {"Syslog", "系统日志协议，以UDP或TCP为传输方式，将设备或系统的日志消息集中发送到日志服务器进行记录。"},
            {"MQTT", "消息队列遥测传输协议，基于发布/订阅模型，适合物联网等低带宽、高延迟或不稳定网络环境。"},
            {"CoAP", "受限应用协议，专为资源受限的物联网设备设计，基于UDP并采用REST风格的交互方式。"},
            {"AMQP", "高级消息队列协议，提供消息中间件功能，支持可靠消息传递与灵活的路由机制。"},
            {"SOAP", "简单对象访问协议，以XML格式封装的远程调用协议，在Web服务中曾被广泛采用。"},
            {"WSDL", "Web服务描述语言，用于描述SOAP Web服务的接口、消息格式与访问地址，基于XML进行定义。"},
            {"XML-RPC", "基于HTTP和XML的远程过程调用协议，使用简单的请求-响应模型，早期Web服务通信的一种实现。"},
            {"JSON-RPC", "轻量级的远程过程调用协议，用JSON格式封装数据，基于HTTP或其他传输层实现跨平台调用。"},
            {"WebSocket", "全双工通信协议，基于HTTP握手，可在浏览器与服务器之间建立持续的双向消息通道。"},
            {"SPDY", "由谷歌提出的实验性协议，优化HTTP传输效率，通过多路复用与压缩等手段减少网络延迟。"},
            {"HTTP/2", "HTTP协议的升级版本，引入二进制分帧、多路复用与头部压缩，为网站加快加载速度。"},
            {"HTTP/3", "基于QUIC的下一代HTTP协议，支持快速握手与更高效的流控制，在弱网络环境下表现更佳。"},
            {"DoH", "DNS over HTTPS，通过HTTPS加密域名解析请求，防止DNS查询被窃听或篡改，提高隐私与安全。"},
            {"DoT", "DNS over TLS，基于TLS加密DNS流量，保护解析请求不被截获或篡改，是传统DNS的安全增强方案。"},
            {"SRTP", "安全实时传输协议，在RTP的基础上增加加密与认证，用于保护音视频流免受窃听或篡改。"},
            {"MGCP", "媒体网关控制协议，早期VoIP场景下的集中式呼叫控制协议，用于呼叫代理与网关之间的通信。"},
            {"H.323", "ITU-T制定的多媒体通信标准，包含呼叫信令、媒体协商和传输等子协议，早期视频会议的主流。"},
            {"SIP", "会话发起协议，主要用于IP网络中的语音、视频通话及即时消息，定义呼叫建立与终止流程。"},
            {"SCCP", "Signaling Connection Control Part，常用于Cisco的呼叫管理系统，与VoIP中的呼叫信令相关。"},
            {"IKE", "互联网密钥交换协议，为IPsec提供自动密钥协商与安全策略管理，确保VPN的加密可靠性。"},
            {"ISAKMP", "互联网安全协会和密钥管理协议，定义了IPsec中用于建立安全关联(SA)的框架与消息格式。"},
            {"FCoE", "以太网上的光纤通道协议，将光纤通道帧封装在以太网中传输，整合存储网络与以太网络。"},
            {"FibreChannel", "光纤通道协议，用于在专用存储区域网络（SAN）中提供高速、低延迟的数据块传输。"},
            {"AoE", "ATA over Ethernet，将ATA协议封装在以太网中，简化存储网络部署，适合本地局域环境。"},
            {"iSCSI", "基于IP的SCSI封装协议，通过TCP/IP网络传输存储指令，广泛用于服务器与存储设备交互。"},
            {"EIGRP", "增强型内部网关路由协议，Cisco私有的高级距离矢量协议，具有快速收敛与低带宽占用特点。"},
            {"HSRP", "热备份路由协议，Cisco私有协议，实现网关冗余，确保网关故障时网络客户端仍可正常访问。"},
            {"VRRP", "虚拟路由冗余协议，与HSRP类似但为开放标准协议，多台路由器通过选举方式实现网关冗余。"},
            {"GLBP", "网关负载均衡协议，Cisco私有协议，可在多台路由器之间负载均衡流量，同时提供冗余能力。"},
            {"LLDP", "链路层发现协议，允许网络设备互相通告自身信息，如设备标识、端口信息，方便网络拓扑管理。"},
            {"CDP", "Cisco发现协议，Cisco设备间专用，用于发现相邻设备信息，协助网络管理员进行拓扑规划。"},
            {"STP", "生成树协议，为以太网生成无环拓扑，防止交换网络出现二层环路，保护网络稳定性。"},
            {"RSTP", "快速生成树协议，STP的改进版本，通过更快的收敛机制减少生成树重计算造成的网络中断时间。"},
            {"MSTP", "多生成树协议，允许在一个网络中维护多条逻辑生成树，充分利用链路资源进行负载分担。"},
            {"VLAN", "虚拟局域网技术，通过划分广播域提高网络灵活性与安全性，可在三层或二层交换机上配置。"},
            {"QinQ", "双层 VLAN 封装技术，将一个 VLAN Tag 封装在另一个 VLAN Tag 中，适用于运营商级二层转发。"},
            {"PPP", "点对点协议，常用于串行链路或拨号连接，提供链路配置、鉴权及错误检测等功能。"},
            {"PPPoE", "以太网上的PPP协议，广泛应用于ADSL或光纤入户宽带拨号，通过PPPoE会话建立IP连接。"},
            {"LCP", "链路控制协议，PPP 框架的一部分，用于建立、配置和测试数据链路连接的有效性。"},
            {"NCP", "网络控制协议，PPP协议族中的一部分，负责为不同网络层协议（如IP、IPX）配置和协商参数。"},
            {"HDLC", "高级数据链路控制协议，面向比特的同步通信协议，常用于点对点或帧中继链路承载。"},
            {"FrameRelay", "早期的分组交换技术，基于虚电路提供连接管理，曾在广域网构建中得到广泛应用。"},
            {"X.25", "一种面向连接的分组交换协议，历史悠久，支持错误纠正与流量控制，早期广域网主流方案。"},
            {"GTP", "GPRS隧道协议，移动通信网络中承载用户数据平面与控制平面流量，关键于2G/3G/4G核心网。"},
            {"GTPv2", "GTP协议的改进版本，用于4G LTE核心网，优化了控制平面流程与承载建立效率。"},
            {"MMS", "多媒体消息服务，移动通信中用于发送图片、音频、视频等富媒体内容，基于WAP或数据通道。"},
            {"MMS-Encap", "MMS 在网络上所使用的封装协议形式，Wireshark可对其进行解析，显示MMS消息结构。"},
            {"WAP", "无线应用协议，为移动设备提供网络浏览、消息等服务，曾在功能机时代广泛使用。"},
            {"BGP EVPN", "BGP扩展，结合EVPN提供二层VPN服务，通过BGP传递MAC/IP绑定信息，简化数据中心互联。"},
            {"VXLAN", "虚拟可扩展局域网，通过UDP在三层网络构建二层覆盖隧道，支持更大规模的数据中心组网。"},
            {"Geneve", "通用可扩展隧道封装协议，与VXLAN类似但扩展性更强，支持自定义元数据，便于网络虚拟化。"},
            {"OTV", "Overlay Transport Virtualization，Cisco技术，通过在三层网络上构建二层覆盖，实现跨数据中心二层互联。"},
            {"LISP", "位置标识分离协议，将端点标识与位置信息分离，简化地址分配并加速路由收敛。"},
            {"VPLS", "虚拟专用LAN服务，在运营商网络上创建面向用户的二层VPN，所有站点共享同一个广播域。"},
            {"MPLS", "多协议标签交换，介于第二层和第三层之间，通过标签转发快速传输IP、以太网等多种协议。"},
            {"RSVP", "资源预留协议，为IP网络提供资源预留与服务质量保障，通过信令在路径上建立带宽预留。"},
            {"LDP", "标签分发协议，MPLS网络中的基础协议，用于在路由器间分发标签信息以建立标签转发路径。"},
            {"TE", "流量工程(traffic engineering)，可基于RSVP-TE或CR-LDP等协议，为网络流量分配最佳路径。"},
            {"BFD", "双向转发检测协议，用于快速检测两端之间通信链路的可达性，提升故障探测与收敛速度。"},
            {"QUIC", "一种基于UDP的传输协议，集成加密与多路复用，减少握手延迟，对HTTP/3具有重要意义。"},
            {"BitTorrent", "分布式文件共享协议，用户通过P2P网络下载资源，大幅提升大文件传输效率。"},
            {"MDNS", "多播DNS协议，在局域网内提供名称解析及设备发现功能，无需外部DNS服务器。"},
            {"LLMNR", "链路本地多播名称解析协议，主要用于Windows环境，在局域网内解析主机名，无需传统DNS。"},
            {"X11", "一种图形窗口系统协议，可在网络环境中运行远程图形界面，常用于Linux/Unix平台。"},
            {"NBNS", "NetBIOS名称服务，通过广播/多播方式解析主机名与IP地址，常见于早期Windows网络。"},
            {"STUN", "主要用于帮助终端设备在存在网络地址转换（NAT）和防火墙的情况下，获取并识别自身在外部网络中的公共IP地址和端口" },
            {"SSDP", "简单服务发现协议（Simple Service Discovery Protocol）是 UPnP架构中的一部分，用于在局域网中自动发现设备与服务。"},
            {"DTLS", "基于 UDP实现的 TLS协议变体。它为无连接、不可靠的传输提供安全特性" },
            {"DTLSv1.2", "基于 UDP实现的 TLS协议变体。它为无连接、不可靠的传输提供安全特性" },
            {"DTLSv1.3", "基于 UDP实现的 TLS协议变体。它为无连接、不可靠的传输提供安全特性" }
        };
    }

    // 获取协议的描述信息
    std::string getProtoDesc(std::string proto) {
        if (protocolMap.find(proto) != protocolMap.end()) {
            return protocolMap[proto];
        }
        else {
            return "";
        }
    }

private:
    std::map<std::string, std::string> protocolMap;
};

#endif // TSHARK_DATATYPE_H
