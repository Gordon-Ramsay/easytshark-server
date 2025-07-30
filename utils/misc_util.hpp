#pragma once
#ifndef MISC_UTIL_HPP
#define MISC_UTIL_HPP

#include <string>
#include <fstream>
#include <sstream>
#include <ctime>
#include <random>
#include <iostream>
#include <sys/stat.h>
#include <set>
#include <chrono>
#include <codecvt>
#include <rapidxml/rapidxml.hpp>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

using namespace rapidxml;
using namespace rapidjson;

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#define make_dir(path) _mkdir(path.c_str())
#define STAT_STRUCT _stat
#define STAT_FUNC _stat
#else
#include <unistd.h>
#include <iostream>

#define STAT_STRUCT stat
#define STAT_FUNC stat
#define make_dir(path) mkdir(path.c_str(), 0755)
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

class MiscUtil {
public:
    // 获得随机字符串
    static std::string getRandomString(size_t length) {
        const std::string chars = "abcdefghijklmnopqrstuvwxyz"
                                  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                  "0123456789";
        std::random_device rd;  // 用于种子
        std::mt19937 generator(rd());  // 生成器
        std::uniform_int_distribution<> distribution(0, chars.size() - 1);

        std::string randomString;
        for (size_t i = 0; i < length; ++i) {
            randomString += chars[distribution(generator)];
        }

        return randomString;
    }

    // 获取数据存储目录
    static std::string getDefaultDataDir() {
        static std::string dir = "";
        if (!dir.empty()) {
            return dir;
        }
#ifdef _WIN32
        dir = std::string(std::getenv("APPDATA")) + "\\easytshark\\";
#else
        dir = std::string(std::getenv("HOME")) + "/easytshark/";
#endif

        createDirectory(dir);
        return dir;
    }

    // 将XML转为JSON格式
    static bool xml2JSON(std::string xmlContent, Document &outJsonDoc) {

        // 解析 XML
        xml_document<> doc;
        try {
            doc.parse<0>(&xmlContent[0]);
        }
        catch (const rapidxml::parse_error& e) {
            std::cout << "XML Parsing error: " << e.what() << std::endl;
            return false;
        }

        // 创建 JSON 文档
        outJsonDoc.SetObject();
        Document::AllocatorType& allocator = outJsonDoc.GetAllocator();

        // 获取 XML 根节点
        xml_node<>* root = doc.first_node();
        if (root) {
            // 将根节点转换为 JSON
            Value root_json(kObjectType);
            xml_to_json_recursive(root_json, root, allocator);

            // 将根节点添加到 JSON 文档
            outJsonDoc.AddMember(Value(root->name(), allocator).Move(), root_json, allocator);
        }
        return true;
    }

    static bool fileExists(const std::string& filename) {
        std::ifstream file(filename);
        return file.good();
    }

    // 通过当前时间戳获取一个pcap文件名
    static std::string getPcapNameByCurrentTimestamp(bool isFullPath=true) {
        // 获取当前时间
        std::time_t now = std::time(nullptr);
        std::tm* localTime = std::localtime(&now);

        // 格式化文件名
        char buffer[64];
        std::strftime(buffer, sizeof(buffer), "easytshark_%Y-%m-%d_%H-%M-%S.pcap", localTime);

        return isFullPath ? getDefaultDataDir() + std::string(buffer) : std::string(buffer);
    }

    static bool directoryExists(const std::string& path) {
        struct stat info;
        return (stat(path.c_str(), &info) == 0 && (info.st_mode & S_IFDIR));
    }

    static bool createDirectory(const std::string& path) {
        // 如果目录已存在，则直接返回 true
        if (directoryExists(path)) {
            return true;
        }

        // 尝试创建父目录
        size_t pos = path.find_last_of("/\\");
        if (pos != std::string::npos) {
            std::string parentDir = path.substr(0, pos);
            if (!createDirectory(parentDir)) {
                return false;
            }
        }

        // 创建当前目录
        if (make_dir(path) == 0) {
            return true;
        } else {
            perror("Error creating directory");
            return false;
        }
    }

    // 简单的字符串分割函数，用于将"1,2,3"之类的字符串分割为set
    static std::set<std::string> splitString(const std::string &str, char delim) {
        std::set<std::string> result;
        std::istringstream iss(str);
        std::string token;
        while (std::getline(iss, token, delim)) {
            if (!token.empty()) {
                result.insert(token);
            }
        }
        return result;
    }

    // 将分割后的string set转换为int set（用于端口列表）
    static std::set<int> toIntVector(const std::set<std::string>& strs) {
        std::set<int> ints;
        for (auto &s : strs) {
            try {
                ints.insert(std::stoi(s));
            } catch (...) {
                // 如果转换失败，可选择忽略或打印错误信息
            }
        }
        return ints;
    }

    // 将set容器中的数据合并为一个字符串
    static std::string convertSetToString(std::set<std::string> dataSets, char delim) {

        std::string result;
        for (auto item : dataSets) {
            if (result.empty()) {
                result = item;
            } else {
                result = result + delim + item;
            }
        }
        return result;
    }

    static void trimEnd(std::string& str) {
        if (str.size() >= 2 && str.substr(str.size() - 2) == "\r\n") {
            str.erase(str.size() - 2);  // 删除末尾的 \r\n
        }
        else if (!str.empty() && str.back() == '\n') {
            str.erase(str.size() - 1);  // 删除末尾的 \n
        }
    }

    // 文件复制函数
    static bool copyFile(const std::string& sourcePath, const std::string& destPath) {
        std::ifstream source(sourcePath, std::ios::binary);
        std::ofstream dest(destPath, std::ios::binary);

        if (!source || !dest) {
            return false;
        }

        // 获取源文件大小
        source.seekg(0, std::ios::end);
        std::streamsize size = source.tellg();
        source.seekg(0, std::ios::beg);

        // 创建缓冲区并复制文件内容
        const std::streamsize bufferSize = 8192; // 8KB缓冲区
        char* buffer = new char[bufferSize];
        
        while (size > 0) {
            std::streamsize bytesToRead = (size > bufferSize) ? bufferSize : size;
            source.read(buffer, bytesToRead);
            dest.write(buffer, source.gcount());
            size -= source.gcount();
        }

        delete[] buffer;
        
        return !source.fail() && !dest.fail();
    }

private:
    // 私有函数，转换过程中需要递归处理子节点
    static void xml_to_json_recursive(Value& json, xml_node<>* node, Document::AllocatorType& allocator) {
        for (xml_node<>* cur_node = node->first_node(); cur_node; cur_node = cur_node->next_sibling()) {

            // 检查是否需要跳过节点
            xml_attribute<>* hide_attr = cur_node->first_attribute("hide");
            if (hide_attr && std::string(hide_attr->value()) == "yes") {
                continue;  // 如果 hide 属性值为 "true"，跳过该节点
            }

            // 检查是否已经有该节点名称的数组
            Value* array = nullptr;
            if (json.HasMember(cur_node->name())) {
                array = &json[cur_node->name()];
            }
            else {
                Value node_array(kArrayType); // 创建新的数组
                json.AddMember(Value(cur_node->name(), allocator).Move(), node_array, allocator);
                array = &json[cur_node->name()];
            }

            // 创建一个 JSON 对象代表当前节点
            Value child_json(kObjectType);

            // 处理节点的属性
            for (xml_attribute<>* attr = cur_node->first_attribute(); attr; attr = attr->next_attribute()) {
                Value attr_name(attr->name(), allocator);
                Value attr_value(attr->value(), allocator);
                child_json.AddMember(attr_name, attr_value, allocator);
            }

            // 递归处理子节点
            xml_to_json_recursive(child_json, cur_node, allocator);

            // 将当前节点对象添加到对应数组中
            array->PushBack(child_json, allocator);
        }
    }
};

#endif //MISC_UTIL_HPP