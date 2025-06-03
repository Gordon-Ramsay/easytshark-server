#pragma once
#include <random>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <rapidxml/rapidxml.hpp>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

using namespace rapidxml;
using namespace rapidjson;

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

    static std::string getDefaultDataDir() {
        return "./";
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