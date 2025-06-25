#pragma once
#ifndef TSHARK_SERVER_SESSION_CONTROLLER_HPP
#define TSHARK_SERVER_SESSION_CONTROLLER_HPP

#include "controller/base_controller.hpp"

// 会话相关的接口
class SessionController : public BaseController {
public:
    SessionController(httplib::Server &server, std::shared_ptr<TsharkManager> tsharkManager)
        :BaseController(server, tsharkManager)
    {
    }

    virtual void registerRoute() {

        __server.Post("/api/getSessionList", [this](const httplib::Request& req, httplib::Response& res) {
            getSessionList(req, res);
        });

        __server.Post("/api/getSessionDataStream", [this](const httplib::Request& req, httplib::Response& res) {
            getSessionDataStream(req, res);
        });
    }

    // 获取会话列表
    void getSessionList(const httplib::Request &req, httplib::Response &res) {

        try {
            QueryCondition queryCondition;
            if (!parseQueryCondition(req, queryCondition)) {
                sendErrorResponse(res, ERROR_PARAMETER_WRONG);
                return;
            }

            // 调用 tSharkManager 的方法获取数据
            int total = 0;
            std::vector<std::shared_ptr<Session>> sessionList;
            __tsharkManager->querySessions(queryCondition, sessionList, total);
            sendDataList(res, sessionList, total);
        } catch (const std::exception &e) {
            // 如果发生异常，返回错误响应
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    // 获取会话数据流
    void getSessionDataStream(const httplib::Request& req, httplib::Response& res) {

        try {
            uint32_t sessionId = 0;

            // 检查是否有 body 数据
            if (req.body.empty()) {
                return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            // 使用 RapidJSON 解析 JSON
            rapidjson::Document doc;
            if (doc.Parse(req.body.c_str()).HasParseError()) {
                return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            // 验证是否是 JSON 对象
            if (!doc.IsObject()) {
                return sendErrorResponse(res, ERROR_PARAMETER_WRONG);
            }

            // 提取参数字段
            if (doc.HasMember("session_id") && doc["session_id"].IsNumber()) {
                sessionId = doc["session_id"].GetInt();
            }

            // 调用 tSharkManager 的方法获取数据
            std::vector<DataStreamItem> dataStreamList;
            DataStreamCountInfo countInfo = __tsharkManager->getSessionDataStream(sessionId, dataStreamList);

            // 准备返回JSON数据
            rapidjson::Document resDoc;
            rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
            resDoc.SetObject();

            // 添加 "code" 和 "msg"
            resDoc.AddMember("code", ERROR_STATUS_SUCCESS, allocator);
            resDoc.AddMember("msg", rapidjson::Value(TsharkError::getErrorMsg(ERROR_STATUS_SUCCESS).c_str(), allocator), allocator);

            // 添加 "count"
            rapidjson::Value countObj(rapidjson::kObjectType);
            countInfo.toJsonObj(countObj, allocator);
            resDoc.AddMember("count", countObj, allocator);

            // 构建 "data" 数组
            rapidjson::Value dataArray(rapidjson::kArrayType);
            for (const auto& data : dataStreamList) {
                rapidjson::Value obj(rapidjson::kObjectType);
                data.toJsonObj(obj, allocator);
                assert(obj.IsObject());
                dataArray.PushBack(obj, allocator);
            }

            resDoc.AddMember("data", dataArray, allocator);

            // 序列化为 JSON 字符串
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            resDoc.Accept(writer);

            // 设置响应内容
            res.set_content(buffer.GetString(), "application/json");
        }
        catch (const std::exception& e) {
            // 如果发生异常，返回错误响应
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }
};

#endif