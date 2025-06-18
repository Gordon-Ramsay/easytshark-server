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
};

#endif