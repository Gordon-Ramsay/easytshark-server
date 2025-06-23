#pragma once
#ifndef TSHARK_SERVER_STATS_CONTROLLER_HPP
#define TSHARK_SERVER_STATS_CONTROLLER_HPP

#include "controller/base_controller.hpp"

// 通信统计相关的接口
class StatsController : public BaseController {
public:
    StatsController(httplib::Server &server, std::shared_ptr<TsharkManager> tsharkManager)
        :BaseController(server, tsharkManager)
    {
    }

    virtual void registerRoute() {
        __server.Post("/api/getIPStatsList", [this](const httplib::Request& req, httplib::Response& res) {
            getIPStatsList(req, res);
        });
    }

    // 获取IP统计列表
    void getIPStatsList(const httplib::Request &req, httplib::Response &res) {

        try {
            // 提取 URL 查询参数
            auto queryParams = req.params;
            int pageNum = getIntParam(req, "pageNum", 1);
            int pageSize = getIntParam(req, "pageSize",  100);

            QueryCondition queryCondition;
            if (!parseQueryCondition(req, queryCondition)) {
                sendErrorResponse(res, ERROR_PARAMETER_WRONG);
                return;
            }

            // 调用 tSharkManager 的方法获取数据
            std::vector<std::shared_ptr<IPStatsInfo>> ipStatsList;
            int total = 0;
            __tsharkManager->getIPStatsList(queryCondition, ipStatsList, total);
            sendDataList(res, ipStatsList, total);
        } catch (const std::exception &e) {
            // 如果发生异常，返回错误响应
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }
};

#endif //TSHARK_SERVER_SESSION_CONTROLLER_HPP
