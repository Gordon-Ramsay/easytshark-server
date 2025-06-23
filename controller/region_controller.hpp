#pragma once
#ifndef TSHARK_SERVER_REGION_CONTROLLER_HPP
#define TSHARK_SERVER_REGION_CONTROLLER_HPP

#include "controller/base_controller.hpp"

// 区域统计相关的接口
class RegionController : public BaseController {
public:
    RegionController(httplib::Server &server, std::shared_ptr<TsharkManager> tsharkManager)
        :BaseController(server, tsharkManager)
    {
    }

    virtual void registerRoute() {
        __server.Post("/api/getRegionStatsList", [this](const httplib::Request& req, httplib::Response& res) {
            getRegionStatsList(req, res);
        });
    }

    // 获取区域统计列表
    void getRegionStatsList(const httplib::Request &req, httplib::Response &res) {
        try {
            // 提取 URL 查询参数
            QueryCondition queryCondition;
            if (!parseQueryCondition(req, queryCondition)) {
                sendErrorResponse(res, ERROR_PARAMETER_WRONG);
                return;
            }

            // 调用tSharkManager的方法获取数据
            std::vector<std::shared_ptr<RegionStatsInfo>> regionStatsList;
            int total = 0;
            __tsharkManager->getRegionStatsList(queryCondition, regionStatsList, total);
            sendDataList(res, regionStatsList, total);
        }
        catch (const std::exception &e) {
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }
};

#endif // TSHARK_SERVER_REGION_CONTROLLER_HPP