#ifndef TSHARK_SERVER_PACKET_CONTROLLER_HPP
#define TSHARK_SERVER_PACKET_CONTROLLER_HPP

#include <memory>

#include "controller/base_controller.hpp"


// 数据包相关的接口
class PacketController : public BaseController {
public:
    PacketController(httplib::Server &server, std::shared_ptr<TsharkManager> tsharkManager)
        : BaseController(server, tsharkManager)
    {
    }

    virtual void registerRoute() {

        __server.Post("/api/getPacketList", [this](const httplib::Request& req, httplib::Response& res) {
            getPacketList(req, res);
        });
    }


    // 获取数据包列表
    void getPacketList(const httplib::Request &req, httplib::Response &res) {

        // 获取 JSON 数据中的字段
        try {

            QueryCondition queryCondition;
            if (!parseQueryCondition(req, queryCondition)) {
                sendErrorResponse(res, ERROR_PARAMETER_WRONG);
                return;
            }

            // 调用 tSharkManager 的方法获取数据
            std::vector<std::shared_ptr<Packet>> packetList;
            __tsharkManager->queryPackets(queryCondition, packetList);
            sendDataList(res, packetList);
        }
        catch (const std::exception& e) {
            // 如果发生异常，返回错误响应
            sendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }


};


#endif //TSHARK_SERVER_PACKET_CONTROLLER_HPP
