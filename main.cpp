#include <iostream>
#include "loguru/loguru.hpp"
#include "httplib/httplib.h"

#include "tshark_manager.h"
#include "controller/packet_controller.hpp"
#include "controller/adaptor_controller.hpp"
#include "controller/session_controller.hpp"

std::shared_ptr<TsharkManager> g_ptrTsharkManager;

void hello(const httplib::Request& req, httplib::Response& res) {
    std::string name = req.get_param_value("name");
    std::string hello = "Hello, " + name;
    res.set_content(hello, "text/plain");
}



httplib::Server::HandlerResponse before_request(const httplib::Request& req, httplib::Response& res) {
    LOG_F(INFO, "Request received for %s", req.path.c_str());
    return httplib::Server::HandlerResponse::Unhandled;
}

void after_response(const httplib::Request& req, httplib::Response& res) {
    LOG_F(INFO, "Received response with status %d", res.status);
}

void InitLog(int argc, char* argv[]) {
    // 初始化 Loguru
    loguru::init(argc, argv);

    // 设置日志文件路径
    loguru::add_file("app.log", loguru::Append, loguru::Verbosity_MAX);
}

int main(int argc, char* argv[]) {

    // 设置控制台环境编码为UTF-8格式，防止打印输出的内容乱码
    setlocale(LC_ALL, "zh_CN.UTF-8");

    InitLog(argc, argv);

    g_ptrTsharkManager = std::make_shared<TsharkManager>("F:/cppProject/tsharkwithui");
    // g_ptrTsharkManager->analysisFile("F:/cppProject/tsharkwithui/build/capture.pcap");

    // 创建一个 HTTP 服务器对象
    httplib::Server server;

    // 设置钩子函数
    server.set_pre_routing_handler(before_request);
    server.set_post_routing_handler(after_response);


    // 创建Controller并注册路由
    std::vector<std::shared_ptr<BaseController>> controllerList;
    controllerList.push_back(std::make_shared<PacketController>(server, g_ptrTsharkManager));
    controllerList.push_back(std::make_shared<SessionController>(server, g_ptrTsharkManager));
    controllerList.push_back(std::make_shared<AdaptorController>(server, g_ptrTsharkManager));

    for (auto controller : controllerList) {
        controller->registerRoute();
    }

    // 启动服务器，监听 8080 端口
    server.listen("127.0.0.1", 8080);
    return 0;
}