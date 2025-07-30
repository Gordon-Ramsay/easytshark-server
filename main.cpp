#include <iostream>
#include "loguru/loguru.hpp"
#include "httplib/httplib.h"

#include "tshark_manager.h"
#include "pagehelper.h"
#include "controller/packet_controller.hpp"
#include "controller/adaptor_controller.hpp"
#include "controller/session_controller.hpp"
#include "controller/stats_controller.hpp"
#include "controller/region_controller.hpp"
#include "utils/process_util.h"

std::shared_ptr<TsharkManager> g_ptrTsharkManager;

void hello(const httplib::Request& req, httplib::Response& res) {
    std::string name = req.get_param_value("name");
    std::string hello = "Hello, " + name;
    res.set_content(hello, "text/plain");
}



httplib::Server::HandlerResponse before_request(const httplib::Request& req, httplib::Response& res) {
    LOG_F(INFO, "Request received for %s", req.path.c_str());

    // 提取分页参数
    PageAndOrder* pageAndOrder = PageHelper::getPageAndOrder();
    pageAndOrder->pageNum = BaseController::getIntParam(req, "pageNum", 1);
    pageAndOrder->pageSize = BaseController::getIntParam(req, "pageSize", 100);
    pageAndOrder->orderBy = BaseController::getStringParam(req, "orderBy", "");
    pageAndOrder->descOrAsc = BaseController::getStringParam(req, "descOrAsc", "asc");
    return httplib::Server::HandlerResponse::Unhandled;
}

void after_response(const httplib::Request& req, httplib::Response& res) {
    if (req.method != "OPTIONS") {
        res.set_header("Access-Control-Allow-Origin", "http://localhost:3000");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE, PUT");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
        res.set_header("Access-Control-Allow-Credentials", "true");
    }
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

    // 提取UI进程参数
    std::string paramName = "--uipid=";
    if (argc < 2 || strstr(argv[1], paramName.c_str()) == nullptr) {
        LOG_F(ERROR, "usage: tshark_server --uipid=xxx");
        return -1;
    }

    std::string pidParam = argv[1];
    auto pos1 = pidParam.find(paramName) + paramName.size();
    auto pos2 = pidParam.find(" ", pos1);
    PID_T pid = std::stoi(pidParam.substr(pos1, pos2));
    if (!ProcessUtil::isProcessRunning(pid)) {
        LOG_F(ERROR, "UI进程不存在，tshark_server将退出");
        return -1;
    }

    // 启动UI监控线程
    std::thread uiMonitorThread([&]() {
            while (true) {
                if (!ProcessUtil::isProcessRunning(pid)) {
                    LOG_F(INFO, "检测到UI进程已退出");
                    return;
                }
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        });

    std::string currentExePath = ProcessUtil::getExecutableDir();
    g_ptrTsharkManager = std::make_shared<TsharkManager>(currentExePath);

    // 创建一个 HTTP 服务器对象
    httplib::Server server;
    server.Options(".*", [](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "http://localhost:3000");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE, PUT");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
        res.set_header("Access-Control-Allow-Credentials", "true");
        res.status = 200;
        });

    // 设置钩子函数
    server.set_pre_routing_handler(before_request);
    server.set_post_routing_handler(after_response);


    // 创建Controller并注册路由
    std::vector<std::shared_ptr<BaseController>> controllerList;
    controllerList.push_back(std::make_shared<PacketController>(server, g_ptrTsharkManager));
    controllerList.push_back(std::make_shared<SessionController>(server, g_ptrTsharkManager));
    controllerList.push_back(std::make_shared<AdaptorController>(server, g_ptrTsharkManager));
    controllerList.push_back(std::make_shared<StatsController>(server, g_ptrTsharkManager));
    controllerList.push_back(std::make_shared<RegionController>(server, g_ptrTsharkManager));

    for (auto controller : controllerList) {
        controller->registerRoute();
    }

    // 在另一个线程中启动HTTP服务
    std::thread serverThread([&]() {
        LOG_F(INFO, "tshark_server is running on http://127.0.0.1:9122");
        server.listen("127.0.0.1", 9122);
        });


    // 等待UI进程退出
    uiMonitorThread.join();

    // UI进程退出后，HTTP服务即关闭
    server.stop();
    serverThread.join();

    // 如果还在抓包或者监控网卡流量，将其关闭
    g_ptrTsharkManager->reset();

    return 0;
}