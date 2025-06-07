#pragma once
#include "sqlite3/sqlite3.h"
#include "tshark_datatype.h"
#include "utils/misc_util.hpp"
#include "loguru/loguru.hpp"
#include "sql/packet_sql.hpp"


// 数据库类
class TsharkDatabase {
public:
    // 构造函数，初始化数据库并创建表
    TsharkDatabase(const std::string &dbName) {
        // 打开数据库连接
        if (sqlite3_open(dbName.c_str(), &db) != SQLITE_OK) {
            throw std::runtime_error("Failed to open database");
        }

        createPacketTable();
    }

    // 析构函数，关闭数据库连接
    ~TsharkDatabase() {
        if (db) {
            sqlite3_close(db);
        }
    }

    bool createPacketTable();
    bool storePackets(std::vector<std::shared_ptr<Packet>> &packets);
    bool queryPackets(QueryCondition& queryConditon, std::vector<std::shared_ptr<Packet>> &packetList);
private:
    sqlite3* db = nullptr; // SQLite 数据库连接
};
