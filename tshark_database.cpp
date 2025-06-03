#include "tshark_database.h"

bool TsharkDatabase::createPacketTable() {
    // 检查表是否存在，若不存在则创建
    std::string createTableSQL = R"(
        CREATE TABLE IF NOT EXISTS t_packets (
            frame_number INTEGER PRIMARY KEY,
            time REAL,
            cap_len INTEGER,
            len INTEGER,
            src_mac TEXT,
            dst_mac TEXT,
            src_ip TEXT,
            src_location TEXT,
            src_port INTEGER,
            dst_ip TEXT,
            dst_location TEXT,
            dst_port INTEGER,
            protocol TEXT,
            info TEXT,
            file_offset INTEGER
        );
    )";

    if (sqlite3_exec(db, createTableSQL.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
        LOG_F(ERROR, "Failed to create table t_packets");
        return false;
    }

    return true;
}

// 存储数据包信息到表中
bool TsharkDatabase::storePackets(std::vector<std::shared_ptr<Packet>>& packets) {

    // 开启事务
    sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    // SQL 插入语句
    std::string insertSQL = R"(
        INSERT INTO t_packets (
            frame_number, time, cap_len, len, src_mac, dst_mac, src_ip, src_location, src_port,
            dst_ip, dst_location, dst_port, protocol, info, file_offset
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, insertSQL.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare insert statement");
    }

    // 遍历列表并插入数据
    bool hasError = false;
    for (const auto& packet : packets) {
        sqlite3_bind_int(stmt, 1, packet->frame_number);
        sqlite3_bind_double(stmt, 2, packet->time);
        sqlite3_bind_int(stmt, 3, packet->cap_len);
        sqlite3_bind_int(stmt, 4, packet->len);
        sqlite3_bind_text(stmt, 5, packet->src_mac.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, packet->dst_mac.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 7, packet->src_ip.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 8, packet->src_location.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 9, packet->src_port);
        sqlite3_bind_text(stmt, 10, packet->dst_ip.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 11, packet->dst_location.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 12, packet->dst_port);
        sqlite3_bind_text(stmt, 13, packet->protocol.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 14, packet->info.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 15, packet->file_offset);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            LOG_F(ERROR, "Failed to execute insert statement");
            hasError = true;
            break;
        }

        sqlite3_reset(stmt); // 重置语句以便下一次绑定
    }

    if (!hasError) {

        // 结束事务
        if (sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr) != SQLITE_OK) {
            hasError = true;
        }

        // 释放语句
        sqlite3_finalize(stmt);
    }

    return !hasError;
}

// 从数据库查询数据包分页数据
bool TsharkDatabase::queryPackets(std::vector<std::shared_ptr<Packet>> &packetList) {
    sqlite3_stmt *stmt = nullptr, *countStmt = nullptr;
    std::string sql = "select * from t_packets";
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        LOG_F(ERROR, "Failed to prepare statement: ");
        return false;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        packet->frame_number = sqlite3_column_int(stmt, 0);
        packet->time = sqlite3_column_double(stmt, 1);
        packet->cap_len = sqlite3_column_int(stmt, 2);
        packet->len = sqlite3_column_int(stmt, 3);
        packet->src_mac = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        packet->dst_mac = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        packet->src_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        packet->src_location = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        packet->src_port = sqlite3_column_int(stmt, 8);
        packet->dst_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
        packet->dst_location = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        packet->dst_port = sqlite3_column_int(stmt, 11);
        packet->protocol = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        packet->info = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 13));
        packet->file_offset = sqlite3_column_int(stmt, 14);
        packetList.push_back(packet);
    }

    sqlite3_finalize(stmt);

    return true;
}
