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
bool TsharkDatabase::queryPackets(QueryCondition& queryConditon, std::vector<std::shared_ptr<Packet>> &packetList, int& total) {
        sqlite3_stmt *stmt = nullptr, *countStmt = nullptr;
        std::string sql = PacketSQL::buildPacketQuerySQL(queryConditon);
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            LOG_F(ERROR, "Failed to prepare statement: ");
            return false;
        }

        sqlite3_bind_text(stmt, 1, queryConditon.ip.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, queryConditon.ip.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, queryConditon.port);
        sqlite3_bind_int(stmt, 4, queryConditon.port);

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

        // 再查询总数total
        sql = PacketSQL::buildPacketQuerySQL_Count(queryConditon);
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &countStmt, nullptr) != SQLITE_OK) {
            std::cout << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
            return false;
        }
        // 执行查询并获取结果
        if (sqlite3_step(countStmt) == SQLITE_ROW) {
            total = sqlite3_column_int(countStmt, 0);
        }

        sqlite3_finalize(countStmt);

        return true;
    }

// 创建会话表
void TsharkDatabase::createSessionTable() {
    // 检查表是否存在，若不存在则创建
    std::string createTableSQL = R"(
        CREATE TABLE IF NOT EXISTS t_sessions (
            session_id INTEGER PRIMARY KEY,
            ip1 TEXT,
            ip1_port INTEGER,
            ip1_location TEXT,
            ip2 TEXT,
            ip2_port INTEGER,
            ip2_location TEXT,
            trans_proto TEXT,
            app_proto TEXT,
            start_time REAL,
            end_time REAL,
            ip1_send_packets_count INTEGER,
            ip1_send_bytes_count INTEGER,
            ip2_send_packets_count INTEGER,
            ip2_send_bytes_count INTEGER,
            packet_count INTEGER,
            total_bytes INTEGER
        );
    )";

    if (sqlite3_exec(db, createTableSQL.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to create table t_sessions");
    }

    // 清空表数据
    std::string clearTableSQL = "DELETE FROM t_sessions;";
    if (sqlite3_exec(db, clearTableSQL.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to clear table t_sessions");
    }
}

// 存储会话信息到表中
void TsharkDatabase::storeAndUpdateSessions(std::unordered_set<std::shared_ptr<Session>>& sessions) {

    // 开启事务
    sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    // SQL UPSERT 语句
    std::string upsertSQL = R"(
        INSERT INTO t_sessions (
            session_id, ip1, ip1_location, ip1_port, ip2, ip2_location, ip2_port,
            trans_proto, app_proto, start_time, end_time,
            ip1_send_packets_count, ip1_send_bytes_count, ip2_send_packets_count, ip2_send_bytes_count,
            packet_count, total_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(session_id) DO UPDATE SET
            trans_proto = excluded.trans_proto,
            app_proto = excluded.app_proto,
            start_time = excluded.start_time,
            end_time = excluded.end_time,
            ip1_send_packets_count = excluded.ip1_send_packets_count,
            ip1_send_bytes_count = excluded.ip1_send_bytes_count,
            ip2_send_packets_count = excluded.ip2_send_packets_count,
            ip2_send_bytes_count = excluded.ip2_send_bytes_count,
            packet_count = excluded.packet_count,
            total_bytes = excluded.total_bytes
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, upsertSQL.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare UPSERT statement");
    }

    // 遍历列表并插入或更新数据
    for (const auto& session : sessions) {
        sqlite3_bind_int(stmt, 1, session->session_id);
        sqlite3_bind_text(stmt, 2, session->ip1.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, session->ip1_location.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 4, session->ip1_port);
        sqlite3_bind_text(stmt, 5, session->ip2.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, session->ip2_location.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 7, session->ip2_port);
        sqlite3_bind_text(stmt, 8, session->trans_proto.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 9, session->app_proto.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_double(stmt, 10, session->start_time);
        sqlite3_bind_double(stmt, 11, session->end_time);
        sqlite3_bind_int(stmt, 12, session->ip1_send_packets_count);
        sqlite3_bind_int(stmt, 13, session->ip1_send_bytes_count);
        sqlite3_bind_int(stmt, 14, session->ip2_send_packets_count);
        sqlite3_bind_int(stmt, 15, session->ip2_send_bytes_count);
        sqlite3_bind_int(stmt, 16, session->packet_count);
        sqlite3_bind_int(stmt, 17, session->total_bytes);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            throw std::runtime_error("Failed to execute UPSERT statement");
        }

        sqlite3_reset(stmt); // 重置语句以便下一次绑定
    }

    // 结束事务
    sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);

    // 释放语句
    sqlite3_finalize(stmt);
}

// 从数据库查询会话分页数据
bool TsharkDatabase::querySessions(QueryCondition& condition, std::vector<std::shared_ptr<Session>>& sessionList, int& total) {
    sqlite3_stmt* stmt = nullptr;
    std::string sql = SessionSQL::buildSessionQuerySQL(condition);

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cout << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::shared_ptr<Session> session = std::make_shared<Session>();
        session->session_id = sqlite3_column_int(stmt, 0);
        session->ip1 = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        session->ip1_port = sqlite3_column_int(stmt, 2);
        session->ip1_location = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        session->ip2 = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        session->ip2_port = sqlite3_column_int(stmt, 5);
        session->ip2_location = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        session->trans_proto = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        session->app_proto = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        session->start_time = sqlite3_column_double(stmt, 9);
        session->end_time = sqlite3_column_double(stmt, 10);
        session->ip1_send_packets_count = sqlite3_column_int(stmt, 11);
        session->ip1_send_bytes_count = sqlite3_column_int(stmt, 12);
        session->ip2_send_packets_count = sqlite3_column_int(stmt, 13);
        session->ip2_send_bytes_count = sqlite3_column_int(stmt, 14);
        session->packet_count = sqlite3_column_int(stmt, 15);
        session->total_bytes = sqlite3_column_int(stmt, 16);

        sessionList.push_back(session);
    }

    sqlite3_finalize(stmt);
    return true;
}
