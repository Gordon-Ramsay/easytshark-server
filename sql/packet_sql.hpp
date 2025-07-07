#pragma once
#ifndef PACKET_SQL_H
#define PACKET_SQL_H

#include <string>
#include <sstream>
#include <iostream>
#include "tshark_datatype.h"
#include "loguru/loguru.hpp"
#include "pagehelper.h"

class PacketSQL {
public:
    static std::string buildPacketQuerySQL(QueryCondition &condition) {

        std::string sql;
        std::stringstream ss;
        ss << "SELECT * FROM t_packets";

        std::vector<std::string> conditionList;

        if (!condition.ip.empty()) {
            char buf[100] = {0};
            snprintf(buf, sizeof(buf), "src_ip='%s' or dst_ip='%s'", condition.ip.c_str(), condition.ip.c_str());
            conditionList.push_back(buf);
        }
        if (condition.port != 0) {
            char buf[100] = {0};
            snprintf(buf, sizeof(buf), "src_port=%d or dst_port=%d", condition.port, condition.port);
            conditionList.push_back(buf);
        }
        if (!condition.proto.empty()) {
            char buf[100] = { 0 };
            snprintf(buf, sizeof(buf), "protocol='%s'", condition.proto.c_str());
            conditionList.push_back(buf);
        }
        if (condition.session_id != 0) {
            char buf[100] = { 0 };
            snprintf(buf, sizeof(buf), "belong_session_id=%d", condition.session_id);
            conditionList.push_back(buf);
        }

        // 拼接 WHERE 条件
        if (!conditionList.empty()) {
            ss << " WHERE ";
            for (size_t i = 0; i < conditionList.size(); ++i) {
                if (i > 0) {
                    ss << " AND ";
                }
                ss << conditionList[i];
            }
        }

        ss << PageHelper::getPageSql();

        sql = ss.str();
        LOG_F(INFO, "[BUILD SQL]: %s", sql.c_str());
        return sql;
    }

    static std::string buildPacketQuerySQL_Count(QueryCondition &condition) {
        std::string sql = buildPacketQuerySQL(condition);
        auto pos = sql.find("LIMIT");
        if (pos != std::string::npos) {
            sql = sql.substr(0, pos);
        }
        std::string countSql = "SELECT COUNT(0) FROM (" + sql + ") t_temp;";
        LOG_F(INFO, "[BUILD SQL]: %s", countSql.c_str());
        return countSql;
    }
};

#endif // PACKET_SQL_H