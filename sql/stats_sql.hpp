#ifndef STATS_SQL_H
#define STATS_SQL_H

#include <string>
#include <sstream>
#include <iostream>
#include "tshark_datatype.h"
#include "loguru/loguru.hpp"
#include "pagehelper.h"

class StatsSQL {
public:
    static std::string buildIPStatsQuerySQL(QueryCondition &condition) {
        std::vector<std::string> conditionList1;
        std::vector<std::string> conditionList2;

        if (!condition.ip.empty()) {
            char buf[100] = {0};
            snprintf(buf, sizeof(buf), "ip1='%s'", condition.ip.c_str());
            conditionList1.push_back(buf);
            snprintf(buf, sizeof(buf), "ip2='%s'", condition.ip.c_str());
            conditionList2.push_back(buf);
        }
        if (condition.port != 0) {
            char buf[100] = {0};
            snprintf(buf, sizeof(buf), "ip1_port=%d", condition.port);
            conditionList1.push_back(buf);
            snprintf(buf, sizeof(buf), "ip2_port=%d", condition.port);
            conditionList2.push_back(buf);
        }
        if (!condition.proto.empty()) {
            char buf[100] = {0};
            snprintf(buf, sizeof(buf), "(trans_proto like '%%%s%%' or app_proto like '%%%s%%')", 
                    condition.proto.c_str(), condition.proto.c_str());
            conditionList1.push_back(buf);
            conditionList2.push_back(buf);
        }

        std::stringstream ss1, ss2;
        ss1 << "SELECT ip1 AS ip, ip1_location AS location, start_time, end_time, "
            << "ip1_port AS port, trans_proto, app_proto, "
            << "ip1_send_packets_count AS sent_packets, ip1_send_bytes_count AS sent_bytes, "
            << "ip2_send_packets_count AS recv_packets, ip2_send_bytes_count AS recv_bytes, "
            << "CASE WHEN trans_proto LIKE '%TCP%' THEN 1 ELSE 0 END AS tcp_sessions, "
            << "CASE WHEN trans_proto LIKE '%UDP%' THEN 1 ELSE 0 END AS udp_sessions "
            << "FROM t_sessions";
        
        if (!conditionList1.empty()) {
            ss1 << " WHERE ";
            for (size_t i = 0; i < conditionList1.size(); ++i) {
                if (i > 0) ss1 << " AND ";
                ss1 << conditionList1[i];
            }
        }

        ss2 << "SELECT ip2 AS ip, ip2_location AS location, start_time, end_time, "
            << "ip2_port AS port, trans_proto, app_proto, "
            << "ip2_send_packets_count AS sent_packets, ip2_send_bytes_count AS sent_bytes, "
            << "ip1_send_packets_count AS recv_packets, ip1_send_bytes_count AS recv_bytes, "
            << "CASE WHEN trans_proto LIKE '%TCP%' THEN 1 ELSE 0 END AS tcp_sessions, "
            << "CASE WHEN trans_proto LIKE '%UDP%' THEN 1 ELSE 0 END AS udp_sessions "
            << "FROM t_sessions";
        
        if (!conditionList2.empty()) {
            ss2 << " WHERE ";
            for (size_t i = 0; i < conditionList2.size(); ++i) {
                if (i > 0) ss2 << " AND ";
                ss2 << conditionList2[i];
            }
        }

        std::stringstream finalSS;
        finalSS << "SELECT ip, location, MIN(start_time) AS earliest_time, MAX(end_time) AS latest_time, "
                << "GROUP_CONCAT(DISTINCT port) AS ports, "
                << "GROUP_CONCAT(DISTINCT trans_proto) AS trans_protos, "
                << "GROUP_CONCAT(DISTINCT app_proto) AS app_protos, "
                << "SUM(sent_packets) AS total_sent_packets, SUM(sent_bytes) AS total_sent_bytes, "
                << "SUM(recv_packets) AS total_recv_packets, SUM(recv_bytes) AS total_recv_bytes, "
                << "SUM(tcp_sessions) AS tcp_session_count, SUM(udp_sessions) AS udp_session_count "
                << "FROM (" << ss1.str() << " UNION ALL " << ss2.str() << ") t GROUP BY ip"
                << PageHelper::getPageSql();

        std::string sql = finalSS.str();
        LOG_F(INFO, "[BUILD SQL]: %s", sql.c_str());
        return sql;
    }

    static std::string buildIPStatsQuerySQL_Count(QueryCondition &condition) {
        std::string sql = buildIPStatsQuerySQL(condition);
        auto pos = sql.find("LIMIT");
        if (pos != std::string::npos) {
            sql = sql.substr(0, pos);
        }
        std::string countSql = "SELECT COUNT(0) FROM (" + sql + ") t_temp;";
        LOG_F(INFO, "[BUILD SQL]: %s", countSql.c_str());
        return countSql;
    }

    static std::string buildProtoStatsQuerySQL(QueryCondition &condition) {
        std::stringstream ss1, ss2, finalSS;

        // 子查询1：统计trans_proto数据
        ss1 << "SELECT session_id, trans_proto AS protocol, packet_count, total_bytes "
            << "FROM t_sessions "
            << "WHERE trans_proto IS NOT NULL AND trans_proto != ''";

        // 子查询2：统计app_proto数据
        ss2 << "SELECT session_id, app_proto AS protocol, packet_count, total_bytes "
            << "FROM t_sessions "
            << "WHERE app_proto IS NOT NULL AND app_proto != ''";

        // 组合查询与聚合统计
        finalSS << "SELECT protocol, "
                << "SUM(packet_count) AS totalPackets, "
                << "SUM(total_bytes) AS total_bytes, "
                << "COUNT(DISTINCT session_id) AS sessionCount "
                << "FROM (" << ss1.str() << " UNION ALL " << ss2.str() << ") AS combined "
                << "GROUP BY protocol" << PageHelper::getPageSql();

        std::string sql = finalSS.str();
        LOG_F(INFO, "[BUILD SQL]: %s", sql.c_str());
        return sql;
    }

    static std::string buildProtoStatsQuerySQL_Count(QueryCondition &condition) {
        std::string sql = buildProtoStatsQuerySQL(condition);
        auto pos = sql.find("LIMIT");
        if (pos != std::string::npos) {
            sql = sql.substr(0, pos);
        }
        std::string countSql = "SELECT COUNT(0) FROM (" + sql + ") t_temp;";
        LOG_F(INFO, "[BUILD SQL]: %s", countSql.c_str());
        return countSql;
    }
};

#endif // STATS_SQL_H