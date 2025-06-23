#pragma once
#ifndef REGION_SQL_H
#define REGION_SQL_H
#include <string>
#include <sstream>
#include <iostream>
#include "tshark_datatype.h"
#include "loguru/loguru.hpp"
#include "pagehelper.h"

class RegionSQL {
public:
    static std::string buildRegionStatsQuerySQL(QueryCondition &condition) {
        std::stringstream ss1, ss2, finalSS;

        // 子查询1：统计ip1_location数据
        ss1 << "SELECT session_id, ip1_location AS region, packet_count, total_bytes "
            << "FROM t_sessions "
            << "WHERE ip1_location IS NOT NULL AND ip1_location != ''";

        // 子查询2：统计ip2_location数据
        ss2 << "SELECT session_id, ip2_location AS region, packet_count, total_bytes "
            << "FROM t_sessions "
            << "WHERE ip2_location IS NOT NULL AND ip2_location != ''";

        // 组合查询与聚合统计
        finalSS << "SELECT region, "
                << "SUM(packet_count) AS total_packets, "
                << "SUM(total_bytes) AS total_bytes, "
                << "COUNT(DISTINCT session_id) AS session_count "
                << "FROM (" << ss1.str() << " UNION ALL " << ss2.str() << ") AS combined "
                << "GROUP BY region" << PageHelper::getPageSql();

        std::string sql = finalSS.str();
        LOG_F(INFO, "[BUILD SQL]: %s", sql.c_str());
        return sql;
    }

    static std::string buildRegionStatsQuerySQL_Count(QueryCondition &condition) {
        std::string sql = buildRegionStatsQuerySQL(condition);
        auto pos = sql.find("LIMIT");
        if (pos != std::string::npos) {
            sql = sql.substr(0, pos);
        }
        std::string countSql = "SELECT COUNT(0) FROM (" + sql + ") t_temp;";
        LOG_F(INFO, "[BUILD SQL]: %s", countSql.c_str());
        return countSql;
    }
};


#endif // REGION_SQL_H