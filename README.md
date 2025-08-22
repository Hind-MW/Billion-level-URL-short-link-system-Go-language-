# 十亿级URL短链系统设计方案

## 1. 系统需求分析

### 1.1 功能性需求
- **生成短链**：将长URL转换为短链接
- **重定向服务**：通过短链访问原始URL
- **自定义短链**：支持用户自定义短链码
- **过期机制**：支持设置链接过期时间
- **统计分析**：提供访问统计和分析数据

### 1.2 非功能性需求
- **高可用性**：99.9%以上的可用性
- **高性能**：重定向延迟 < 100ms
- **高并发**：支持2万QPS读取，200QPS写入
- **可扩展性**：支持十亿级数据存储
- **安全性**：防止恶意攻击和滥用

## 2. 容量预估

### 2.1 流量预估
- **写入QPS**：每月5亿次写入 ≈ 200次/秒
- **读取QPS**：按100:1读写比 ≈ 2万次/秒
- **存储需求**：5年数据量 ≈ 15TB
- **缓存需求**：热点数据20% ≈ 170GB

### 2.2 性能指标
| 指标 | 数值 |
|------|------|
| 日均写入 | 1728万次 |
| 日均读取 | 17.28亿次 |
| 总存储量 | 300亿条记录 |
| 单机QPS | 2万 |

## 3. 核心架构设计

### 3.1 整体架构图
```
[CDN] → [负载均衡器] → [应用服务器集群] → [缓存集群(Redis)] → [数据库集群(分片)]
                          ↓
                     [统计分析服务]
                          ↓
                     [密钥生成服务(KGS)]
```

### 3.2 核心组件说明

#### 3.2.1 应用服务器
- 处理HTTP请求
- 短链生成和重定向逻辑
- API接口实现
- 限流和防滥用

#### 3.2.2 密钥生成服务（KGS）
- 预生成唯一短链码
- 基于自增ID + Base62编码
- 高可用集群部署
- 密钥池管理

#### 3.2.3 缓存层
- Redis集群
- LRU淘汰策略
- 热点数据缓存
- 读写穿透保护

#### 3.2.4 数据存储层
- 水平分片
- 主从复制
- 读写分离
- 一致性哈希

## 4. 数据库设计

### 4.1 URL映射表
```sql
CREATE TABLE url_mapping (
    short_code VARCHAR(8) PRIMARY KEY,
    original_url TEXT NOT NULL,
    user_id VARCHAR(32),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    status TINYINT DEFAULT 1,
    custom_alias BOOLEAN DEFAULT FALSE,
    INDEX idx_user_id (user_id),
    INDEX idx_created_at (created_at),
    INDEX idx_expires_at (expires_at)
);
```

### 4.2 统计表
```sql
CREATE TABLE url_analytics (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    short_code VARCHAR(8) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    referer TEXT,
    country VARCHAR(2),
    city VARCHAR(50),
    clicked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_short_code (short_code),
    INDEX idx_clicked_at (clicked_at)
);
```

### 4.3 用户表
```sql
CREATE TABLE users (
    user_id VARCHAR(32) PRIMARY KEY,
    email VARCHAR(100) UNIQUE,
    password_hash VARCHAR(128),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TINYINT DEFAULT 1
);
```

## 5. 短链码生成算法

### 5.1 Base62编码
使用字符集：`0-9, a-z, A-Z` (62个字符)

### 5.2 算法流程
1. 从KGS获取全局唯一ID
2. 将十进制ID转换为Base62
3. 检查是否冲突（极低概率）
4. 返回短链码

### 5.3 容量计算
- 6位Base62：62^6 ≈ 568亿个组合
- 8位Base62：62^8 ≈ 218万亿个组合

## 6. 缓存策略

### 6.1 多级缓存
1. **本地缓存**：应用服务器内存缓存
2. **分布式缓存**：Redis集群
3. **CDN缓存**：地理分布式缓存

### 6.2 缓存策略
- **Cache-Aside模式**：应用控制缓存逻辑
- **TTL设置**：根据访问频率动态调整
- **预热机制**：系统启动时预加载热点数据

## 7. 数据分片策略

### 7.1 分片方案
基于短链码的一致性哈希分片：
```
shard_id = hash(short_code) % shard_count
```

### 7.2 优势
- 数据分布均匀
- 易于水平扩展
- 避免热点问题

## 8. 高可用设计

### 8.1 服务层面
- 应用服务器集群部署
- 负载均衡器高可用
- 健康检查和自动故障转移

### 8.2 数据层面
- 数据库主从复制
- 跨机房部署
- 定期备份和恢复演练

## 9. 监控和告警

### 9.1 关键指标
- QPS和响应时间
- 错误率和可用性
- 缓存命中率
- 数据库连接数

### 9.2 告警机制
- 实时监控大盘
- 异常自动告警
- 性能趋势分析

## 10. 安全防护

### 10.1 防滥用机制
- API限流（基于IP和用户）
- 验证码验证
- 黑名单机制

### 10.2 数据安全
- HTTPS加密传输
- SQL注入防护
- XSS攻击防护

## 11. 运维和扩展

### 11.1 自动化运维
- Docker容器化部署
- Kubernetes集群管理
- CI/CD自动化流程

### 11.2 弹性扩展
- 自动水平扩展
- 数据迁移工具
- 蓝绿部署策略

## 12. 成本优化

### 12.1 存储优化
- 冷热数据分离
- 数据压缩和归档
- 过期数据清理

### 12.2 计算优化
- 资源利用率监控
- 自动伸缩策略
- 成本分析和优化建议
