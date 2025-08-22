package main

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/time/rate"
)

// 配置结构
type Config struct {
	Database DatabaseConfig `json:"database"`
	Redis    RedisConfig    `json:"redis"`
	Server   ServerConfig   `json:"server"`
	KGS      KGSConfig      `json:"kgs"`
}

type DatabaseConfig struct {
	DSN             string `json:"dsn"`
	MaxOpenConns    int    `json:"max_open_conns"`
	MaxIdleConns    int    `json:"max_idle_conns"`
	ConnMaxLifetime string `json:"conn_max_lifetime"`
}

type RedisConfig struct {
	Addr         string `json:"addr"`
	Password     string `json:"password"`
	DB           int    `json:"db"`
	PoolSize     int    `json:"pool_size"`
	MinIdleConns int    `json:"min_idle_conns"`
}

type ServerConfig struct {
	Port           string `json:"port"`
	Domain         string `json:"domain"`
	JWTSecret      string `json:"jwt_secret"`
	RateLimitRPS   int    `json:"rate_limit_rps"`
	RateLimitBurst int    `json:"rate_limit_burst"`
}

type KGSConfig struct {
	CacheSize    int  `json:"cache_size"`
	PreGenerate  bool `json:"pre_generate"`
	BatchSize    int  `json:"batch_size"`
	WorkerCount  int  `json:"worker_count"`
}

// 数据模型
type URLMapping struct {
	ShortCode   string    `json:"short_code" db:"short_code"`
	OriginalURL string    `json:"original_url" db:"original_url"`
	UserID      string    `json:"user_id" db:"user_id"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at" db:"expires_at"`
	Status      int       `json:"status" db:"status"`
	CustomAlias bool      `json:"custom_alias" db:"custom_alias"`
}

type Analytics struct {
	ID        int64     `json:"id" db:"id"`
	ShortCode string    `json:"short_code" db:"short_code"`
	IPAddress string    `json:"ip_address" db:"ip_address"`
	UserAgent string    `json:"user_agent" db:"user_agent"`
	Referer   string    `json:"referer" db:"referer"`
	Country   string    `json:"country" db:"country"`
	City      string    `json:"city" db:"city"`
	ClickedAt time.Time `json:"clicked_at" db:"clicked_at"`
}

type User struct {
	UserID       string    `json:"user_id" db:"user_id"`
	Email        string    `json:"email" db:"email"`
	PasswordHash string    `json:"-" db:"password_hash"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	Status       int       `json:"status" db:"status"`
}

// API请求响应结构
type CreateShortURLRequest struct {
	OriginalURL    string     `json:"original_url" binding:"required,url"`
	CustomAlias    string     `json:"custom_alias,omitempty"`
	ExpirationDate *time.Time `json:"expiration_date,omitempty"`
}

type CreateShortURLResponse struct {
	ShortURL       string    `json:"short_url"`
	OriginalURL    string    `json:"original_url"`
	ShortCode      string    `json:"short_code"`
	CreationDate   time.Time `json:"creation_date"`
	ExpirationDate *time.Time `json:"expiration_date,omitempty"`
}

type AnalyticsResponse struct {
	ShortCode     string            `json:"short_code"`
	ClickCount    int64             `json:"click_count"`
	UniqueClicks  int64             `json:"unique_clicks"`
	ReferringSites map[string]int64  `json:"referring_sites"`
	LocationData  map[string]int64  `json:"location_data"`
	DeviceData    map[string]int64  `json:"device_data"`
	TimeRange     map[string]int64  `json:"time_range"`
}

// Base62编码
const base62Chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func encodeBase62(num int64) string {
	if num == 0 {
		return "0"
	}
	
	var encoded strings.Builder
	for num > 0 {
		encoded.WriteByte(base62Chars[num%62])
		num /= 62
	}
	
	// 反转字符串
	result := encoded.String()
	runes := []rune(result)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func decodeBase62(encoded string) int64 {
	var num int64
	base := int64(62)
	
	for _, char := range encoded {
		var val int64
		switch {
		case char >= '0' && char <= '9':
			val = int64(char - '0')
		case char >= 'a' && char <= 'z':
			val = int64(char-'a') + 10
		case char >= 'A' && char <= 'Z':
			val = int64(char-'A') + 36
		default:
			return 0
		}
		num = num*base + val
	}
	return num
}

// 密钥生成服务 (KGS)
type KeyGenerationService struct {
	counter    int64
	mutex      sync.Mutex
	keyCache   chan string
	config     KGSConfig
	cacheSize  int
}

func NewKeyGenerationService(config KGSConfig) *KeyGenerationService {
	kgs := &KeyGenerationService{
		counter:   1000000, // 起始值，避免生成太短的码
		keyCache:  make(chan string, config.CacheSize),
		config:    config,
		cacheSize: config.CacheSize,
	}
	
	// 预生成密钥
	if config.PreGenerate {
		go kgs.preGenerateKeys()
	}
	
	return kgs
}

func (kgs *KeyGenerationService) preGenerateKeys() {
	for {
		if len(kgs.keyCache) < kgs.cacheSize/2 {
			for i := 0; i < kgs.config.BatchSize; i++ {
				key := kgs.generateKey()
				select {
				case kgs.keyCache <- key:
				default:
					return // 缓存已满
				}
			}
		}
		time.Sleep(time.Millisecond * 100)
	}
}

func (kgs *KeyGenerationService) generateKey() string {
	kgs.mutex.Lock()
	defer kgs.mutex.Unlock()
	
	kgs.counter++
	return encodeBase62(kgs.counter)
}

func (kgs *KeyGenerationService) GetKey() string {
	select {
	case key := <-kgs.keyCache:
		return key
	default:
		return kgs.generateKey()
	}
}

// 缓存服务
type CacheService struct {
	client *redis.Client
	ctx    context.Context
}

func NewCacheService(config RedisConfig) *CacheService {
	client := redis.NewClient(&redis.Options{
		Addr:         config.Addr,
		Password:     config.Password,
		DB:           config.DB,
		PoolSize:     config.PoolSize,
		MinIdleConns: config.MinIdleConns,
	})
	
	return &CacheService{
		client: client,
		ctx:    context.Background(),
	}
}

func (cs *CacheService) Set(key string, value interface{}, expiration time.Duration) error {
	return cs.client.Set(cs.ctx, key, value, expiration).Err()
}

func (cs *CacheService) Get(key string) (string, error) {
	return cs.client.Get(cs.ctx, key).Result()
}

func (cs *CacheService) Delete(key string) error {
	return cs.client.Del(cs.ctx, key).Err()
}

func (cs *CacheService) IncrementCounter(key string, expiration time.Duration) (int64, error) {
	pipe := cs.client.TxPipeline()
	incr := pipe.Incr(cs.ctx, key)
	pipe.Expire(cs.ctx, key, expiration)
	_, err := pipe.Exec(cs.ctx)
	if err != nil {
		return 0, err
	}
	return incr.Val(), nil
}

// 数据库服务
type DatabaseService struct {
	db *sql.DB
}

func NewDatabaseService(config DatabaseConfig) (*DatabaseService, error) {
	db, err := sql.Open("mysql", config.DSN)
	if err != nil {
		return nil, err
	}
	
	db.SetMaxOpenConns(config.MaxOpenConns)
	db.SetMaxIdleConns(config.MaxIdleConns)
	
	if config.ConnMaxLifetime != "" {
		duration, err := time.ParseDuration(config.ConnMaxLifetime)
		if err == nil {
			db.SetConnMaxLifetime(duration)
		}
	}
	
	return &DatabaseService{db: db}, nil
}

func (ds *DatabaseService) CreateURLMapping(mapping *URLMapping) error {
	query := `INSERT INTO url_mapping (short_code, original_url, user_id, created_at, expires_at, status, custom_alias) 
			  VALUES (?, ?, ?, ?, ?, ?, ?)`
	
	_, err := ds.db.Exec(query, mapping.ShortCode, mapping.OriginalURL, mapping.UserID,
		mapping.CreatedAt, mapping.ExpiresAt, mapping.Status, mapping.CustomAlias)
	return err
}

func (ds *DatabaseService) GetURLMapping(shortCode string) (*URLMapping, error) {
	query := `SELECT short_code, original_url, user_id, created_at, expires_at, status, custom_alias 
			  FROM url_mapping WHERE short_code = ? AND status = 1`
	
	mapping := &URLMapping{}
	err := ds.db.QueryRow(query, shortCode).Scan(
		&mapping.ShortCode, &mapping.OriginalURL, &mapping.UserID,
		&mapping.CreatedAt, &mapping.ExpiresAt, &mapping.Status, &mapping.CustomAlias,
	)
	
	if err != nil {
		return nil, err
	}
	
	// 检查是否过期
	if mapping.ExpiresAt != nil && mapping.ExpiresAt.Before(time.Now()) {
		ds.DeleteURLMapping(shortCode)
		return nil, fmt.Errorf("URL已过期")
	}
	
	return mapping, nil
}

func (ds *DatabaseService) DeleteURLMapping(shortCode string) error {
	query := `UPDATE url_mapping SET status = 0 WHERE short_code = ?`
	_, err := ds.db.Exec(query, shortCode)
	return err
}

func (ds *DatabaseService) RecordAnalytics(analytics *Analytics) error {
	query := `INSERT INTO url_analytics (short_code, ip_address, user_agent, referer, country, city, clicked_at) 
			  VALUES (?, ?, ?, ?, ?, ?, ?)`
	
	_, err := ds.db.Exec(query, analytics.ShortCode, analytics.IPAddress, analytics.UserAgent,
		analytics.Referer, analytics.Country, analytics.City, analytics.ClickedAt)
	return err
}

func (ds *DatabaseService) GetAnalytics(shortCode string, startDate, endDate *time.Time) (*AnalyticsResponse, error) {
	baseQuery := `SELECT COUNT(*) as click_count, 
					     COUNT(DISTINCT ip_address) as unique_clicks 
				  FROM url_analytics WHERE short_code = ?`
	
	args := []interface{}{shortCode}
	
	if startDate != nil && endDate != nil {
		baseQuery += " AND clicked_at BETWEEN ? AND ?"
		args = append(args, *startDate, *endDate)
	}
	
	var clickCount, uniqueClicks int64
	err := ds.db.QueryRow(baseQuery, args...).Scan(&clickCount, &uniqueClicks)
	if err != nil {
		return nil, err
	}
	
	// 获取推荐网站统计
	referringQuery := `SELECT referer, COUNT(*) as count 
					   FROM url_analytics 
					   WHERE short_code = ? AND referer != '' 
					   GROUP BY referer 
					   ORDER BY count DESC LIMIT 10`
	
	referringSites := make(map[string]int64)
	rows, err := ds.db.Query(referringQuery, shortCode)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var referer string
			var count int64
			rows.Scan(&referer, &count)
			referringSites[referer] = count
		}
	}
	
	// 获取地理位置统计
	locationQuery := `SELECT country, COUNT(*) as count 
					  FROM url_analytics 
					  WHERE short_code = ? AND country != '' 
					  GROUP BY country 
					  ORDER BY count DESC LIMIT 20`
	
	locationData := make(map[string]int64)
	rows, err = ds.db.Query(locationQuery, shortCode)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var country string
			var count int64
			rows.Scan(&country, &count)
			locationData[country] = count
		}
	}
	
	return &AnalyticsResponse{
		ShortCode:      shortCode,
		ClickCount:     clickCount,
		UniqueClicks:   uniqueClicks,
		ReferringSites: referringSites,
		LocationData:   locationData,
		DeviceData:     make(map[string]int64),
		TimeRange:      make(map[string]int64),
	}, nil
}

// 限流器
type RateLimiter struct {
	limiters sync.Map // map[string]*rate.Limiter
	rps      int
	burst    int
}

func NewRateLimiter(rps, burst int) *RateLimiter {
	return &RateLimiter{
		rps:   rps,
		burst: burst,
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	limiter, _ := rl.limiters.LoadOrStore(key, rate.NewLimiter(rate.Limit(rl.rps), rl.burst))
	return limiter.(*rate.Limiter).Allow()
}

// 主服务
type TinyURLService struct {
	config     Config
	db         *DatabaseService
	cache      *CacheService
	kgs        *KeyGenerationService
	limiter    *RateLimiter
	httpServer *http.Server
}

func NewTinyURLService(config Config) (*TinyURLService, error) {
	// 初始化数据库
	db, err := NewDatabaseService(config.Database)
	if err != nil {
		return nil, fmt.Errorf("初始化数据库失败: %v", err)
	}
	
	// 初始化缓存
	cache := NewCacheService(config.Redis)
	
	// 初始化密钥生成服务
	kgs := NewKeyGenerationService(config.KGS)
	
	// 初始化限流器
	limiter := NewRateLimiter(config.Server.RateLimitRPS, config.Server.RateLimitBurst)
	
	return &TinyURLService{
		config:  config,
		db:      db,
		cache:   cache,
		kgs:     kgs,
		limiter: limiter,
	}, nil
}

// URL验证
func (s *TinyURLService) validateURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("URL不能为空")
	}
	
	if len(urlStr) > 2048 {
		return fmt.Errorf("URL长度不能超过2048字符")
	}
	
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("URL格式无效: %v", err)
	}
	
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("只支持HTTP和HTTPS协议")
	}
	
	return nil
}

// 创建短链接
func (s *TinyURLService) CreateShortURL(req *CreateShortURLRequest, userID string) (*CreateShortURLResponse, error) {
	// 验证原始URL
	if err := s.validateURL(req.OriginalURL); err != nil {
		return nil, err
	}
	
	var shortCode string
	var isCustom bool
	
	// 处理自定义别名
	if req.CustomAlias != "" {
		if len(req.CustomAlias) < 4 || len(req.CustomAlias) > 16 {
			return nil, fmt.Errorf("自定义别名长度应在4-16字符之间")
		}
		
		// 检查自定义别名是否已存在
		if _, err := s.db.GetURLMapping(req.CustomAlias); err == nil {
			return nil, fmt.Errorf("自定义别名已存在")
		}
		
		shortCode = req.CustomAlias
		isCustom = true
	} else {
		// 生成短链码
		shortCode = s.kgs.GetKey()
	}
	
	// 创建URL映射记录
	mapping := &URLMapping{
		ShortCode:   shortCode,
		OriginalURL: req.OriginalURL,
		UserID:      userID,
		CreatedAt:   time.Now(),
		ExpiresAt:   req.ExpirationDate,
		Status:      1,
		CustomAlias: isCustom,
	}
	
	// 保存到数据库
	if err := s.db.CreateURLMapping(mapping); err != nil {
		return nil, fmt.Errorf("创建短链接失败: %v", err)
	}
	
	// 缓存热点数据
	cacheKey := "url:" + shortCode
	s.cache.Set(cacheKey, req.OriginalURL, 24*time.Hour)
	
	// 构建完整短链接
	shortURL := fmt.Sprintf("%s/%s", s.config.Server.Domain, shortCode)
	
	return &CreateShortURLResponse{
		ShortURL:       shortURL,
		OriginalURL:    req.OriginalURL,
		ShortCode:      shortCode,
		CreationDate:   mapping.CreatedAt,
		ExpirationDate: req.ExpirationDate,
	}, nil
}

// 重定向服务
func (s *TinyURLService) RedirectURL(shortCode, clientIP, userAgent, referer string) (string, error) {
	// 首先查询缓存
	cacheKey := "url:" + shortCode
	originalURL, err := s.cache.Get(cacheKey)
	
	if err == redis.Nil {
		// 缓存未命中，查询数据库
		mapping, err := s.db.GetURLMapping(shortCode)
		if err != nil {
			return "", fmt.Errorf("短链接不存在或已过期")
		}
		
		originalURL = mapping.OriginalURL
		
		// 更新缓存
		s.cache.Set(cacheKey, originalURL, 24*time.Hour)
	} else if err != nil {
		return "", fmt.Errorf("查询失败: %v", err)
	}
	
	// 异步记录访问统计
	go s.recordAnalytics(shortCode, clientIP, userAgent, referer)
	
	// 增加访问计数
	counterKey := "counter:" + shortCode
	s.cache.IncrementCounter(counterKey, 24*time.Hour)
	
	return originalURL, nil
}

// 记录访问统计
func (s *TinyURLService) recordAnalytics(shortCode, clientIP, userAgent, referer string) {
	analytics := &Analytics{
		ShortCode: shortCode,
		IPAddress: clientIP,
		UserAgent: userAgent,
		Referer:   referer,
		Country:   s.getCountryFromIP(clientIP),
		City:      s.getCityFromIP(clientIP),
		ClickedAt: time.Now(),
	}
	
	s.db.RecordAnalytics(analytics)
}

// 获取国家信息（简化实现，实际可使用GeoIP库）
func (s *TinyURLService) getCountryFromIP(ip string) string {
	// 这里可以集成MaxMind GeoIP等服务
	// 简化实现返回默认值
	return "US"
}

// 获取城市信息
func (s *TinyURLService) getCityFromIP(ip string) string {
	// 这里可以集成MaxMind GeoIP等服务
	return "Unknown"
}

// 获取分析数据
func (s *TinyURLService) GetAnalytics(shortCode string, startDate, endDate *time.Time) (*AnalyticsResponse, error) {
	return s.db.GetAnalytics(shortCode, startDate, endDate)
}

// 删除短链接
func (s *TinyURLService) DeleteShortURL(shortCode, userID string) error {
	// 验证用户权限（简化实现）
	mapping, err := s.db.GetURLMapping(shortCode)
	if err != nil {
		return fmt.Errorf("短链接不存在")
	}
	
	if mapping.UserID != userID {
		return fmt.Errorf("无权限删除此短链接")
	}
	
	// 删除数据库记录
	if err := s.db.DeleteURLMapping(shortCode); err != nil {
		return fmt.Errorf("删除失败: %v", err)
	}
	
	// 删除缓存
	cacheKey := "url:" + shortCode
	s.cache.Delete(cacheKey)
	
	return nil
}

// HTTP处理器
func (s *TinyURLService) setupRoutes() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	
	// 中间件
	r.Use(s.corsMiddleware())
	r.Use(s.rateLimitMiddleware())
	r.Use(s.loggingMiddleware())
	
	// 健康检查
	r.GET("/health", s.healthCheckHandler)
	
	// API路由组
	api := r.Group("/api/v1")
	{
		api.POST("/shorten", s.authMiddleware(), s.createShortURLHandler)
		api.GET("/analytics/:shortCode", s.authMiddleware(), s.getAnalyticsHandler)
		api.DELETE("/:shortCode", s.authMiddleware(), s.deleteShortURLHandler)
		api.GET("/user/urls", s.authMiddleware(), s.getUserURLsHandler)
	}
	
	// 重定向处理
	r.GET("/:shortCode", s.redirectHandler)
	
	return r
}

// CORS中间件
func (s *TinyURLService) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		
		c.Next()
	}
}

// 限流中间件
func (s *TinyURLService) rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		
		if !s.limiter.Allow(clientIP) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "请求频率过高，请稍后重试",
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// 日志中间件
func (s *TinyURLService) loggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	})
}

// JWT认证中间件
func (s *TinyURLService) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "缺少Authorization header",
			})
			c.Abort()
			return
		}
		
		// 解析Bearer token
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "无效的token格式",
			})
			c.Abort()
			return
		}
		
		// 验证JWT token
		token, err := jwt.Parse(tokenParts[1], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("意外的签名方法: %v", token.Header["alg"])
			}
			return []byte(s.config.Server.JWTSecret), nil
		})
		
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "无效的token",
			})
			c.Abort()
			return
		}
		
		// 提取用户ID
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if userID, exists := claims["user_id"].(string); exists {
				c.Set("user_id", userID)
			}
		}
		
		c.Next()
	}
}

// 健康检查处理器
func (s *TinyURLService) healthCheckHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"version":   "1.0.0",
	})
}

// 创建短链接处理器
func (s *TinyURLService) createShortURLHandler(c *gin.Context) {
	var req CreateShortURLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "请求参数无效: " + err.Error(),
		})
		return
	}
	
	userID := c.GetString("user_id")
	if userID == "" {
		userID = s.generateAnonymousUserID(c.ClientIP())
	}
	
	response, err := s.CreateShortURL(&req, userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusCreated, response)
}

// 重定向处理器
func (s *TinyURLService) redirectHandler(c *gin.Context) {
	shortCode := c.Param("shortCode")
	if shortCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "短链码不能为空",
		})
		return
	}
	
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")
	referer := c.GetHeader("Referer")
	
	originalURL, err := s.RedirectURL(shortCode, clientIP, userAgent, referer)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": err.Error(),
		})
		return
	}
	
	// HTTP 302重定向
	c.Redirect(http.StatusFound, originalURL)
}

// 获取分析数据处理器
func (s *TinyURLService) getAnalyticsHandler(c *gin.Context) {
	shortCode := c.Param("shortCode")
	if shortCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "短链码不能为空",
		})
		return
	}
	
	// 解析时间范围参数
	var startDate, endDate *time.Time
	if start := c.Query("start_date"); start != "" {
		if parsed, err := time.Parse("2006-01-02", start); err == nil {
			startDate = &parsed
		}
	}
	if end := c.Query("end_date"); end != "" {
		if parsed, err := time.Parse("2006-01-02", end); err == nil {
			endDate = &parsed
		}
	}
	
	analytics, err := s.GetAnalytics(shortCode, startDate, endDate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "获取分析数据失败: " + err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, analytics)
}

// 删除短链接处理器
func (s *TinyURLService) deleteShortURLHandler(c *gin.Context) {
	shortCode := c.Param("shortCode")
	userID := c.GetString("user_id")
	
	if err := s.DeleteShortURL(shortCode, userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"status": "短链接已删除",
	})
}

// 获取用户URL列表处理器
func (s *TinyURLService) getUserURLsHandler(c *gin.Context) {
	userID := c.GetString("user_id")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	
	offset := (page - 1) * pageSize
	
	// 查询用户的URL列表
	query := `SELECT short_code, original_url, created_at, expires_at, custom_alias 
			  FROM url_mapping 
			  WHERE user_id = ? AND status = 1 
			  ORDER BY created_at DESC 
			  LIMIT ? OFFSET ?`
	
	rows, err := s.db.db.Query(query, userID, pageSize, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "查询失败: " + err.Error(),
		})
		return
	}
	defer rows.Close()
	
	var urls []map[string]interface{}
	for rows.Next() {
		var shortCode, originalURL string
		var createdAt time.Time
		var expiresAt *time.Time
		var customAlias bool
		
		rows.Scan(&shortCode, &originalURL, &createdAt, &expiresAt, &customAlias)
		
		url := map[string]interface{}{
			"short_code":   shortCode,
			"short_url":    fmt.Sprintf("%s/%s", s.config.Server.Domain, shortCode),
			"original_url": originalURL,
			"created_at":   createdAt,
			"custom_alias": customAlias,
		}
		
		if expiresAt != nil {
			url["expires_at"] = *expiresAt
		}
		
		urls = append(urls, url)
	}
	
	c.JSON(http.StatusOK, gin.H{
		"urls":      urls,
		"page":      page,
		"page_size": pageSize,
		"total":     len(urls),
	})
}

// 生成匿名用户ID
func (s *TinyURLService) generateAnonymousUserID(clientIP string) string {
	hash := md5.Sum([]byte(clientIP + time.Now().Format("2006-01-02")))
	return "anon_" + hex.EncodeToString(hash[:])[:8]
}

// 启动服务
func (s *TinyURLService) Start() error {
	router := s.setupRoutes()
	
	s.httpServer = &http.Server{
		Addr:           ":" + s.config.Server.Port,
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}
	
	log.Printf("TinyURL服务启动在端口: %s", s.config.Server.Port)
	return s.httpServer.ListenAndServe()
}

// 优雅关闭
func (s *TinyURLService) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// 清理过期链接的后台任务
func (s *TinyURLService) startCleanupTask() {
	ticker := time.NewTicker(24 * time.Hour) // 每24小时运行一次
	go func() {
		for {
			select {
			case <-ticker.C:
				s.cleanupExpiredURLs()
			}
		}
	}()
}

func (s *TinyURLService) cleanupExpiredURLs() {
	log.Println("开始清理过期链接...")
	
	// 批量删除过期链接
	query := `UPDATE url_mapping SET status = 0 
			  WHERE expires_at IS NOT NULL 
			  AND expires_at < NOW() 
			  AND status = 1 
			  LIMIT 1000`
	
	for {
		result, err := s.db.db.Exec(query)
		if err != nil {
			log.Printf("清理过期链接失败: %v", err)
			break
		}
		
		affected, _ := result.RowsAffected()
		if affected == 0 {
			break
		}
		
		log.Printf("清理了 %d 个过期链接", affected)
		time.Sleep(time.Second) // 避免对数据库造成压力
	}
	
	log.Println("过期链接清理完成")
}

// 配置文件示例
func getDefaultConfig() Config {
	return Config{
		Database: DatabaseConfig{
			DSN:             "user:password@tcp(localhost:3306)/tinyurl?charset=utf8mb4&parseTime=True&loc=Local",
			MaxOpenConns:    100,
			MaxIdleConns:    10,
			ConnMaxLifetime: "1h",
		},
		Redis: RedisConfig{
			Addr:         "localhost:6379",
			Password:     "",
			DB:           0,
			PoolSize:     100,
			MinIdleConns: 10,
		},
		Server: ServerConfig{
			Port:           "8080",
			Domain:         "https://short.ly",
			JWTSecret:      "your-super-secret-jwt-key",
			RateLimitRPS:   100,
			RateLimitBurst: 200,
		},
		KGS: KGSConfig{
			CacheSize:   10000,
			PreGenerate: true,
			BatchSize:   1000,
			WorkerCount: 4,
		},
	}
}

// 数据库初始化脚本
const initSQL = `
CREATE TABLE IF NOT EXISTS url_mapping (
    short_code VARCHAR(16) PRIMARY KEY,
    original_url TEXT NOT NULL,
    user_id VARCHAR(32),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    status TINYINT DEFAULT 1,
    custom_alias BOOLEAN DEFAULT FALSE,
    INDEX idx_user_id (user_id),
    INDEX idx_created_at (created_at),
    INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS url_analytics (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    short_code VARCHAR(16) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    referer TEXT,
    country VARCHAR(2),
    city VARCHAR(50),
    clicked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_short_code (short_code),
    INDEX idx_clicked_at (clicked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(32) PRIMARY KEY,
    email VARCHAR(100) UNIQUE,
    password_hash VARCHAR(128),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TINYINT DEFAULT 1,
    INDEX idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`

// 主函数
func main() {
	// 加载配置
	config := getDefaultConfig()
	
	// 创建服务实例
	service, err := NewTinyURLService(config)
	if err != nil {
		log.Fatalf("创建服务失败: %v", err)
	}
	
	// 启动清理任务
	service.startCleanupTask()
	
	// 启动HTTP服务
	if err := service.Start(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("服务启动失败: %v", err)
	}
}
