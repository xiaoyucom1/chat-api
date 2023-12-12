package main

import (
	"embed"
	"fmt"
	"log"
	"one-api/common"
	"one-api/controller"
	"one-api/middleware"
	"one-api/model"
	"one-api/router"
	"os"
	"strconv"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	_ "net/http/pprof"
)

//go:embed web/build
var buildFS embed.FS

//go:embed web/build/index.html
var indexPage []byte

func main() {
	common.SetupLogger()
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found or error loading")
	}

	common.SysLog("One API " + common.Version + " started")
	if os.Getenv("GIN_MODE") != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}
	if common.DebugEnabled {
		common.SysLog("running in debug mode")
	}
	// Initialize SQL Database
	// 初始化 SQL 数据库，并在结束时关闭它。
	if err := model.InitDB(); err != nil { // 使用 := 声明和初始化 err
		common.FatalLog("failed to initialize database: " + err.Error())
	}
	defer func() {
		if err := model.CloseDB(); err != nil { // defer 中又一个新的作用域和局部变量 err
			common.FatalLog("failed to close database: " + err.Error())
		}
	}()

	// Initialize Redis
	if err := common.InitRedisClient(); err != nil { // 再次使用 := 声明和初始化 err
		common.FatalLog("failed to initialize Redis: " + err.Error())
	}

	// Initialize options
	model.InitOptionMap()
	if common.RedisEnabled {
		// for compatibility with old versions
		common.MemoryCacheEnabled = true
	}
	if common.MemoryCacheEnabled {
		common.SysLog("memory cache enabled")
		common.SysError(fmt.Sprintf("sync frequency: %d seconds", common.SyncFrequency))
		model.InitChannelCache()
	}
	if common.MemoryCacheEnabled {
		go model.SyncOptions(common.SyncFrequency)
		go model.SyncChannelCache(common.SyncFrequency)
	}
	if os.Getenv("CHANNEL_UPDATE_FREQUENCY") != "" {
		frequency, err := strconv.Atoi(os.Getenv("CHANNEL_UPDATE_FREQUENCY"))
		if err != nil {
			common.FatalLog("failed to parse CHANNEL_UPDATE_FREQUENCY: " + err.Error())
		}
		go controller.AutomaticallyUpdateChannels(frequency)
	}
	if os.Getenv("CHANNEL_TEST_FREQUENCY") != "" {
		frequency, err := strconv.Atoi(os.Getenv("CHANNEL_TEST_FREQUENCY"))
		if err != nil {
			common.FatalLog("failed to parse CHANNEL_TEST_FREQUENCY: " + err.Error())
		}

		gptVersion := os.Getenv("GPT_VERSION") // 获取 GPT 版本环境变量
		if gptVersion == "" {
			gptVersion = "gpt-3.5-turbo" // 如果没有设置环境变量，默认为 "gpt-3.5-turbo"
		}

		go controller.AutomaticallyTestChannels(frequency, gptVersion)
	}

	go controller.UpdateMidjourneyTask()
	if os.Getenv("BATCH_UPDATE_ENABLED") == "true" {
		common.BatchUpdateEnabled = true
		common.SysLog("batch update enabled with interval " + strconv.Itoa(common.BatchUpdateInterval) + "s")
		model.InitBatchUpdater()
	}

	if os.Getenv("ENABLE_PPROF") == "true" {
		go common.Monitor()
		common.SysLog("pprof enabled")
	}

	controller.InitTokenEncoders()

	// Initialize HTTP server
	server := gin.New()
	server.Use(gin.Recovery())
	// This will cause SSE not to work!!!
	//server.Use(gzip.Gzip(gzip.DefaultCompression))
	server.Use(middleware.RequestId())
	middleware.SetUpLogger(server)
	// Initialize session store
	store := cookie.NewStore([]byte(common.SessionSecret))
	server.Use(sessions.Sessions("session", store))

	router.SetRouter(server, buildFS, indexPage)
	var port = os.Getenv("PORT")
	if port == "" {
		port = strconv.Itoa(*common.Port)
	}
	// 启动 HTTP 服务器。
	if err := server.Run(":" + port); err != nil { // 再次使用 := 声明和初始化 err
		common.FatalLog("failed to start HTTP server: " + err.Error())
	}
}
