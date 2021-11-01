package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/matryer/runner"
	"github.com/netmsglog/okv5/okex"
	"github.com/rapidloop/skv"
)

// Trade - 数据表，用于记录网格交易成交记录
type Trade struct {
	ID         string    `gorm:"primary_key"` // okex订单号
	Symbol     string    // 交易对
	TradeTime  time.Time // 交易时间
	Side       string    // 方向: sell/buy
	Price      float64   // 开单价格
	Size       float64   // 开单量
	RealAmount float64   // 实际成交额
	RealPrice  float64   // 实际成交价格
	RealSize   float64   // 实际成交数量
	Grid       int       // 对应网格索引
}

// Grid - 网格数据结构
type Grid struct {
	Index   int    // 格子索引，备用
	Orderid string // okex返回平台订单号
	Status  int    // 网格状态： -1 下单失败   0 未下单或空闲已完成   1 已下单
}

var (
	okexCli          *okex.Client
	db               *gorm.DB          // 网格成交订单数据库
	cache            *skv.KVStore      // 网格跟踪K/V数据: ltc-usdt-1 => Grid
	reverse          *skv.KVStore      // 订单反向索引K/V数据: 2013413423424324 => ltc-usdt-1
	priceConfig      map[string]string // 货币的price的小数点精度
	sizeConfig       map[string]string // 货币的size的小数点精度
	gridTask         *runner.Task
	maxPrice         float64 // 网格上限
	minPrice         float64 // 网格下限
	minBalance       float64 // 最低余额
	currentSymbol    string  // 当前交易对
	motherCurrency   string  // 母币，用于获取余额
	availableBalance float64 // 可用余额
	currentStatus    string  // 当前状态
	globalCID        string  // 当前API账户标示
)

func encrypt(key []byte, message string) (encmess string, err error) {
	plainText := []byte(message)

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	//returns to base64 encoded string
	encmess = base64.URLEncoding.EncodeToString(cipherText)
	return
}

func decrypt(key []byte, securemess string) (decodedmess string, err error) {
	cipherText, err := base64.URLEncoding.DecodeString(securemess)
	if err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("ciphertext block size is too short")
		return
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(cipherText, cipherText)

	decodedmess = string(cipherText)
	return
}

// ToFloat : 将字符串转换为float64
func ToFloat(s string) float64 {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		fmt.Println(err)
		return 0.0
	}
	return f
}

// ToInt : 字符串转换为整数
func ToInt(s string) int {
	f, err := strconv.Atoi(s)
	if err != nil {
		// fmt.Println(err)
		return 0
	}
	return f
}

// ToTime : 将字符串转换为time.Time
func ToTime(s string) time.Time {
	/*
		layout := "2006-01-02T15:04:05.000Z"
		t, err := time.Parse(layout, s)
		if err != nil {
			fmt.Println(err)
			return time.Time{}
		}
		return t
	*/
	t, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(0, t*int64(time.Millisecond))
}

func file2strs(fileName string) []string {
	f, _ := os.Open(fileName)
	// Create new Scanner.
	scanner := bufio.NewScanner(f)
	result := []string{}
	// Use Scan.
	for scanner.Scan() {
		line := scanner.Text()
		// Append line to result.
		result = append(result, line)
	}
	return result
}

func sendReq(address string, paras *url.Values) string {
	resp, err := http.PostForm(address, *paras)
	if err != nil {
		fmt.Println("http post error:", err)
		return ""
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("http post body read error:", err)
		return ""
	}
	return string(body)
}

func report(cid string, symbol string, step string, size string, low string, high string, max string, price string, profit string, status string) string {
	p := url.Values{}
	p.Set("cid", cid)
	p.Set("symbol", symbol)
	p.Set("step", step)
	p.Set("size", size)
	p.Set("low", low)
	p.Set("high", high)
	p.Set("max", max)
	p.Set("price", price)
	p.Set("profit", profit)
	p.Set("status", status)
	return sendReq("http://127.0.0.1/rep", &p)
}

func register(cid string, apikey string, secret string, passphrase string) string {
	p := url.Values{}
	p.Set("cid", cid)
	p.Set("apikey", apikey)
	p.Set("secret", secret)
	p.Set("passphrase", passphrase)
	return sendReq("http://127.0.0.1/reg", &p)
}

// 初始化okex客户端和数据库
func init() {
	var config okex.Config
	var err error

	// 读取配置文件
	cfgFile := file2strs(".config")
	if len(cfgFile) < 4 { // 最后一行为CID标示
		fmt.Println("错误的配置文件!")
		os.Exit(1)
	}
	cipher := []byte("4dHqMHNpbNxTriVf")
	config.Endpoint = "https://www.okex.com/"
	config.ApiKey, _ = decrypt(cipher, cfgFile[0])
	config.SecretKey, _ = decrypt(cipher, cfgFile[1])
	config.Passphrase, _ = decrypt(cipher, cfgFile[2])
	// config.IsPrint = true
	globalCID = cfgFile[3]
	config.TimeoutSecond = 45
	config.IsPrint = false
	config.I18n = okex.ENGLISH
	okexCli = okex.NewClient(config)

	currentStatus = "stopped"
	register(globalCID, cfgFile[0], cfgFile[1], cfgFile[2])
	gridTask = nil

	maxPrice = 10000.0
	minPrice = 0.0
	currentSymbol = "btc-usdt"
	motherCurrency = "USDT"
	availableBalance = 100000.0
	minBalance = 1000.0
	priceConfig = make(map[string]string)
	sizeConfig = make(map[string]string)
	priceConfig["ETH-USDT"] = "%.2f"
	sizeConfig["ETH-USDT"] = "%.3f"
	db, err = gorm.Open("sqlite3", "trade.db")
	if err != nil {
		fmt.Println(err)
		panic("无法打开交易数据库trade.db")
	}
	db.AutoMigrate(&Trade{})

	cache, err = skv.Open("grid.db")
	if err != nil {
		fmt.Println(err)
		panic("无法打开网格数据库grid.db")
	}
	reverse, err = skv.Open("reverse.db")
	if err != nil {
		fmt.Println(err)
		panic("无法打开反向跟踪数据库reverse.db")
	}
}

// 程序中断时(e.g. kill或Ctrl-C)关闭数据库
func shutdown() {
	db.Close()
	cache.Close()
}

// 捕获系统中断(e.g. kill或Ctrl-C)
func catchInterrupts() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGUSR1)
	go func() {
		for sig := range c {
			if sig == syscall.SIGUSR1 {
			} else {
				fmt.Println("正在关闭程序:", sig)
				if gridTask != nil {
					gridTask.Stop()
				}
				// shutdown()
				// os.Exit(0)
			}
		}
	}()
}

// 当前时间
func curTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

/*
postOrder - okex下单个订单，成功返回okex订单id，失败返回"-1"
	symbol - 交易对
	direction - buy/sell
	price - 限价
	size - 交易量
*/
func postOrder(symbol string, direction string, price string, size string) string {
	opts := okex.NewParams()
	opts["type"] = "limit"
	opts["price"] = price
	opts["size"] = size
	r, err := okexCli.PostSpotOrders(direction, symbol, &opts)
	if err != nil || r == nil {
		fmt.Printf("okex下单失败:%s (%s %s %s):\n", symbol, direction, opts["price"], opts["size"])
		if err != nil {
			fmt.Println(err)
		}
		if r == nil {
			fmt.Println("null return!")
		} else {
			jstr, _ := okex.Struct2JsonString(r)
			fmt.Println(jstr)
		}
		return "-1"
	}
	oid := (*r)["ordId"].(string)
	sCode := (*r)["sCode"].(string)
	sMsg := (*r)["sMsg"].(string)
	if sCode != "0" {
		fmt.Printf("okex下单失败:%s (%s %s %s):订单号(%s) (code:%s) (msg:%s)\n", symbol, direction, opts["price"], opts["size"], oid, sCode, sMsg)
		jstr, _ := okex.Struct2JsonString(r)
		fmt.Println(jstr)
		return "-1"
	} else {
		fmt.Printf("okex下单成功:%s (%s %s %s):订单号(%s)\n", symbol, direction, opts["price"], opts["size"], oid)
	}
	return oid
}

/*
cancelOrder - okex取消单个订单，成功返回true, 失败返回false
	symbol - 交易对
	oid - okex订单号
*/
func cancelOrder(symbol string, oid string) bool {
	r, err := okexCli.PostSpotCancelOrders(symbol, oid)
	if err != nil || r == nil {
		fmt.Printf("okex取消订单失败:%s (%s):\n", symbol, oid)
		if err != nil {
			fmt.Println(err)
		}
		if r == nil {
			fmt.Println("null return!")
		}
		return false
	}
	sCode := (*r)["sCode"].(string)
	// sMsg := (*r)["sMsg"].(string)
	// result := (*r)["result"].(bool)
	if sCode != "0" {
		jstr, _ := okex.Struct2JsonString(r)
		fmt.Printf("okex取消订单失败:%s (%s): %s\n", symbol, oid, jstr)
		return false
	}
	return true
}

/*
getPrice - 获取单个交易对的当前价格
	symbol - 交易对
*/
func getPrice(symbol string) float64 {
	r, err := okexCli.GetSpotInstrumentTicker(strings.ToUpper(symbol))
	if err != nil {
		fmt.Printf("获取%s价格失败:%s\n", symbol, err.Error())
		return -1.0
	}
	rr := (*r)
	last := ToFloat(rr["last"].(string))
	return last
}

/*
cancelGrid - 撤销单个网格下单， 撤销对应的okex单，并把格子状态设置为-1
	symbol - 交易对
	direction - buy/sell 买单还是卖单
	idx - 网格索引
*/
func cancelGrid(symbol string, direction string, idx int) {
	var grid Grid
	// 在kvstore中的网格索引key值
	key := fmt.Sprintf("%s-%s-%d", symbol, direction, idx)
	err := cache.Get(key, &grid)
	if err != nil {
		fmt.Printf("待撤销的网格%s不存在: %s\n", key, err.Error())
		return
	}
	if grid.Status != 1 {
		fmt.Printf("网格%s已经没有对应的挂单, 状态:%d, 订单号:%s\n", key, grid.Status, grid.Orderid)
		return
	}
	// 去okex撤销订单
	// 查询订单状态，如果是open才可以撤销，如果是part_filled或者filled则不能撤销
	r, err := okexCli.GetSpotOrdersById(symbol, grid.Orderid)
	if err != nil {
		fmt.Printf("取消网格%s时，获取订单%s信息失败:%s\n", key, grid.Orderid, err)
		return
	}
	status := (*r)["state"]
	fmt.Printf("待取消网格%s对应订单%s状态:%s\n", key, grid.Orderid, status)
	if status != "live" { // 没有成交时，可以取消
		fmt.Printf("状态不是live，不能取消\n")
		return
	}
	// 偶尔会出现已经cancel成功，但是仍然完成的情况
	ret := cancelOrder(symbol, grid.Orderid)
	if ret {
		fmt.Printf("网格%s, 订单号:%s 撤销成功\n", key, grid.Orderid)
	} else {
		fmt.Printf("网格%s, 订单号:%s撤销失败\n", key, grid.Orderid)
		return
	}
	grid.Status = -1
	err = cache.Put(key, grid)
	if err != nil {
		fmt.Printf("极端错误，写入网格数据%s失败:%s\n", key, err.Error())
	}
}

/*
updateGrid - 跟踪okex已完成订单，更新对应网格数据，返回对应的网格索引，返回-1为失败
	oid - okex订单号
*/
func updateGrid(oid string) int {
	var key string
	var grid Grid
	err := reverse.Get(oid, &key)
	if err != nil {
		//		fmt.Printf("反向索引中没有对应%s的网格: %s\n", oid, err.Error())
		return -1
	}
	if key == "done" {
		//		fmt.Printf("反向索引显示订单%s对应的网格已处理，忽略后续\n", oid)
		return -1
	}
	err = cache.Get(key, &grid)
	if err != nil {
		fmt.Printf("异常错误，虽然有反向索引%s=>%s, 找不到对应的网格数据:%s\n", oid, key, err.Error())
		return -1
	}
	grid.Status = 0 // 设置状态为0 已完成或空闲
	err = cache.Put(key, grid)
	if err != nil {
		fmt.Printf("极端错误，写入网格数据%s失败:%s\n", key, err.Error())
	}
	err = reverse.Put(oid, "done")
	if err != nil {
		fmt.Printf("极端错误，写入反向数据%s=>done失败:%s\n", oid, err.Error())
	}
	fmt.Printf("订单完成: %s %d [%s %s] %d\n", key, grid.Index, oid, grid.Orderid, grid.Status)
	return grid.Index
}

func incrValue(key string) {
	var count int
	err := cache.Get(key, &count)
	if err != nil {
		count = 0
	}
	count = count + 1
	cache.Put(key, count)
}

func getValue(key string) int {
	var count int
	err := cache.Get(key, &count)
	if err != nil {
		count = 0
	}
	return count
}

/*
	setMinGridIdx - 记录当前有数据的（就是调用过setGrid的）买或卖最小格子索引
	force : 不比较直接赋值
*/
func setMinGridIdx(symbol string, direction string, idx int, force bool) {
	var min int
	key := fmt.Sprintf("min-%s-%s", symbol, direction)
	err := cache.Get(key, &min)
	if err != nil {
		min = idx
		cache.Put(key, min)
		return
	}
	if force {
		min = idx
		cache.Put(key, min)
		return
	}
	if idx < min {
		min = idx
		cache.Put(key, min)
	}
}

/*
	getMinGridIdx - 获取当前最小格子索引
*/
func getMinGridIdx(symbol string, direction string) int {
	var min int
	key := fmt.Sprintf("min-%s-%s", symbol, direction)
	err := cache.Get(key, &min)
	if err != nil {
		return -1
	}
	return min
}

/*
	setMaxGridIdx - 记录当前有数据的（就是调用过setGrid的）买或卖最大格子索引
*/
func setMaxGridIdx(symbol string, direction string, idx int, force bool) {
	var max int
	key := fmt.Sprintf("max-%s-%s", symbol, direction)
	err := cache.Get(key, &max)
	if err != nil {
		max = idx
		cache.Put(key, max)
		return
	}
	if force {
		max = idx
		cache.Put(key, max)
		return
	}
	if idx > max {
		max = idx
		cache.Put(key, max)
	}
}

/*
	getMaxGridIdx - 获取当前最小格子索引
*/
func getMaxGridIdx(symbol string, direction string) int {
	var max int
	key := fmt.Sprintf("max-%s-%s", symbol, direction)
	err := cache.Get(key, &max)
	if err != nil {
		return -1
	}
	return max
}

/*
	refreshGrid - 主动刷新网格对应订单状态，有时候批量查询已完成状态并不能返回结果
*/
func refreshGrid(symbol string, direction string, idx int, stepf float64, size string) {
	var grid Grid
	key := fmt.Sprintf("%s-%s-%d", symbol, direction, idx)
	err := cache.Get(key, &grid)
	if err != nil {
		fmt.Printf("网格%s不存在，不能刷新:%s\n", key, err.Error())
		return
	}
	if grid.Status != 1 {
		fmt.Printf("网格%s没有在运行订单:%d，不能刷新\n", key, grid.Status)
		return
	}
	r, err := okexCli.GetSpotOrdersById(symbol, grid.Orderid)
	if err != nil {
		fmt.Printf("刷新网格%s时，获取订单%s信息失败:%s\n", key, grid.Orderid, err)
		return
	}
	status := (*r)["state"]
	fmt.Printf("网格%s (%s) 对应订单%s状态:%s\n", key,
		fmt.Sprintf(priceConfig[symbol], float64(idx)*stepf),
		grid.Orderid, status)
	if status == "filled" { // 已完成
		processFilledOrder(*r, symbol, stepf, size)
	}
	if status == "failure" { // 订单出现异常，极为罕见，此时应将网格状态设置为-1，以便对应买单能继续下单
		// 重新挂单
		grid.Status = -1
		cache.Put(key, grid)
		price := fmt.Sprintf(priceConfig[symbol], float64(idx)*stepf)
		setGrid(symbol, direction, idx, price, size, true)
	}
}

/*
setGrid - 放置网格单
	symbol:交易对A-B
	direction: buy/sell 买或卖
	idx:网格索引
	price:价格
	size:交易量
	force: 表示，为true的时候，表示对应买/卖已完成，如果为空那么开单
		   为false的时候，为跟随价格买单，这时候没有应对应卖单挂单的情况下才挂买单
返回： 网格状态
网格可能的状态是：
- 0 未初始化：初始化网格数据结果，下单，修改网格数据
- 1 状态为已开单： 忽略
- 0 状态为已完成： 下单，修改网格数据
- -1 网格对应okex被撤销(一般是买单)
*/
func setGrid(symbol string, direction string, idx int, price string, size string, force bool) int {
	var grid Grid
	// 在kvstore中的网格索引key值
	key := fmt.Sprintf("%s-%s-%d", symbol, direction, idx)
	err := cache.Get(key, &grid)
	if err != nil {
		fmt.Printf("网格%s不存在，将进行创建:%s\n", key, err.Error())
		grid = Grid{Index: idx, Orderid: "-1", Status: 0}
	} else {
		if !force && grid.Status != -1 {
			fmt.Printf("有格子存在，等待对应买/卖单完成才可以开单:%s (%s) %d\n", key,
				// fmt.Sprintf(priceConfig[symbol], float64(idx)*ToFloat(price)),
				price,
				grid.Status)
			return grid.Status
		}
	}
	if grid.Status == 1 { // 已经有对应okex在运行了！
		fmt.Printf("网格%s已经开过单，订单号:%s\n", key, grid.Orderid)
		return grid.Status
	}
	// 去okex下限价单
	grid.Orderid = postOrder(symbol, direction, price, size)
	if grid.Orderid == "-1" { // 重试两次
		fmt.Printf("网格%s开单失败，重试...\n", key)
		time.Sleep(1 * time.Second)
		grid.Orderid = postOrder(symbol, direction, price, size)
		if grid.Orderid == "-1" {
			fmt.Printf("网格%s开单失败，再次重试...\n", key)
			time.Sleep(2 * time.Second)
			grid.Orderid = postOrder(symbol, direction, price, size)
		}
	}
	if grid.Orderid == "-1" {
		fmt.Printf("网格%s开单失败\n", key)
		grid.Status = -1 // 开单失败
	} else {
		grid.Status = 1 // 开单成功
		// 加入反向订单索引缓存，订单号-网格索引Key值
		err = reverse.Put(grid.Orderid, key)
		if err != nil {
			fmt.Printf("极端错误，写入反向索引数据%s=>%s失败:%s\n", grid.Orderid, key, err.Error())
		}
	}
	err = cache.Put(key, grid)
	if err != nil {
		fmt.Printf("极端错误，写入网格数据%s失败:%s\n", key, err.Error())
	}
	setMinGridIdx(symbol, direction, idx, false)
	setMaxGridIdx(symbol, direction, idx, false)
	fmt.Printf("网格%s开单成功，订单号:%s\n", key, grid.Orderid)
	return grid.Status
}

/*
runDynamicGrid - 跟随当前币价运行动态网格
	symbol:交易对A-B
	buydepth:保持买单深度
	step:网格价格间距
	size:每网购成交数量(A的数量)

TODO: 最高限价
TODO: 中途中断/恢复
TODO: 撤销
*/
func runDynamicGrid(symbol string, buydepth int, step string, size string) {
	stepf := ToFloat(step) // 网格价格步长
	profitf := stepf * ToFloat(size)
	cnt := 0
	gridTask = runner.Go(func(shouldStop runner.S) error {
		for {
			cnt = cnt + 1
			if shouldStop() {
				fmt.Printf("正在终止网格程序: %s %d %s %s...", symbol, buydepth, step, size)
				report(globalCID, symbol, step, size, "-1", "-1", "-1", "-1", "-1", "stopped")
				shutdown()
				time.Sleep(2 * time.Second)
				fmt.Println("终止完毕")
				break
			}
			currentPrice := getPrice(symbol)
			if currentPrice < 0.0 { // 获取价格失败
				// 稍后重试
				fmt.Printf("获取%s价格失败，5秒后重试..\n", symbol)
				time.Sleep(5 * time.Second)
				continue
			}

			minBuy := getMinGridIdx(symbol, "buy")
			maxBuy := getMaxGridIdx(symbol, "buy")
			minSell := getMinGridIdx(symbol, "sell")
			maxSell := getMaxGridIdx(symbol, "sell")

			totalSell := getValue(symbol + "-totalsell")
			estimateProfit := profitf * float64(totalSell)

			fmt.Printf("[%s] %s (%.4f-%.4f %s %s) 当前价格:%s\n买入:%d(%s)-%d(%s)  卖出:%d(%s)-%d(%s) 已获利润:%s\n",
				curTime(), symbol, minPrice, maxPrice, step, size,
				fmt.Sprintf(priceConfig[symbol], currentPrice),
				minBuy,
				fmt.Sprintf(priceConfig[symbol], float64(minBuy)*stepf),
				maxBuy,
				fmt.Sprintf(priceConfig[symbol], float64(maxBuy)*stepf),
				minSell,
				fmt.Sprintf(priceConfig[symbol], float64(minSell)*stepf),
				maxSell,
				fmt.Sprintf(priceConfig[symbol], float64(maxSell)*stepf),
				fmt.Sprintf(priceConfig[symbol], estimateProfit))

			idx := int(currentPrice / stepf) // 前一个网格索引
			if math.Abs(currentPrice-float64(idx)*stepf) < 0.1*stepf {
				fmt.Printf("价差小，下降格子: %d(%s)=> %d(%s)\n", idx, fmt.Sprintf(priceConfig[symbol], float64(idx)*stepf), idx-1, fmt.Sprintf(priceConfig[symbol], float64(idx-1)*stepf))
				idx = idx - 1
			}
			// 该网格和接下来的buydepth-1个网格是否挂上买单了？ 如果没有，挂上买单
			if currentPrice >= minPrice && currentPrice <= maxPrice && availableBalance > minBalance {
				for i := 0; i < buydepth; i++ {
					// 格子买单价格
					price := fmt.Sprintf(priceConfig[symbol], float64(idx-i)*stepf)
					status := setGrid(symbol, "buy", idx-i, price, size, false)
					if status == 0 { // 如果为0，说明对应的卖单没有结束，需要Refresh一下
						refreshGrid(symbol, "sell", idx-i+1, stepf, size)
					}
				}
				currentStatus = "running"
			} else {
				if availableBalance <= minBalance {
					fmt.Printf("余额已经不足最小购买额%s，不会下买单!\n", fmt.Sprintf(priceConfig[symbol], minBalance))
					currentStatus = "out-$"
				} else {
					fmt.Println("已经超过价格区间，不会下买单!")
					currentStatus = "out-p"
				}

			}
			// 监测所有完成订单状态，开启对应的买单或卖单
			f, err := okexCli.GetSpotOrders("filled", symbol, nil) // 最大100个单啊，注意是否有坑 "cancelled"
			if err != nil {
				fmt.Printf("获取%s已完成订单信息错误:%s, 5秒后重试...\n", symbol, err.Error())
				time.Sleep(5 * time.Second)
				continue
			}
			code := (*f)["code"]
			if code != "0" {
				fmt.Printf("获取%s已完成订单信息错误:%s %s, 5秒后重试...\n", symbol, code, (*f)["msg"])
				time.Sleep(5 * time.Second)
				continue
			}
			filled := (*f)["data"].([]interface{})
			// 处理每个已完成订单
			for _, recx := range filled {
				rec := recx.(map[string]interface{})
				processFilledOrder(rec, symbol, stepf, size)
			}
			// 每循环10次，撤销超过买单深度的买单以释放资金
			if cnt%10 == 0 {
				min := getMinGridIdx(symbol, "buy")
				curMin := idx - buydepth + 1
				if min < curMin {
					for i := min; i < curMin; i++ {
						cancelGrid(symbol, "buy", i)
					}
					// 设置最新的minGridIdx
					setMinGridIdx(symbol, "buy", curMin, true)
				}
			}
			// 每半分钟显示账户余额， 并且报告给gridhub
			if cnt%30 == 0 {
				showAccount()
				fmt.Println("报告到GridHub....")
				resp := report(globalCID, symbol, step, size,
					fmt.Sprintf(priceConfig[symbol], minPrice),
					fmt.Sprintf(priceConfig[symbol], maxPrice),
					fmt.Sprintf(priceConfig[symbol], float64(maxSell)*stepf),
					fmt.Sprintf(priceConfig[symbol], currentPrice),
					fmt.Sprintf(priceConfig[symbol], estimateProfit),
					currentStatus)
				if resp != "NULL" && resp != "" { // 接收命令
					fmt.Printf("接收到命令:[%s]\n", resp)
					segs := strings.Fields(resp)
					if len(segs) > 1 {
						switch {
						case segs[0] == "low":
							minPrice = ToFloat(segs[1])
						case segs[0] == "high":
							maxPrice = ToFloat(segs[1])
						}
					}
				}
			}
			// 每隔1s循环
			time.Sleep(1 * time.Second)
		}
		return nil
	})
}

func printOrder(rec map[string]interface{}) {
	orderID := rec["ordId"].(string) // 订单ID
	// orderRealAmount := ToFloat(rec["filled_notional"].(string)) // 已成交金额
	orderRealSize := rec["accFillSz"].(string)
	orderRealSizef := ToFloat(orderRealSize)    // 已成交数量
	orderPrice := ToFloat(rec["px"].(string))   // 挂单价格
	orderSize := ToFloat(rec["sz"].(string))    // 挂单数量
	realPrice := ToFloat(rec["avgPx"].(string)) // orderRealAmount / orderRealSizef // 实际成交价格
	orderRealAmount := orderRealSizef * realPrice
	orderTime := rec["cTime"].(string) // 订单创建时间
	orderSide := rec["side"].(string)  // 订单方向(buy/sell)
	orderStatus := rec["state"].(string)
	fmt.Printf("ID:%s  类型:%s 状态:%s 成交金额:%.4f 成交数量:%.4f 成交单价:%.4f, 挂单价格:%.4f 挂单数量:%.4f %s\n",
		orderID, orderSide, orderStatus, orderRealAmount, orderRealSizef, realPrice, orderPrice, orderSize, orderTime)

}

/*
	processFilledOrder - 处理已完成交易的okex订单，设置对应网格状态，设置对应的买卖网格，记录到数据库
	called by runDynamicGrid
*/
func processFilledOrder(rec map[string]interface{}, symbol string, stepf float64, size string) {
	orderID := rec["ordId"].(string) // 订单ID
	// orderRealAmount := ToFloat(rec["filled_notional"].(string)) // 已成交金额
	orderRealSize := rec["accFillSz"].(string)
	orderRealSizef := ToFloat(orderRealSize)    // 已成交数量
	orderPrice := ToFloat(rec["px"].(string))   // 挂单价格
	orderSize := ToFloat(rec["sz"].(string))    // 挂单数量
	realPrice := ToFloat(rec["avgPx"].(string)) // orderRealAmount / orderRealSizef // 实际成交价格
	orderRealAmount := orderRealSizef * realPrice
	orderTime := ToTime(rec["cTime"].(string)) // 订单创建时间
	orderSide := rec["side"].(string)          // 订单方向(buy/sell)

	ridx := updateGrid(orderID) // 找到并更新网格状态
	if ridx == -1 {             // 已经处理过了
		return
	}

	switch {
	case orderSide == "buy": // 挂对应格子卖单，以实际成交数量
		price := fmt.Sprintf(priceConfig[symbol], float64(ridx+1)*stepf)
		setGrid(symbol, "sell", ridx+1, price, orderRealSize, true)
	case orderSide == "sell": // 挂对应格子买单，以设定数量size
		price := fmt.Sprintf(priceConfig[symbol], float64(ridx-1)*stepf)
		setGrid(symbol, "buy", ridx-1, price, size, true)
		incrValue(symbol + "-totalsell")
	}
	// 存入trade数据库作为记录
	r := Trade{
		ID:         orderID,
		Symbol:     symbol,
		TradeTime:  orderTime,
		Side:       orderSide,
		Price:      orderPrice,
		Size:       orderSize,
		RealAmount: orderRealAmount,
		RealPrice:  realPrice,
		RealSize:   orderRealSizef,
		Grid:       ridx,
	}
	db.FirstOrCreate(&r, Trade{ID: orderID})
}

func showAccount() {
	f, err := okexCli.GetSpotAccounts()
	if err != nil {
		fmt.Printf("获取账户信息错误:%s\n", err.Error())
		return
	}
	/*
		jstr, _ := okex.Struct2JsonString(f)
		fmt.Println(jstr)
	*/
	data := (*f)["data"].([]interface{})
	data0 := data[0].(map[string]interface{})
	details := data0["details"].([]interface{})

	rec := details[0].(map[string]interface{})
	/*
		data := (*f)["data"] // := (*f["data"]).([]map[string]interface{})

		// 打印每个已完成订单
	*/
	fmt.Println("---------------------------------------------------------------------")
	// for _, rec := range *filled {
	currency := rec["ccy"].(string)
	balance := rec["cashBal"].(string)
	hold := rec["frozenBal"].(string)
	available := rec["availEq"].(string)
	if currency == motherCurrency {
		availableBalance = ToFloat(available)
	}
	fmt.Printf("币种:%s 可用:%s 冻结:%s 总共:%s\n", currency, available, hold, balance)
	// }
	fmt.Println("---------------------------------------------------------------------")
	fmt.Printf("可用余额:%s 最小余额:%s\n", fmt.Sprintf(priceConfig[currentSymbol], availableBalance), fmt.Sprintf(priceConfig[currentSymbol], minBalance))

}

func help() {
	fmt.Println("Usage: v5 account                    查询账户余额")
	fmt.Println("       v5 eval symbol buydepth step size minprice maxprice   评估投入资金")
	fmt.Println("       v5 grid grid-key              查询网格数据")
	fmt.Println("       v5 fix grid-key               修正网格数据")
	fmt.Println("       v5 set grid-key value-int     设置网格数据")
	fmt.Println("       v5 get grid-key     internal")
	fmt.Println("       v5 count                      查询卖单条数")
	fmt.Println("       v5 reverse order-id           查询反向数据")
	fmt.Println("       v5 query symbol order-id      查询单个订单")
	fmt.Println("       v5 cancel symbol order-id     取消单个订单")
	fmt.Println("       v5 list symbol [filled/pending]     查询所有完成订单")

	fmt.Println("       v5 order symbol buy/sell price size  手工下订单")
	fmt.Println("       v5 run symbol buydepth step size [minprice maxprice]  运行!")
	os.Exit(1)
}

func main() {
	catchInterrupts()

	if len(os.Args) < 2 {
		help()
	}
	switch {
	case os.Args[1] == "fix":
		if len(os.Args) != 3 {
			help()
		}
		key := os.Args[2]
		var grid Grid
		err := cache.Get(key, &grid)
		if err != nil {
			fmt.Println(err)
			return
		}
		grid.Status = -1
		cache.Put(key, grid)
		return
	case os.Args[1] == "count":
		var cnt int
		db.Model(&Trade{}).Where("side = ?", "sell").Count(&cnt)
		fmt.Printf("Sells:%d\n", cnt)
		return
	case os.Args[1] == "set":
		if len(os.Args) != 4 {
			help()
		}
		key := os.Args[2]

		d := ToInt(os.Args[3])
		cache.Put(key, d)
		return
	case os.Args[1] == "get":
		if len(os.Args) != 3 {
			help()
		}
		key := os.Args[2]
		var d int
		err := cache.Get(key, &d)
		fmt.Println(d, err)
		return
	case os.Args[1] == "eval":
		if len(os.Args) != 8 {
			help()
		}
		if len(os.Args) < 6 {
			help()
		}
		symbol := os.Args[2]
		// buydepth := ToInt(os.Args[3])
		step := ToFloat(os.Args[4])
		size := ToFloat(os.Args[5])
		low := ToFloat(os.Args[6])
		high := ToFloat(os.Args[7])

		lowidx := int(low / step)
		highidx := int(high / step)
		total := 0.0
		amount := 0.0
		for i := lowidx; i <= highidx; i++ {
			amount = amount + size
			total = total + float64(i)*step*size
			if i > lowidx {
				startp := float64(i-1) * step
				endp := float64(i) * step
				profit := endp*size - startp*size
				fmt.Printf("%d-%d: %s - %s , 利润: %.4f,  利润率: %.3f%%,  累积需要资金: %.2f\n",
					i-1, i,
					fmt.Sprintf(priceConfig[symbol], startp),
					fmt.Sprintf(priceConfig[symbol], endp),
					profit,
					(profit*100.0)/(startp*size),
					total,
				)

			}

		}

		fmt.Printf("总共需要资金: %.2f 单步资金: %.2f 最大持币：%.2f  最大持币均价: %.4f  最大浮亏:%.2f\n", total, float64(highidx)*step*size, amount, total/amount, amount*low-total)
		return
	case os.Args[1] == "account":
		showAccount()
		return
	case os.Args[1] == "order": // 手工下单
		if len(os.Args) != 6 {
			help()
		}
		symbol := os.Args[2]
		direction := os.Args[3]
		price := os.Args[4]
		size := os.Args[5]
		oid := postOrder(symbol, direction, price, size)
		fmt.Printf("返回: %s\n", oid)
		return
	case os.Args[1] == "grid": // 显示网格数据
		var grid Grid
		if len(os.Args) != 3 {
			help()
		}
		key := os.Args[2]
		if err := cache.Get(key, &grid); err != nil {
			fmt.Println("没有对应的网格数据:", err)
			return
		}
		fmt.Printf("索引:%d 订单ID:%s 网格状态:%d\n", grid.Index, grid.Orderid, grid.Status)
		return
	case os.Args[1] == "reverse": // 显示反向索引数据
		var key string
		if len(os.Args) != 3 {
			help()
		}
		oid := os.Args[2]
		if err := reverse.Get(oid, &key); err != nil {
			fmt.Println("没有对应的反向索引数据:", err)
			return
		}
		fmt.Printf("订单ID:%s => 网格key:%s\n", oid, key)
		return
	case os.Args[1] == "query": // 查询单个订单状态
		if len(os.Args) != 4 {
			help()
		}
		symbol := os.Args[2]
		oid := os.Args[3]
		r, err := okexCli.GetSpotOrdersById(symbol, oid)
		if err != nil {
			fmt.Println("获取订单信息失败:", err)
			return
		}
		printOrder(*r)
		return
	case os.Args[1] == "cancel": // 查询单个订单状态
		if len(os.Args) != 4 {
			help()
		}
		symbol := os.Args[2]
		oid := os.Args[3]
		/*
			r, err := okexCli.PostSpotCancelOrders(symbol, oid)
			if err != nil {
				fmt.Println("取消订单信息失败:", err)
				return
			}
			fmt.Println((*r)["ordId"], (*r)["sCode"])
		*/
		fmt.Println(cancelOrder(symbol, oid))
		// printOrder(*r)
		return
	case os.Args[1] == "list": // 显示所有已完成订单
		if len(os.Args) < 3 {
			help()
		}
		symbol := os.Args[2]
		// paras := okex.NewParams()
		stat := "filled"
		if len(os.Args) >= 4 {
			stat = os.Args[3]
		}
		f, err := okexCli.GetSpotOrders(stat, symbol, nil) // 最大100个单啊，注意是否有坑 "cancelled"
		if err != nil {
			fmt.Printf("获取%s已完成订单信息错误:%s\n", symbol, err.Error())
			return
		}
		code := (*f)["code"]
		if code != "0" {
			fmt.Printf("获取%s已完成订单信息错误:%s %s\n", symbol, code, (*f)["msg"])
			return
		}
		filled := (*f)["data"].([]interface{})
		// 打印每个已完成订单
		for _, recx := range filled {
			rec := recx.(map[string]interface{})
			printOrder(rec)
		}
		return
	case os.Args[1] == "run":
		if len(os.Args) < 8 {
			help()
		}
		symbol := os.Args[2]
		buydepth := ToInt(os.Args[3])
		step := os.Args[4]
		size := os.Args[5]
		minPrice = ToFloat(os.Args[6])
		maxPrice = ToFloat(os.Args[7])
		if minPrice <= 0.0 || maxPrice <= 0.0 || maxPrice < minPrice {
			help()
		}
		stepf := ToFloat(step)
		sizef := ToFloat(size)
		highidx := int(maxPrice / stepf)
		minBalance = float64(highidx) * stepf * sizef
		currentSymbol = symbol
		segs := strings.Split(currentSymbol, "-")
		motherCurrency = strings.ToUpper(segs[1])

		fmt.Println("启动网格程序...")
		runDynamicGrid(symbol, buydepth, step, size)
		fmt.Println("等待网格程序完成...")
		select {
		case <-gridTask.StopChan():
			fmt.Println("网格程序已终止运行。")
		}
		return
	}

}
