### gost 2.4 修改版，增加环境变量，用于openshift v3 c2i 方式部署

##### 环境变量
```
	strMode := os.Getenv("GS_MODE") //http2 tls wss http ws
	strUser := os.Getenv("GS_USER") //""
	strPass := os.Getenv("GS_PASS") //""
	strHost := os.Getenv("GS_HOST") //""
	strPort := os.Getenv("GS_PORT") //PORT
	等效:  -L=GS_MODE://GS_USER:GS_PASS@GS_HOST:GS_PORT
```
例如：
  GS_MODE http2
  GS_USER myuser
  GS_PASS mypass
  GS_PORT 8080
等效：
  -L=http2://myuser:mypass@:8080

##### 使用说明
1 GS_MODE 和 GS_PORT 都不为空时，且无-F参数时，启用环境变量模式
2 GS_USER、GS_PASS及GS_HOST 三项可空
3 启用环境变量模式时，运行./gost, 虽然没有输入任何命令行参数，已实现了:
  -L=http2://myuser:mypass@:8080

##### 部署说明
参看：https://github.com/amsokol/openshift-golang-template
注意：现该模版不支持命令行参数，才有了此环境变量版gost

thanks:
	https://github.com/ginuerzh/gost
	https://github.com/amsokol/openshift-golang-template

	