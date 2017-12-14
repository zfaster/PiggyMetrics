[云框架]基于Spring Cloud的微服务架构实例[PiggyMetrics](https://github.com/sqshq/PiggyMetrics)，点击查看[用户指南](https://github.com/cloudframeworks-springcloud/user-guide-springcloud)


本地运行步骤
1、右键服务edit configuration中 spring boot setting 中添加相关属性
export CONFIG_SERVICE_PASSWORD=root
export NOTIFICATION_SERVICE_PASSWORD=root
export STATISTICS_SERVICE_PASSWORD=root
export ACCOUNT_SERVICE_PASSWORD=root
export MONGODB_PASSWORD=root         ## 必填，其他变量可不设置
2、安装mongodb 和rabbitmq
3、运行mongo脚本init.sh
4、配置host 服务名指向地址
4、服务启动顺序 config-》register-》auth-》其他