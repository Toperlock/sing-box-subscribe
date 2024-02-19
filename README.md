# 操作说明去看[英文文档](https://github.com/Toperlock/sing-box-subscribe/blob/main/instructions/README.md)，中文文档操作说明不再提供

# 免责声明：sing-box-subscribe.vercel.app域名目前已被其他人占用，与本项目无关。后果自负
![image](https://github.com/Toperlock/sing-box-subscribe/assets/86833913/f9af80bc-f1b7-45dd-a2eb-e26910069f21)

### 使用 `/config/URL` 添加参数符号已修改，从原来的 `/&` 改为 `&`。有问题请提issue，不要打扰 `sing-box`

### 请使用 `/config/URL` 时添加任何参数不要在第一个`&`，加上 `/`，我已经取消适配这种错误的写法

### sing-box 1.8.0+ 已发布，配置需要修改。已上传rule_set模板，并且默认生成最新配置文件适配 sing-box 1.8.0。~~用旧版singbox请选择`config_template_groups_tun.json`模板~~(已删除旧版配置模板)

### 使用 `/config/URL` 可以后面添加 `&file=2` 参数选择 `config_template_groups_v6_rule_set_tun` 模板。两条订阅的形式也可以后面加 `&file=2` 参数

### 根据已有的qx，surge，loon，clash规则列表自定义规则集[https://github.com/Toperlock/sing-box-geosite](https://github.com/Toperlock/sing-box-geosite)

### wechat规则集源文件写法：
```json
{
  "version": 1,
  "rules": [
    {
      "domain": [
        "dl.wechat.com",
        "sgfindershort.wechat.com",
        "sgilinkshort.wechat.com",
        "sglong.wechat.com",
        "sgminorshort.wechat.com",
        "sgquic.wechat.com",
        "sgshort.wechat.com",
        "tencentmap.wechat.com.com",
        "qlogo.cn",
        "qpic.cn",
        "servicewechat.com",
        "tenpay.com",
        "wechat.com",
        "wechatlegal.net",
        "wechatpay.com",
        "weixin.com",
        "weixin.qq.com",
        "weixinbridge.com",
        "weixinsxy.com",
        "wxapp.tc.qq.com"
      ]
    },
    {
      "domain_suffix": [
        ".qlogo.cn",
        ".qpic.cn",
        ".servicewechat.com",
        ".tenpay.com",
        ".wechat.com",
        ".wechatlegal.net",
        ".wechatpay.com",
        ".weixin.com",
        ".weixin.qq.com",
        ".weixinbridge.com",
        ".weixinsxy.com",
        ".wxapp.tc.qq.com"
      ]
    },
    {
      "ip_cidr": [
        "101.32.104.4/32",
        "101.32.104.41/32",
        "101.32.104.56/32",
        "101.32.118.25/32",
        "101.32.133.16/32",
        "101.32.133.209/32",
        "101.32.133.53/32",
        "129.226.107.244/32",
        "129.226.3.47/32",
        "162.62.163.63/32"
      ]
    }
  ]
}
```
配置文件添加源文件规则集：
```
{
  "tag": "geosite-wechat",
  "type": "remote",
  "format": "source",
  "url": "https://raw.githubusercontent.com/Toperlock/sing-box-geosite/main/wechat.json",
  "download_detour": "auto"
}
```

