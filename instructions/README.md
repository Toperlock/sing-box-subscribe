# sing-box-subscribe

Generate the `config.json` used by sing-box based on the configuration template. This is mainly used to add subscription nodes to the config for those using the `clash_mode` configuration.

It is not suitable for people who are completely unfamiliar with the sing-box configuration file. At the very least, you should know about outbound, DNS server, DNS rules, and routing rules. It's best to understand clash's grouping method.

Please refer to: [http://sing-box.sagernet.org/configuration](http://sing-box.sagernet.org/configuration/).

**The SSR protocol script is not parsed by default. If the subscription link contains the SSR protocol, an error will be reported!!!**

**The upper limit of the vecel server's processing time is 10 seconds. If the clash file is too large, it will fail due to processing timeout!!!**

## Feature

**sing-box web parser**

Use the website you built to achieve real-time configuration updates, which can serve as the remote link of sing-box

For example, the website I built [https://sing-box-subscribe.vercel.app](https://sing-box-subscribe.vercel.app), add `/config/URL_LINK` after the website, here` URL_LINK` refers to the subscription link

```
https://xxxxxxx.vercel.app/config/https://xxxxxxsubscribe?token=123456&file=https://github.com/Toperlock/sing-box-subscribe/raw/main/config_template/config_template_groups_rule_set_tun.json
```

### 2024.2.16 Update: Support adding `emoji`, `tag`, `prefix`, `ua`, `file`, `eps` , `enn` parameters after the link. Use `&` to connect multiple parameters. The usage is the same as the parameters in `providers.json`

`/config/URL_LINK&emoji=1&prefix=♥&ua=v2rayng&eps=vmess,hy2&enn=网站,剩余流量&file=https://xxxxxxxxx.json`

The above example shows: enable emoji, add ♥ before the node name, use v2rayng user agent, and use `https://xxxxxxxxx.json` as the generated sing-box configuration template

Example: https://sing-box-subscribe.vercel.app/config/https://gist.githubusercontent.com/Toperlock/b1ca381c32820e8c79669cbbd85b68ac/raw/dafae92fbe48ff36dae6e5172caa1cfd7914cda4/gistfile1.txt&file=https://github.com/Toperlock/sing-box-subscribe/raw/main/config_template/config_template_groups_rule_set_tun.json

### 2023.11.04 Update: Two sub links can be processed, the format is: `/config/URL encoding`, `emoji`, `tag`, `prefix`, `UA` parameters cannot be written (supports 3 sub links by 2024.1.1)

Use `|` to connect the two sub links and then [URL encode](https://www.urlencoder.org/) and put them after `config/`, as shown in the figure:

<div align="left">
  <img src="https://github.com/Toperlock/sing-box-subscribe/assets/86833913/5ed8e9de-3296-4dfc-ad65-2e181017829e" alt="how-to-use" width="50%" />
</div>

Example: https://sing-box-subscribe.vercel.app/config/https%3A%2F%2Fgist.githubusercontent.com%2FToperlock%2Fb1ca381c32820e8c79669cbbd85b68ac%2Fraw%2Fdafae92fbe48ff36dae6e5172caa1cfd7914cda4%2Fgistfile1.txt%7Chttps%3A%2F%2Fgist.githubusercontent.com%2FToperlock%2Ffa2fdc5f827ff7d288c23d568db75412%2Fraw%2F6c3b725da347f57b0021b806dfca5f51e1660746%2F1.yaml

### 2023.11.10 Update: The `file` parameter can be simplified and written as a number `1`, `2` represents the use of the template serial number provided in the github repository

Example: https://sing-box-subscribe.vercel.app/config/https://gist.githubusercontent.com/Toperlock/b1ca381c32820e8c79669cbbd85b68ac/raw/dafae92fbe48ff36dae6e5172caa1cfd7914cda4/gistfile1.txt&file=2

### Demo video

|Web parsing subscription link(v2/clash/sing-box)|
|-----------------------------|
|<video controls width="250" src="https://github.com/Toperlock/sing-box-subscribe/assets/86833913/a583c443-0c7b-454e-aaf2-f0a7159b276a"></video>|

## Catalog

[Operation video](https://github.com/Toperlock/sing-box-subscribe/blob/main/instructions/README.md#-demonstration-video)

[Parameter meaning](https://github.com/Toperlock/sing-box-subscribe/tree/main/instructions#providersjson-file)

[Detailed template explanation](https://github.com/Toperlock/sing-box-subscribe/tree/main/instructions#config-template-files)

[Run sing-box on Windows](https://github.com/Toperlock/sing-box-subscribe/tree/main/instructions#windows-sing-box-usage)

## Supported Protocols

|  Protocol | V2 Sub | Clash Sub | Standard URI Format | SingBox Format |
|  :----  | :----: | :----: | :----: | :----: |
| http  | ✅ | ✅ | ✅ | ✅ |
| socks5  | ✅ | ✅ | ✅ | ✅ |
| shadowsocks  | ✅ | ✅ | ✅ | ✅ |
| shadowsocksR  | ✅ | ✅ | ✅ | singbox doesn't support this by default |
| vmess  | ✅ | ✅ | ✅ | ✅ |
| trojan  | ✅ | ✅ | ✅ | ✅ |
| vless  | ✅ | ✅ | ✅ | ✅ |
| tuic  | ✅ | ✅ | ✅ | ✅ |
| hysteria  | ✅ | ✅ | ✅ | ✅ |
| hysteria2  | ✅ | ✅ | ✅ | ✅ |
| wireguard  | ✅ | ✅ | ✅ | ✅ |

~Parsing of clash subscriptions is not supported~ Only parsing of the checked protocol sharing links in( **v2 or clash subscription format**) has been implemented for now. You can write your own protocol parsers, for example, `vless.py` (the filename must match the protocol name), and place it in the `parsers` directory. The `vless.py` file must include a `parse` function.

**This script is for personal use. I use [yacd](https://yacd.metacubex.one) (For ios please use http://yacd.metacubex.one) to manage node switching (outbound types `urltest` and `selector`) and distribute traffic like in clash, which is very convenient. If you have similar needs, you can try it. If you have any new functional requirements or any errors when using the script, please submit an issue and do not harass sing-box.**.

**Scripts can be deployed to run on a web page using a vercel server, or you can download the project source code and run it locally. Please use your own deployed website to generate the sing-box configuration.**

# I. Server deployment

## Getting Started

1. Click the fork button on the top right corner of this project to fork this project to your own repository;
2. Click the button on the right to start deployment:
   [![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new), and log in directly with your Github account; [Please see the detailed tutorial](../docs/vercel-en.md#how-to-create-a-new-project).
3. Once deployed, you can start using it;
4. (Optional) [Bind a custom domain name](https://vercel.com/docs/concepts/projects/domains/add-a-domain): Vercel's assigned domain DNS is polluted in some zones, bind a custom domain name to connect directly.

### Turn on automatic updates

> If you encounter an Upstream Sync execution error, please manually click Sync Fork once!

After you have forked the project, due to Github's limitations, you need to manually go to the Actions page of the project you have forked to enable Workflows and enable Upstream Sync Action, which will turn on the hourly auto-updates:

![AutoUpdate](https://github.com/Toperlock/ChatGPT-Next-Web/raw/main/docs/images/enable-actions.jpg)

![Enable Automatic Updates](https://github.com/Toperlock/ChatGPT-Next-Web/raw/main/docs/images/enable-actions-sync.jpg)

### Manual update code

If you want to enable manual updates right away, check out [Github's documentation](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/syncing-a-fork) for information on how to synchronize a forked project with your upstream code.

You can star/watch the project or follow the author to be notified of new features.

## Steps for page manipulation

[Sample website](https://sing-box-subscribe.vercel.app/). Open your deployed website, edit the contents of the `编辑服务器 TEMP_JSON_DATA` box on the right side, click `保存`, select the configuration template in the upper left corner, and click `生成配置文件`. 👉🏻[Parameter Fill View](https://github.com/Toperlock/sing-box-subscribe/tree/main/instructions#providersjson-file)

ios with the shortcut command to copy the content of the web page, or too much content to choose to download the file to solve the problem of the file suffix by yourself. 👉🏻[Shortcut Install](https://www.icloud.com/shortcuts/75fd371e0aa8438a89f715238a21ee68)

Android use chrome browser to open the webpage to generate the configuration file (please go to the browser Settings - Accessibility to reduce the webpage), long press the content, select it in full, share it to the code editor, check whether the editor shows the content is complete. 👉🏻[Editor Install](https://mt2.cn/download/)

**Note that after clicking Save, go to Generate Configuration File as soon as possible, otherwise the content you fill in will remain on the webpage, and other people can browse to it when they open the website. Can't think of a solution at the moment**

<div align="left">
  <img src="https://github.com/Toperlock/sing-box-subscribe/assets/86833913/f794806c-edfc-4951-a216-6e38646f3791" alt="how-to-use" width="50%" />
</div>

## 🎬 Demonstration video

|Web parsing sub link|Web parsing URI links|
|-----------------------------|-----------------------------|
|<video controls width="250" src="https://github.com/Toperlock/sing-box-subscribe/assets/86833913/9f8f1a70-58b1-4117-a650-f956d9249e43"></video>|<video controls width="250" src="https://github.com/Toperlock/sing-box-subscribe/assets/86833913/63e180ad-eead-433f-8ee8-73055dafbd56"></video>|

|Android Chrome page shrink|Web directly parse base64|
|-----------------------------|-----------------------------|
|<video controls width="250" src="https://github.com/Toperlock/sing-box-subscribe/assets/86833913/cb149206-307f-4de8-9968-9832dcf8268a"></video>|<video controls width="250" src="https://github.com/Toperlock/sing-box-subscribe/assets/86833913/0081f055-2cd4-46bb-a4a9-7aac7d5f93a5"></video>|

|Local parsing sub link|Local parsing URI links|
|-----------------------------|-----------------------------|
|<video controls width="250" src="https://github.com/Toperlock/sing-box-subscribe/assets/86833913/12da95a3-aae9-4ae4-ab88-774ed54f3217"></video>|<video controls width="250" src="https://github.com/Toperlock/sing-box-subscribe/assets/86833913/7e93568d-ece6-4cba-8dd0-bc5b5e64ade7"></video>|

# II. Local installation
### Install [Python](https://www.python.org/) version 3.10 or above on your PC. Make sure to add Python to your system environment variables (follow Google's installation steps).

<div align="left">
  <img src="https://github.com/Toperlock/sing-box-subscribe/assets/86833913/f387322b-a602-40df-b3b6-95561329f2f8" alt="install" width="60%" />
</div>

### In the terminal, input the following command to install dependencies (on Mac, replace `pip` with `pip3`):

```
pip install -r requirements.txt
```

<div align="left">
  <img src="https://github.com/Toperlock/sing-box-subscribe/assets/86833913/0fc03b49-4c57-4ef3-a4fc-044c1a108d75" alt="install" width="60%" />
</div>

### Download the `sing-box-subscribe` project and open the terminal to navigate to the project directory (you can directly type `cmd` in the file path).

<div align="left">
  <img src="https://github.com/Toperlock/sing-box-subscribe/assets/86833913/73f05ba8-105c-4f10-8e6c-16e27f26c084" alt="run" width="60%" />
</div>

### Put your subscription links in `providers.json`, edit `config_template_groups_tun.json` file and use the following command to run the script after editing the template:

```
python main.py
```

or you can directly select the template with the  `template_index`, `0` means the first template(no flask doesn't support)

```
python main.py --template_index=0
```

For Windows systems, it's recommended to add the commands to a batch program for execution.

Before using, make sure to edit the `providers.json` file and the `.json` template files in the `config_template` directory.

A lazy configuration `config_template_groups_rule_set_tun` file is included, which allows filtering nodes based on different categories:
* Implement `Openai` routing rules
* Implement `Youtube` routing rules
* Implement `Google` routing rules
* Implement `Github` routing rules
* Implement `Telegram` routing rules
* Implement `Twitter` routing rules
* Implement `Facebook` routing rules
* Implement `Instagram` routing rules
* Implement `Bilibili` routing rules
* Implement `Bahamut` routing rules
* Implement `Spotify` routing rules
* Implement `TikTok` routing rules
* Implement `Netflix` routing rules
* Implement `Disney+` routing rules
* Implement `Apple` routing rules
* Implement `Amazon` routing rules
* Implement `Microsoft` routing rules
* Implement `Game` routing rules
* Implement `Hbo` routing rules
* Implement `Prime Video` routing rules


# providers.json File
In this file, you can add subscription links and basic settings.
```json
{
    "subscribes":[
        {
            "url": "https://4gviet.com/api/v1/client/subscribe?token=xx",
            "tag": "airport1_tag", //You can keep the default without modification
            "enabled": true, //Enable conversion of this link
            "emoji": 1, //Add flag emoji
            "subgroup": "",
            "prefix": "", //Do not add node name prefix
            "ex-node-name": "网站|流量|过期", //Filter nodes containing keywords
            "User-Agent":"clashmeta" //Set browser UA
        },
        {
            "url": "https://5gtocdocao.com/api/v1/client/subscribe?token=xx",
            "tag": "airport2_tag", //You can keep the default without modification
            "enabled": false, //Disable conversion of this link
            "emoji": 0, //Do not add flag emoji
            "subgroup": "named", //Name the subscription link
            "prefix": "❤️node_name prefix - ", //Add node name prefix
            "User-Agent":"clashmeta" //Set browser UA
        }
    ],
    "auto_set_outbounds_dns":{
        "proxy": "",
        "direct": ""
    },
    "save_config_path": "./config.json",
    "auto_backup": false,
    "exclude_protocol": "ssr", //Not parsing ssr nodes!!!
    "config_template": "", //Customize the correct web page json configuration template link
    "Only-nodes": false //Output the complete sing-box configuration
}
```
- `url`: Required.

> Supports setting up a regular V2 subscription link (**content in base64 encoding**)

> Supports setting up a clash subscription link

> Supports setting up a sing-box subscription link

> Supports setting up a local file paths (**content as standard URI links or Clash field**)

    Local files with `.txt` suffix need to add single node share links one per line in the file, e.g. `ss://` at the beginning (non-subscription links).

    Local files with `.yaml` suffix, with the correct clash proxies fields filled in.

    Local files need to be saved on the same drive. Local path formats: `/Desktop/sing-box-subscribe/xx.txt` or relative path formats in the same folder as `main.py`: `./xx.txt`.

- `tag`: Required. Just keep the default.

> Fill in this tag in the config template to add this subscription. The "airport1_tag" here corresponds to "{机场1}" in the config template. Specific usage can be found in the config template section below.

<details>
      <summary>tag screenshot reference</summary>

<div align="left">
  <img src="https://github.com/Toperlock/sing-box-subscribe/assets/86833913/781c5bb7-c5c5-467e-a6ae-05ff44a19973" alt="download" width="65%" />
</div>

</details>

- `enabled`: Optional. **Set it to false, and the subscription will be ignored**.

- `emoji`: Optional. **Set it to false or 0, and the node name will not have a country flag emoji**.

- `subgroup`: Optional. Name the subscription link and generate an outbound.

- `prefix`: Optional. Set a custom prefix that will be added to the beginning of the node names. If not set, no prefix will be added.

- `ex-node-name`: Optional. Filter nodes containing keywords. Multiple keywords are separated by "|"

- `User-Agent`: Optional. You can customize UA, such as setting UA to "clash.meta" or "sing-box"

<details>
      <summary>prefix effect reference</summary>
  
![Snipaste_2023-05-02_12-53-27](https://user-images.githubusercontent.com/21310130/235582317-6bb3d0a6-916f-445f-999b-f17b3db41eea.png)

</details>

- `auto_set_outbounds_dns`: Optional.
> Includes `proxy` and `direct` settings.

> `proxy` and `direct` should be set to the `tag` of the `dns server` in the config template file.

> With this option set, the script will automatically adapt routing rules to DNS rules.

> DNS servers for outbound rules with `direct` setting in the routing rules will be set to the specified `direct` outbound.

> Outbound rules that need to be proxied in the routing rules will be set to the corresponding `proxy` outbound, and the script will automatically create a corresponding `dns server` for the proxy outbound, using the `dns server` specified in the `proxy` setting.

- `save_config_path`: Required. Set the path for the generated configuration file.

- `auto_backup`: Optional.
> When set to true, the script will rename the currently used sing-box configuration file to `original_filename.current_time.bak` for backup purposes, in case an incorrect configuration file is generated and needs to be restored.

- `exclude_protocol`: Optional.
> Set the protocols to exclude, separated by commas, e.g., ssr, vmess.

> Sharing links using protocols in this setting will be ignored.

> The sing-box release program does not support ssr (needs additional parameters to build), so this setting might be useful.

- `config_template`：Optional. Enter a correct webpage json configuration template link to generate sing-box configuration from this template.

- `Only-nodes`: Optional.
> When it is set to true or 1, only the node information in sing-box format of the subscription link is output.

# config Template Files
The script will search for JSON template files in the `config_template` directory, and you can select which template file to use when the script runs.

For example, if there are `tun.json` and `socks.json` template files in the directory.

![Snipaste_2023-03-24_22-16-49](https://user-images.githubusercontent.com/21310130/227548643-ffbf3825-9304-4df7-9b65-82a935227aef.png)

The script does not validate the correctness of the template files. If the template file is incorrect, errors will occur, and the script won't run.

The template files are similar to sing-box configs, but with some new parameters like `{all}`, `{机场tag}` (translated as `{airport_tag}`), `filter`, which only work with `clash_mode` in `urltest` and `selector` outbounds.
```json
{
  "tag":"proxy",
  "type":"selector",
  "outbounds":[
    "auto",
    "{all}"//All nodes of all subscriptions are added to the location of this tag
  ],
  "filter":[
    //This filter will remove nodes containing ˣ² in airport1_tag
    {"action":"exclude","keywords":["ˣ²"],"for":["机场1"]}
  ]
},
{
  "tag":"netflix",
  "type":"selector",
  "outbounds":[
    "{机场1}",//Tag with the airport1_tag will be added to this tagged location
    "{机场2}"//Tag with the airport2_tag will be added to this tagged location
  ],
  "filter":[
    //If airport1_tag and airport2_tag have nodes with these names 'sg','新加坡','tw','台湾' they collectively form the netflix group
    {"action":"include","keywords":["sg|新加坡|tw|台湾"]},
    //The "for" is set to airport1_tag, which means that this rule only works on airport1_tag
    {"action":"exclude","keywords":["ˣ²"],"for":["机场1"]}
    //This filter will remove nodes containing ˣ² in airport1_tag
  ]
}
```
- `{all}`: Represents all nodes in all subscriptions. The script will add all nodes to the `outbounds` with this identifier.

- `{机场tag}` (translated as `{airport_tag}`): The airport `tag` set in `providers.json` can be used here, representing all nodes in this subscription.

- `filter`: Optional. Node filtering, an array object where you can add any number of rules, formatted as:
```json
"filter": [
    {"action": "include", "keywords": ["keyword1|keyword2"]},
    {"action": "exclude", "keywords": ["keyword1|keyword2"], "for": ["airport1_tag", "airport2_tag"]}
  ]
```
- **Keyword case-sensitive**

- `include`: Add the keywords to be retained, use '|' to connect multiple keywords. Nodes with names containing these keywords will be retained, and other nodes will be deleted.

- `exclude`: Add the keywords to be excluded, use '|' to connect multiple keywords. Nodes with names containing these keywords will be deleted, and other nodes will be retained.

- `for`: Optional. Set the airport `tag`, can be multiple. This rule will only apply to the specified airports, and other airports will ignore this rule.

Multiple rules will be executed in order.

# Windows sing-box Usage

1. Download the Windows client program [sing-box-windows-amd64.zip](https://github.com/SagerNet/sing-box/releases).
2. Create a `.bat` batch file with the content `start /min sing-box.exe run`.
3. Refer to the [client configuration](https://github.com/chika0801/sing-box-examples/blob/main/Tun/config_client_windows.json) example, modify as needed, and change the filename to **config.json**, then put the batch file in the same folder as **sing-box.exe**.
4. Right-click **sing-box.exe**, select Properties, go to Compatibility, and choose to run the program as an administrator.
5. Run the batch file, and in the User Account Control dialog that appears, choose Yes.

## Hide the cmd window that pops up when Windows runs sing-box

> Use WinSW to set sing-box.exe as a Windows service, [WinSW tutorial](https://github.com/winsw/winsw)

> XML configuration file modification
```xml
<service>
  <id>sing-box</id>
  <name>sing-box</name>
  <description>sing-box Service</description>
  <executable>./sing-box.exe</executable>
  <log mode="reset"></log>
  <arguments>run</arguments>
</service>
```
<details>
      <summary>Windows sing-box folder contents</summary>
 
<div align="left">
  <img src="https://github.com/Toperlock/sing-box-subscribe/assets/86833913/c6a815bf-b542-43c6-aeb6-84020586a1f1" alt="download" width="50%" />
</div>

</details>

## In non-graphical clients, operations without using tun

For example, if you use the kernel to run sing-box on Windows, delete the tun field in the inbounds:

```json
"inbounds": [
    {
      "type": "mixed",
      "listen": "127.0.0.1",
      "listen_port": 2080, //This port must be consistent with the windows proxy port
      "sniff": true,
      "set_system_proxy": true,
      "sniff_override_destination": false,
      "domain_strategy": "ipv4_only"
    }
  ]
```

<div align="left">
  <img src="https://github.com/Toperlock/sing-box-subscribe/assets/86833913/387f2077-b8b6-42ed-9658-361b28179db2" alt="download" width="50%" />
</div>

<details>
      <summary><b>Effect Reference</b></summary>

The specific effects depend on individual outbound and rule settings.

<div align="left">
  <img src="https://user-images.githubusercontent.com/21310130/227577941-01c80cfc-1cd9-4f95-a709-f5442a2a2058.png" alt="download" width="50%" />
  <img src="https://user-images.githubusercontent.com/21310130/227577968-6747c7aa-db61-4f6c-b7cc-e3802e34cc3d.png" alt="download" width="50%" />
  <img src="https://github.com/Toperlock/sing-box-subscribe/assets/86833913/955968d7-98e7-4bd2-a582-02576877dba1" alt="download" width="50%" />
  <img src="https://github.com/Toperlock/sing-box-subscribe/assets/86833913/9e7c35ff-c6c4-46c4-a74b-624ff72c17ea" alt="download" width="50%" />
</div>

</details>

# Thanks
- [xream](https://github.com/xream)
- [sing-box](https://github.com/SagerNet/sing-box)
- [yacd](https://github.com/haishanh/yacd)
- [clash](https://github.com/Dreamacro/clash)
- [sing-box-examples@chika0801](https://github.com/chika0801/sing-box-examples)

Some protocol parsing referenced from [convert2clash](https://github.com/waited33/convert2clash).

Some clash2v2ray parsing referenced from [clash2base64](https://github.com/yuanyiwei/toys/blob/master/DEPRECATED/clash/clash2base64.py).

Some synchronization code referenced from [ChatGPT-Next-Web](https://github.com/Yidadaa/ChatGPT-Next-Web).

Thanks to @SayRad for the Vietnamese translation
