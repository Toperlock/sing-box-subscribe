from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from urllib.parse import quote, urlparse, unquote
import json
import os
import sys
import subprocess
import tempfile
import shutil
import tempfile  # 导入 tempfile 模块
from datetime import datetime, timedelta

app = Flask(__name__, template_folder='../templates')  # 指定模板文件夹的路径
app.secret_key = 'sing-box'  # 替换为实际的密钥
data_json = {}
os.environ['TEMP_JSON_DATA'] = '{"subscribes":[{"url":"URL","tag":"tag_1","enabled":true,"emoji":1,"subgroup":"","prefix":"","User-Agent":"v2rayng"},{"url":"URL","tag":"tag_2","enabled":false,"emoji":0,"subgroup":"命名/named","prefix":"❤️","User-Agent":"clashmeta"}],"auto_set_outbounds_dns":{"proxy":"","direct":""},"save_config_path":"./config.json","auto_backup":false,"exclude_protocol":"ssr","config_template":"","Only-nodes":false}'
data_json['TEMP_JSON_DATA'] = '{"subscribes":[{"url":"URL","tag":"tag_1","enabled":true,"emoji":1,"subgroup":"","prefix":"","User-Agent":"v2rayng"},{"url":"URL","tag":"tag_2","enabled":false,"emoji":0,"subgroup":"命名/named","prefix":"❤️","User-Agent":"clashmeta"}],"auto_set_outbounds_dns":{"proxy":"","direct":""},"save_config_path":"./config.json","auto_backup":false,"exclude_protocol":"ssr","config_template":"","Only-nodes":false}'

# 获取系统默认的临时目录路径
TEMP_DIR = tempfile.gettempdir()

"""
# 存储配置文件的过期时间（10分钟）
config_expiry_time = None
"""

def cleanup_temp_config():
    global config_expiry_time, config_file_path
    if config_expiry_time and datetime.now() > config_expiry_time:
        shutil.rmtree(os.path.dirname(config_file_path), ignore_errors=True)
        config_expiry_time = None
        config_file_path = None

# 获取临时 JSON 数据
def get_temp_json_data():
    temp_json_data = os.environ.get('TEMP_JSON_DATA')
    if temp_json_data:
        return json.loads(temp_json_data)
    return {}

# 获取config_template目录下的模板文件列表
def get_template_list():
    template_list = []
    config_template_dir = 'config_template'  # 配置模板文件夹路径
    template_files = os.listdir(config_template_dir)  # 获取文件夹中的所有文件
    template_list = [os.path.splitext(file)[0] for file in template_files if file.endswith('.json')]  # 移除扩展名并过滤出以.json结尾的文件
    template_list.sort()  # 对文件名进行排序
    return template_list

# 读取providers.json文件的内容，如果有临时 JSON 数据则使用它
def read_providers_json():
    temp_json_data = get_temp_json_data()
    if temp_json_data :
        return temp_json_data
    with open('providers.json', 'r', encoding='utf-8') as json_file:
        providers_data = json.load(json_file)
    return providers_data

# 写入providers.json文件的内容，如果有临时 JSON 数据则不写入
def write_providers_json(data):
    temp_json_data = get_temp_json_data()
    if not temp_json_data:
        with open('providers.json', 'w', encoding='utf-8') as json_file:
            json.dump(data, json_file, indent=4, ensure_ascii=False)

@app.route('/')
def index():
    template_list = get_template_list()
    template_options = [f"{index + 1}、{template}" for index, template in enumerate(template_list)]
    providers_data = read_providers_json()
    temp_json_data = get_temp_json_data()
    return render_template('index.html', template_options=template_options, providers_data=json.dumps(providers_data, indent=4, ensure_ascii=False), temp_json_data=json.dumps(temp_json_data, indent=4, ensure_ascii=False))

@app.route('/update_providers', methods=['POST'])
def update_providers():
    try:
        # 获取表单提交的数据
        new_providers_data = json.loads(request.form.get('providers_data'))
        # 更新providers.json文件
        write_providers_json(new_providers_data)
        flash('Providers.json文件已更新', 'success')
        flash('File Providers.json đã được cập nhật', 'Thành công^^')
    except Exception as e:
        flash(f'更新Providers.json文件时出错；{str(e)}', 'error')
        flash(f'Có lỗi khi cập nhật file Providers.json; {str(e)}', 'Lỗi!!!')
    return redirect(url_for('index'))

@app.route('/edit_temp_json', methods=['GET', 'POST'])
def edit_temp_json():
    if request.method == 'POST':
        try:
            new_temp_json_data = request.form.get('temp_json_data')
            print (new_temp_json_data)
            if new_temp_json_data:
                temp_json_data = json.loads(new_temp_json_data)
                os.environ['TEMP_JSON_DATA'] = json.dumps(temp_json_data, indent=4, ensure_ascii=False)
                #flash('TEMP_JSON_DATA 已更新', 'success')
                #flash('TEMP_JSON_DATA đã được cập nhật', 'Thành công^^')
                return jsonify({'status': 'success'})  # 返回成功状态
            else:
                return jsonify({'status': 'error', 'message': 'TEMP_JSON_DATA 不能为空(không thể trống)'}, content_type='application/json; charset=utf-8')  # 返回错误状态和消息
        except Exception as e:
            flash('TEMP_JSON_DATA 不能为空', 'error')
            flash('TEMP_JSON_DATA 格式出错：注意订阅链接末尾不要有换行，要在双引号""里面！！！')
            flash('TEMP_JSON_DATA không thể trống', 'Lỗi!!!')
            flash('Lỗi định dạng TEMP_JSON_DATA: lưu ý rằng liên kết đăng ký không được có ký tự xuống dòng ở cuối, mà phải nằm trong dấu ngoặc kép ""')
            flash('TEMP_JSON_DATA cannot be empty', 'error')
            flash(f'Error updating TEMP_JSON_DATA: note that the subscription link should not have a newline at the end, but should be inside double quotes ""')
            return jsonify({'status': 'error', 'message': str(e)})  # 返回错误状态和消息

@app.route('/config/<path:url>', methods=['GET'])
def config(url):
    user_agent = request.headers.get('User-Agent') or ""
    rua_values = os.getenv('RUA')
    if rua_values and any(rua_value in user_agent for rua_value in rua_values.split(',')):
        return Response(json.dumps({'status': 'error', 'message': 'block'}, indent=4, ensure_ascii=False),
                        content_type='application/json; charset=utf-8', status=403)
    substrings = os.getenv('STR')
    if substrings and any(substring in url for substring in substrings.split(',')):
        return Response(json.dumps({'status': 'error', 'message_CN': '填写参数不符合规范'}, indent=4, ensure_ascii=False),
                        content_type='application/json; charset=utf-8', status=403)
    # temp_json_data_str = os.environ['TEMP_JSON_DATA']
    # temp_json_data = json.loads(temp_json_data_str)
    temp_json_data = json.loads('{"subscribes":[{"url":"URL","tag":"tag_1","enabled":true,"emoji":1,"subgroup":"","prefix":"","ex-node-name": "","User-Agent":"v2rayng"},{"url":"URL","tag":"tag_2","enabled":false,"emoji":1,"subgroup":"","prefix":"","ex-node-name": "","User-Agent":"v2rayng"},{"url":"URL","tag":"tag_3","enabled":false,"emoji":1,"subgroup":"","prefix":"","ex-node-name": "","User-Agent":"v2rayng"}],"auto_set_outbounds_dns":{"proxy":"","direct":""},"save_config_path":"./config.json","auto_backup":false,"exclude_protocol":"ssr","config_template":"","Only-nodes":false}')
    subscribe = temp_json_data['subscribes'][0]
    subscribe2 = temp_json_data['subscribes'][1]
    subscribe3 = temp_json_data['subscribes'][2]
    query_string = request.query_string.decode('utf-8')
    #print (f"query_string: {query_string}")
    #print (f"url: {url}")
    #encoded_url = quote(url, safe=':/')  # 对 url 进行编码
    encoded_url = unquote(url)
    #print (f"encoded_url: {encoded_url}")
    index_of_colon = encoded_url.find(":")

    if not query_string:
        if any(substring in encoded_url for substring in ['&emoji=', '&file=', '&eps=', '&enn=']):
            if '|' in encoded_url:
                param = urlparse(encoded_url.rsplit('&', 1)[-1])
            else:
                param = urlparse(encoded_url.split('&', 1)[-1])
            request.args = dict(item.split('=') for item in param.path.split('&'))
            if request.args.get('prefix'):
                request.args['prefix'] = unquote(request.args['prefix'])
            if request.args.get('eps'):
                request.args['eps'] = unquote(request.args['eps'])
            if request.args.get('enn'):
                request.args['enn'] = unquote(request.args['enn'])
            if request.args.get('file'):
                index = request.args.get('file').find(":")
                next_index = index + 2
                if index != -1:
                    if next_index < len(request.args['file']) and request.args['file'][next_index] != "/":
                        request.args['file'] = request.args['file'][:next_index-1] + "/" + request.args['file'][next_index-1:]
    else:
        if any(substring in query_string for substring in ['&emoji=', '&file=', '&eps=', '&enn=']):
            param = urlparse(query_string.split('&', 1)[-1])
            request.args = dict(item.split('=') for item in param.path.split('&'))
            if request.args.get('prefix'):
                request.args['prefix'] = unquote(request.args['prefix'])
            if request.args.get('eps'):
                request.args['eps'] = unquote(request.args['eps'])
            if request.args.get('enn'):
                request.args['enn'] = unquote(request.args['enn'])
            if request.args.get('file'):
                index = request.args.get('file').find(":")
                next_index = index + 2
                if index != -1:
                    if next_index < len(request.args['file']) and request.args['file'][next_index] != "/":
                        request.args['file'] = request.args['file'][:next_index-1] + "/" + request.args['file'][next_index-1:]
            elif 'file=' in query_string:
                index = query_string.find("file=")
                request.args['file'] = query_string.split('file=')[-1].split('&', 1)[0]
    #print (f"request.args: {request.args}")

    if index_of_colon != -1:
        # 检查 ":" 后面是否只有一个 "/"，如果是，添加一个额外的 "/"
        next_char_index = index_of_colon + 2
        if next_char_index < len(encoded_url) and encoded_url[next_char_index] != "/":
            encoded_url = encoded_url[:next_char_index-1] + "/" + encoded_url[next_char_index-1:]
    if query_string:
        full_url = f"{encoded_url}?{query_string}"
    else:
        if any(substring in encoded_url for substring in ['&emoji=', '&file=']):
            full_url = f"{encoded_url.split('&')[0]}"
        else:
            full_url = f"{encoded_url}"

    #print (f"full_url: {full_url}")

    emoji_param = request.args.get('emoji', '')
    file_param = request.args.get('file', '')
    tag_param = request.args.get('tag', '')
    ua_param = request.args.get('ua', '')
    UA_param = request.args.get('UA', '')
    pre_param = request.args.get('prefix', '')
    eps_param = request.args.get('eps', '')
    enn_param = request.args.get('enn', '')
    gh_proxy_param = request.args.get('gh', '')

    # 构建要删除的字符串列表
    params_to_remove = [
        f'&prefix={quote(pre_param)}',
        f'&ua={ua_param}',
        f'&UA={UA_param}',
        f'&file={file_param}',
        f'file={file_param}',
        f'&emoji={emoji_param}',
        f'&tag={tag_param}',
        f'&gh={gh_proxy_param}',
        f'&eps={quote(eps_param)}',
        f'&enn={quote(enn_param)}'
    ]
    # 从url中删除这些字符串
    full_url = full_url.replace(',', '%2C')
    for param in params_to_remove:
        if param in full_url:
            full_url = full_url.replace(param, '')
    if request.args.get('url'):
        full_url = full_url
    else:
        full_url = unquote(full_url)
    if '/api/v4/projects/' in full_url:
        parts = full_url.split('/api/v4/projects/')
        full_url = parts[0] + '/api/v4/projects/' + parts[1].replace('/', '%2F', 1)
    print (full_url)
    url_parts = full_url.split('|')
    if len(url_parts) > 1:
        subscribe['url'] = full_url.split('url=', 1)[-1].split('|')[0] if full_url.startswith('url') else full_url.split('|')[0]
        subscribe['ex-node-name'] = enn_param
        subscribe2['url'] = full_url.split('url=', 1)[-1].split('|')[1] if full_url.startswith('url') else full_url.split('|')[1]
        subscribe2['emoji'] = 1
        subscribe2['enabled'] = True
        subscribe2['subgroup'] = ''
        subscribe2['prefix'] = ''
        subscribe2['ex-node-name'] = enn_param
        subscribe2['User-Agent'] = 'v2rayng'
        if len(url_parts) == 3:
            subscribe3['url'] = full_url.split('url=', 1)[-1].split('|')[2] if full_url.startswith('url') else full_url.split('|')[2]
            subscribe3['enabled'] = True
            subscribe3['ex-node-name'] = enn_param
    if len(url_parts) == 1:
        subscribe['url'] = full_url.split('url=', 1)[-1] if full_url.startswith('url') else full_url
        subscribe['emoji'] = int(emoji_param) if emoji_param.isdigit() else subscribe.get('emoji', '')
        subscribe['tag'] = tag_param if tag_param else subscribe.get('tag', '')
        subscribe['prefix'] = pre_param if pre_param else subscribe.get('prefix', '')
        subscribe['ex-node-name'] = enn_param
        subscribe['User-Agent'] = ua_param if ua_param else 'v2rayng'
    temp_json_data['exclude_protocol'] = eps_param if eps_param else temp_json_data.get('exclude_protocol', '')
    temp_json_data['config_template'] = unquote(file_param) if file_param else temp_json_data.get('config_template', '')
    #print (f"Custom Page for {url} with link={full_url}, emoji={emoji_param}, file={file_param}, tag={tag_param}, UA={ua_param}, prefix={pre_param}")
    #page_content = f"生成的页面内容：{full_url}"
    #return page_content
    try:
        selected_template_index = '0'
        selected_gh_proxy_index = ''
        if file_param.isdigit():
            temp_json_data['config_template'] = ''
            selected_template_index = str(int(file_param) - 1)
        if gh_proxy_param.isdigit():
            selected_gh_proxy_index = str(int(gh_proxy_param) - 1)
        temp_json_data = json.dumps(json.dumps(temp_json_data, indent=4, ensure_ascii=False), indent=4, ensure_ascii=False)
        subprocess.check_call([sys.executable, 'main.py', '--template_index', selected_template_index, '--temp_json_data', temp_json_data, '--gh_proxy_index', selected_gh_proxy_index])
        CONFIG_FILE_NAME = json.loads(os.environ['TEMP_JSON_DATA']).get("save_config_path", "config.json")
        if CONFIG_FILE_NAME.startswith("./"):
            CONFIG_FILE_NAME = CONFIG_FILE_NAME[2:]
        # 设置配置文件的完整路径
        config_file_path = os.path.join('/tmp/', CONFIG_FILE_NAME) 
        if not os.path.exists(config_file_path):
            config_file_path = CONFIG_FILE_NAME  # 使用相对于当前工作目录的路径 
        os.environ['TEMP_JSON_DATA'] = json.dumps(json.loads(data_json['TEMP_JSON_DATA']), indent=4, ensure_ascii=False)
        # 读取配置文件内容
        with open(config_file_path, 'r', encoding='utf-8') as config_file:
            config_content = config_file.read()
            if config_content:
                flash('配置文件生成成功', 'success')
                flash('Tạo file cấu hình thành công', 'Thành công^^')
        config_data = json.loads(config_content)
        return Response(config_content, content_type='text/plain; charset=utf-8')
    except subprocess.CalledProcessError as e:
        os.environ['TEMP_JSON_DATA'] = json.dumps(json.loads(data_json['TEMP_JSON_DATA']), indent=4, ensure_ascii=False)
        return Response(json.dumps({'status': 'error'}, indent=4,ensure_ascii=False), content_type='application/json; charset=utf-8', status=500)
        #return jsonify({'status': 'error', 'message': str(e)}) 
    except Exception as e:
        #flash(f'Error occurred while generating the configuration file: {str(e)}', 'error')
        return Response(json.dumps({'status': 'error', 'message_CN': '认真看刚刚的网页说明、github写的reademe文件;', 'message_VN': 'Quá thời gian phân tích đăng ký: Vui lòng kiểm tra xem liên kết đăng ký có chính xác không hoặc vui lòng chuyển sang "nogroupstemplate" và thử lại; Vui lòng không chỉnh sửa giá trị "tag", trừ khi bạn hiểu nó làm gì;', 'message_EN': 'Subscription parsing timeout: Please check if the subscription link is correct or please change to "no_groups_template" and try again; Please do not modify the "tag" value unless you understand what it does;'}, indent=4,ensure_ascii=False), content_type='application/json; charset=utf-8', status=500)

@app.route('/generate_config', methods=['POST'])
def generate_config():
    try:
        selected_template_index = request.form.get('template_index')
        if not selected_template_index:
            flash('请选择一个配置模板', 'error')
            flash('Vui lòng chọn một mẫu cấu hình', 'Lỗi!!!')
            return redirect(url_for('index'))
        temp_json_data = json.dumps(os.environ['TEMP_JSON_DATA'], indent=4, ensure_ascii=False)
        # 修改这里：执行main.py并传递模板序号作为命令行参数，如果未指定，则传递空字符串
        subprocess.check_call([sys.executable, 'main.py', '--template_index', selected_template_index, '--temp_json_data', temp_json_data])
        CONFIG_FILE_NAME = json.loads(os.environ['TEMP_JSON_DATA']).get("save_config_path", "config.json")
        if CONFIG_FILE_NAME.startswith("./"):
            CONFIG_FILE_NAME = CONFIG_FILE_NAME[2:]
        # 设置配置文件的完整路径
        config_file_path = os.path.join('/tmp/', CONFIG_FILE_NAME) 
        if not os.path.exists(config_file_path):
            config_file_path = CONFIG_FILE_NAME  # 使用相对于当前工作目录的路径 
        os.environ['TEMP_JSON_DATA'] = json.dumps(json.loads(data_json['TEMP_JSON_DATA']), indent=4, ensure_ascii=False)
        # 读取配置文件内容
        with open(config_file_path, 'r', encoding='utf-8') as config_file:
            config_content = config_file.read()
            if config_content:
                flash('配置文件生成成功', 'success')
                flash('Tạo file cấu hình thành công', 'Thành công^^')
        config_data = json.loads(config_content)
        return Response(config_content, content_type='text/plain; charset=utf-8')
    except subprocess.CalledProcessError as e:
        os.environ['TEMP_JSON_DATA'] = json.dumps(json.loads(data_json['TEMP_JSON_DATA']), indent=4, ensure_ascii=False)
        return Response(json.dumps({'status': 'error'}, indent=4,ensure_ascii=False), content_type='application/json; charset=utf-8', status=500)
    except Exception as e:
        #flash(f'Error occurred while generating the configuration file: {str(e)}', 'error')
        return Response(json.dumps({'status': 'error', 'message_CN': '认真看刚刚的网页说明、github写的reademe文件;', 'message_VN': 'Quá thời gian phân tích đăng ký: Vui lòng kiểm tra xem liên kết đăng ký có chính xác không hoặc vui lòng chuyển sang "nogroupstemplate" và thử lại; Vui lòng không chỉnh sửa giá trị "tag", trừ khi bạn hiểu nó làm gì;', 'message_EN': 'Subscription parsing timeout: Please check if the subscription link is correct or please change to "no_groups_template" and try again; Please do not modify the "tag" value unless you understand what it does;'}, indent=4,ensure_ascii=False), content_type='application/json; charset=utf-8', status=500)
    #return redirect(url_for('index'))

@app.route('/clear_temp_json_data', methods=['POST'])
def clear_temp_json_data():
    try:
        os.environ['TEMP_JSON_DATA'] = json.dumps({}, indent=4, ensure_ascii=False)
        flash('TEMP_JSON_DATA 已清空', 'success')
        flash('TEMP_JSON_DATA đã được làm trống', 'Thành công^^')
    except Exception as e:
        flash(f'清空 TEMP_JSON_DATA 时出错：{str(e)}', 'error')
        flash(f'Có lỗi khi làm trống TEMP_JSON_DATA: {str(e)}', 'Lỗi!!!')
    return jsonify({'status': 'success'})

"""
@app.route('/download_config', methods=['GET'])
def download_config():
    try:
        if config_file_path:
            # 清理临时配置文件
            #cleanup_temp_config()

            # 使用send_file发送文件
            return send_file(config_file_path, as_attachment=True)
        else:
            flash('配置文件不存在或已过期', 'error')
            flash('File cấu hình không tồn tại hoặc đã hết hạn', 'Lỗi!!!')
            return redirect(url_for('index'))
    except Exception as e:
        return str(e)  # 或者适当处理异常，例如返回一个错误页面
"""
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')