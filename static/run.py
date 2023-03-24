import argparse
import json
import requests
import threading

# # 解析命令行参数
# parser = argparse.ArgumentParser()
# parser.add_argument("--urls", nargs="+", help="one or more website URLs to scan")
# args = parser.parse_args()

# 从JSON文件中读取指纹信息
with open("finger.json", "r", encoding='utf-8') as f:
    fingerprints = json.load(f)

# 定义指纹识别函数
def identify_cms(url):
    # 发送HTTP请求获取网页源代码，并根据指纹匹配规则来识别CMS信息
    response = requests.get(url)
    html = response.text

    for fingerprint in fingerprints:
        if fingerprint["location"] == "body":
            if fingerprint["method"] == "keyword":
                for keyword in fingerprint["keyword"]:
                    if keyword in html:
                        print(f"URL: {url}, CMS: {fingerprint['cms']}")
                        break
            elif fingerprint["method"] == "faviconhash":
                # 从HTML源代码中获取网站favicon的URL，并下载该文件并计算哈希值
                # 如果哈希值与指纹匹配，则说明网站使用该CMS
                pass # 此处省略代码
        elif fingerprint["location"] == "header":
            for keyword in fingerprint["keyword"]:
                if keyword.lower() in response.headers:
                    print(f"URL: {url}, CMS: {fingerprint['cms']}")
                    break

url = "https://oa.xyc.edu.cn"

identify_cms(url)

# # 创建多个线程进行指纹识别
# threads = []
# for url in args.urls:
#     thread = threading.Thread(target=identify_cms, args=(url,))
#     thread.start()
#     threads.append(thread)

# # 等待所有线程完成
# for thread in threads:
#     thread.join()
