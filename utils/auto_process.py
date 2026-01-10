import base64
import json
import socket
import re
import os
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# ================= 配置区域 =================
# 输入文件路径 (根据你的目录结构调整)
INPUT_FILE = '../subscribe/v2ray.txt'
# 输出文件路径 (覆盖原文件)
OUTPUT_FILE = '../subscribe/v2ray.txt'
# 测速超时时间 (秒)，超过这个时间连不上算超时
TIMEOUT = 4
# 并发线程数 (越高越快，但太高容易报错，推荐 50-100)
MAX_WORKERS = 50
# 是否输出 Base64 编码 (True: 输出一长串乱码供订阅; False: 输出明文一行一个)
# 建议 True，兼容性更好
EXPORT_BASE64 = True
# ===========================================

def decode_base64(data):
    """尝试解码 Base64，如果不是 Base64 则返回原字符串"""
    data = data.strip()
    # 补全 padding
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    try:
        return base64.b64decode(data).decode('utf-8')
    except:
        return data

def parse_node(link):
    """
    解析节点链接，提取 (ip, port)
    支持: vmess://, ss://, trojan://, vless:// (部分)
    """
    ip = None
    port = None
    
    try:
        if link.startswith('vmess://'):
            # vmess 协议通常是 base64 编码的 json
            b64_str = link[8:]
            try:
                info = json.loads(decode_base64(b64_str))
                ip = info.get('add')
                port = info.get('port')
            except:
                pass
                
        elif link.startswith('ss://'):
            # ss://base64(method:pass@ip:port)
            # 或者 ss://base64(method:pass)@ip:port
            try:
                if '@' in link:
                    # 新格式
                    parts = link.split('@')
                    netloc = parts[1].split('#')[0] # 去掉备注
                    if ':' in netloc:
                        ip, port = netloc.split(':')
                else:
                    # 旧格式全加密
                    decoded = decode_base64(link[5:].split('#')[0])
                    if '@' in decoded:
                        info = decoded.split('@')[1]
                        if ':' in info:
                            ip, port = info.split(':')
            except:
                pass

        elif link.startswith('trojan://') or link.startswith('vless://'):
            # trojan://password@ip:port
            try:
                parsed = urlparse(link)
                ip = parsed.hostname
                port = parsed.port
            except:
                pass
                
    except Exception as e:
        print(f"解析出错: {link[:20]}... {e}")

    return ip, port

def check_connect(link):
    """
    TCP 握手测试
    返回: (link, is_valid, latency_ms)
    """
    ip, port = parse_node(link)
    
    # 如果解析不出来 IP 端口，为了保险起见，先保留（或者你可以选择丢弃）
    # 这里选择：保留但标记为 -1 延迟
    if not ip or not port:
        return link, True, -1 

    try:
        port = int(port)
        start_time = time.time()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((ip, port))
        latency = int((time.time() - start_time) * 1000)
        return link, True, latency
    except:
        return link, False, 0

def main():
    print("🔨 破壁计划 - 节点处理脚本启动...")
    
    # 1. 读取文件
    if not os.path.exists(INPUT_FILE):
        print(f"❌ 错误: 找不到文件 {INPUT_FILE}")
        return

    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        content = f.read().strip()

    # 处理可能已经是 Base64 编码的文件
    decoded_content = decode_base64(content)
    
    # 按行分割，去除空行
    raw_nodes = [line.strip() for line in decoded_content.split('\n') if line.strip()]
    print(f"📥 原始读取节点数: {len(raw_nodes)}")

    # 2. 去重
    unique_nodes = list(set(raw_nodes))
    print(f"♻️ 去重后节点数: {len(unique_nodes)}")
    
    # 3. 测速与筛选
    print(f"🚀 开始 TCP 连通性测试 (并发: {MAX_WORKERS})...")
    valid_nodes = []
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = executor.map(check_connect, unique_nodes)
        
        for link, is_valid, latency in results:
            if is_valid:
                valid_nodes.append(link)
            """
            if latency == -1:
                    print(f"⚠️ 无法解析: {link[:30]}... (已保留)")
                else:
                    print(f"✅ 存活: {latency}ms")
            else:
                print(f"❌ 死亡: {link[:30]}... (已剔除)")
            """

    print(f"📊 最终可用节点数: {len(valid_nodes)}")

    # 4. 写入结果
    final_content = '\n'.join(valid_nodes)
    
    if EXPORT_BASE64:
        # 编码回 Base64，方便订阅软件识别
        final_content = base64.b64encode(final_content.encode('utf-8')).decode('utf-8')
        
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(final_content)
        
    print(f"💾 结果已保存至: {OUTPUT_FILE}")
    print("Stay Online. Stay Rebellious.")

if __name__ == '__main__':
    main()
