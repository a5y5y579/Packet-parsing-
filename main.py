import csv
import socket
import os

import dpkt
from dpkt.ethernet import Ethernet

# 定義CSV檔案中的欄位名稱
fields = ["編號", "資料長度", "來源MAC", "目的地MAC", "Eth類型", "時間戳記(ns)",
      "來源IP", "目的地IP", "來源端口", "目的地端口", "第三層協議", "第四層協議"]

# 初始化封包計數器
index = 0 

# 創建CSV檔案並寫入欄位名稱
with open('output.csv', 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(fields)

    # 資料夾路徑
    directory = r'C:\Users\owner\Desktop\use' 

    # 獲取所有 pcap 檔案
    file_list = [f for f in os.listdir(directory) if f.endswith('.pcap')] 

    # 遍歷列表中的每個檔案
    for file_name in file_list:

        # 讀取PCAP檔案
        with open(os.path.join(directory, file_name), 'rb') as f:
            pcap = dpkt.pcap.Reader(f)

            # 遍歷讀取到的數據
            for timestamp, buf in pcap: 

                index += 1
                data_len = len(buf)

                eth = Ethernet(buf)
                ip = eth.data if eth.type == dpkt.ethernet.ETH_TYPE_IP else None

                # 如果不是IP封包，跳過
                if ip is None:  
                    continue

                source_ip = socket.inet_ntoa(ip.src)
                dest_ip = socket.inet_ntoa(ip.dst)

                source_mac = eth.src.hex()
                dest_mac = eth.dst.hex()
                eth_type = eth.type

                if ip.p in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):

                    trans = ip.data
                    source_port = trans.sport
                    dest_port = trans.dport
                    layer3_protocol = ip.p
                    layer4_protocol = 'TCP' if ip.p == dpkt.ip.IP_PROTO_TCP else 'UDP'

                    writer.writerow([index, data_len, source_mac, dest_mac, eth_type, 
                                     timestamp*1e9, source_ip, dest_ip, source_port,
                                     dest_port, layer3_protocol, layer4_protocol])

                else:
                    continue   # 如果封包不是TCP或UDP，則跳過