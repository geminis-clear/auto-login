# -*- coding: utf-8 -*-
import webbrowser as web
from pymouse import PyMouse
from pykeyboard import PyKeyboard
import pyperclip
import time
from multiprocessing import Process, Queue
from scapy.sendrecv import sniff
from scapy.utils import wrpcap
import os
import dpkt
import re


class Cookieget:
    # 抓包
    def scapy_get_cookie(self, q):
        # os.system('ping sem.taobao.com')
        s = os.popen('ping sem.taobao.com').read()

        patt = '来自(.*?)的回复'
        res = re.findall(patt, s)
        # print(res[0])

        dpkt = sniff(count=100, filter='tcp and host {0}'.format(res[0]), timeout=30)
        wrpcap("demo.pcap", dpkt)
        q.put('抓包完成')

    # 自动登录
    def webbrowser_login(self, q):
        m = PyMouse()
        k = PyKeyboard()
        with open('browser_setting.txt') as b:
            bro = b.readlines()
            for index, i in enumerate(bro):
                bro_name, browser = i.strip().split(',', 1)

                # 浏览器地址
                chromepath = browser
                web.register(bro_name, None, web.BackgroundBrowser(chromepath))

                url = 'http://sem.taobao.com/login.html'
                web.get(bro_name).open(url, new=1)
                time.sleep(5)

                k.tap_key(k.right_key)
                k.tap_key(k.enter_key)
                time.sleep(1)

                # 读取用户名和密码
                with open('name_pwd.txt', encoding='utf8') as f:
                    n_p = f.readlines()
                    name_pwd = n_p[index].split(',')
                    username = name_pwd[0]
                    password = name_pwd[1]

                    pyperclip.copy(username)    # 复制用户名

                    m.click(900, 285)
                    time.sleep(1)

                    # 组合键-复制粘贴
                    k.press_key(k.control_key)  # 按住alt键
                    k.tap_key('v')    # 点击v建
                    k.release_key(k.control_key)    # 松开alt键
                    time.sleep(1)

                    k.tap_key(k.tab_key)
                    pyperclip.copy(password)
                    time.sleep(1)

                    # 组合键-粘贴
                    k.press_key(k.control_key)  # 按住alt键
                    k.tap_key('v')
                    k.release_key(k.control_key)    # 松开alt键
                    time.sleep(1)

                    k.tap_key(k.enter_key)
                    time.sleep(5)

                    message = q.get()
                    print(message)
                    if '抓包完成' == message:
                        # 解析包
                        self.parse_pcap()

    # 解析pcap包
    def parse_pcap(self):
        f = open('demo.pcap','rb')
        pcap = dpkt.pcap.Reader(f)
        cookie_list = []
        try:
            for t, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf) #获得以太包，即数据链路层包
                if eth.data.__class__.__name__ == 'IP':
                    if eth.data.data.__class__.__name__ == 'TCP':
                        data = eth.data.data.data
                        data = data.decode('utf-8', 'ignore')
                        if 'Cookie' in data:
                            patt = r'Cookie: (.*)'
                            cookies = re.findall(patt, data)
                            cookie_list.append(cookies[0])
            print(cookie_list[-1])
            with open('cookie.txt', 'w+') as f:
                f.write(cookie_list[-1])
        except Exception as e:
            print(e)
        finally:
            f.close()


if __name__ == '__main__':
    c = Cookieget()
    q = Queue()
    cookie = Process(target=c.scapy_get_cookie, args=(q,))
    login = Process(target=c.webbrowser_login, args=(q,))
    cookie.start()
    login.start()