#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
DDNS
@author: New Future
@modified: rufengsuixing
"""
from __future__ import print_function
from time import ctime, asctime
from os import path, environ, name as os_name
from tempfile import gettempdir
from logging import DEBUG, basicConfig, info, warning, error, debug
from subprocess import check_output
import sys,time,threading

from flask import Flask,jsonify,request
from gevent import pywsgi

from util import ip
from util.cache import Cache
from util.config import init_config, get_config

__version__ = "${BUILD_VERSION}@${BUILD_DATE}"  # CI 时会被Tag替换
__description__ = "automatically update DNS records to dynamic local IP [自动更新DNS记录指向本地IP]"
__doc__ = """
ddns[%s]
(i) homepage or docs [文档主页]: https://ddns.newfuture.cc/
(?) issues or bugs [问题和帮助]: https://github.com/NewFuture/DDNS/issues
Copyright (c) New Future (MIT License)
""" % (__version__)

environ["DDNS_VERSION"] = "${BUILD_VERSION}"

app = Flask(__name__)


if getattr(sys, 'frozen', False):
    # https://github.com/pyinstaller/pyinstaller/wiki/Recipe-OpenSSL-Certificate
    environ['SSL_CERT_FILE'] = path.join(
        getattr(sys, '_MEIPASS'), 'lib', 'cert.pem')

@app.route('/api/get_ip/',methods=['GET'])
def api_get_ip():
    ipv4 = get_ip("4", get_config('index' + "4", "default"))
    local_ipv4 = get_ip("4", "default")
    ipv6 = get_ip("6", get_config('index' + "6", "default"))
    rdata = {"code": 0, "msg": "", "data": {"ipv4": ipv4, "ipv6": ipv6, "local_ipv4": local_ipv4}}
    return jsonify(rdata)

@app.route('/api/refresh_ip/',methods=['GET'])
def api_refresh_ip():

    # 清空缓存 并更新ip
    cache = get_config('cache', True)
    cache = cache is True and path.join(gettempdir(), 'ddns.cache') or cache
    cache = Cache(cache)
    cache.clear()
    updata_ip_main(True)

    ipv4 = get_ip("4", get_config('index' + "4", "default"))
    local_ipv4 = get_ip("4","default")
    ipv6 = get_ip("6", get_config('index' + "6", "default"))
    rdata = {"code":0,"msg":"","data":{"ipv4":ipv4,"ipv6":ipv6,"local_ipv4":local_ipv4}}
    return jsonify(rdata)




def get_ip(ip_type, index="default"):
    """
    get IP address
    """
    if index is False:  # disabled
        return False
    elif type(index) == list:  # 如果获取到的规则是列表，则依次判断列表中每一个规则，直到找到一个可以正确获取到的IP
        value = None
        for i in index:
            value = get_ip(ip_type, i)
            if value:
                break
    elif str(index).isdigit():  # 数字 local eth
        value = getattr(ip, "local_v" + ip_type)(index)
    elif index.startswith('cmd:'):  # cmd
        value = str(check_output(index[4:]).strip().decode('utf-8'))
    elif index.startswith('shell:'):  # shell
        value = str(check_output(
            index[6:], shell=True).strip().decode('utf-8'))
    elif index.startswith('url:'):  # 自定义 url
        value = getattr(ip, "public_v" + ip_type)(index[4:])
    elif index.startswith('regex:'):  # 正则 regex
        value = getattr(ip, "regex_v" + ip_type)(index[6:])
    elif any((c in index) for c in '*.:'):  # 兼容 regex
        value = getattr(ip, "regex_v" + ip_type)(index)
    else:
        value = getattr(ip, index + "_v" + ip_type)()

    return value
def change_dns_record(dns, proxy_list, **kw):
    for proxy in proxy_list:
        if not proxy or (proxy.upper() in ['DIRECT', 'NONE']):
            dns.PROXY = None
        else:
            dns.PROXY = proxy
        record_type, domain = kw['record_type'], kw['domain']
        print('%s %s(%s) ==> %s [via %s]' %(asctime(), domain, record_type, kw['ip'], proxy))
        try:
            return dns.update_record(domain, kw['ip'], record_type=record_type)
        except Exception as e:
            error(e)
    return False
def update_ip(ip_type, cache, dns, proxy_list):
    """
    更新IP
    """
    ipname = 'ipv' + ip_type
    domains = get_config(ipname)
    if not domains:
        return None
    if not isinstance(domains, list):
        domains = domains.strip('; ').replace(
            ',', ';').replace(' ', ';').split(';')
    index_rule = get_config('index' + ip_type, "default")  # 从配置中获取index配置
    address = get_ip(ip_type, index_rule)
    record_type = (ip_type == '4') and 'A' or 'AAAA'
    if not address:
        error('Fail to get %s address!', ipname)
        return False
    elif cache and (address == cache[ipname]):
        for domain in domains:
            print('%s %s(%s) ==> %s [via %s]' %(asctime(), domain, record_type, address, 'cache'))
        return True

    update_fail = False  # https://github.com/NewFuture/DDNS/issues/16
    for domain in domains:
        if change_dns_record(dns, proxy_list, domain=domain, ip=address, record_type=record_type):
            update_fail = True
    if cache is not False:
        # 如果更新失败删除缓存
        cache[ipname] = update_fail and address

def updata_ip_main(is_api=False):
    """
    更新
    """

    # Dynamicly import the dns module as configuration
    dns_provider = str(get_config('dns', 'dnspod').lower())
    dns = getattr(__import__('dns', fromlist=[dns_provider]), dns_provider)
    dns.Config.ID = get_config('id')
    dns.Config.TOKEN = get_config('token')
    dns.Config.TTL = get_config('ttl')
    if get_config('debug'):
        ip.DEBUG = get_config('debug')
        basicConfig(
            level=DEBUG,
            format='%(asctime)s <%(module)s.%(funcName)s> %(lineno)d@%(pathname)s \n[%(levelname)s] %(message)s')
        print("DDNS[", __version__, "] run:", os_name, sys.platform)
        if get_config("config"):
            print("Configuration was loaded from <==",
                  path.abspath(get_config("config")))
        print("=" * 25, ctime(), "=" * 25, sep=' ')


    proxy = get_config('proxy') or 'DIRECT'
    proxy_list = proxy if isinstance(
        proxy, list) else proxy.strip('; ').replace(',', ';').split(';')

    cache = get_config('cache', True)
    cache = cache is True and path.join(gettempdir(), 'ddns.cache') or cache
    cache = Cache(cache)
    if is_api:
        cache = False
    if cache is False:
        info("Cache is disabled!")
    elif get_config("config_modified_time") is None or get_config("config_modified_time") >= cache.time:
        #warning("Cache file is out of dated.")
        cache.clear()
    elif not cache:
        debug("Cache is empty.")
    update_ip('4', cache, dns, proxy_list)
    update_ip('6', cache, dns, proxy_list)

class backgroud_thread(threading.Thread):
    def __init__(self, ):
        threading.Thread.__init__(self)

    def run(self):
        timeout = get_config('timeout')
        print("当前DDNS IP 刷新时间:" + str(timeout))
        while True:
            time.sleep(timeout)
            print(asctime() + " 刷新IP地址信息")
            updata_ip_main()


if __name__ == '__main__':
    init_config(__description__, __doc__, __version__)
    ipv4 = get_ip("4", get_config('index' + "4", "default"))
    updata_ip_main()
    back_thread = backgroud_thread()
    back_thread.start()
    # 启动 Flask 进程
    server = pywsgi.WSGIServer(("0.0.0.0", get_config("port")), app)
    server.serve_forever()




