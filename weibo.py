import base64
import re
from binascii import b2a_hex
from requests_toolbelt.utils import dump
import requests
import time

import rsa


class LoginWeibo():
    def __init__(self,username,password):
        self.username=username
        self.password=password

        #session设置
        self.session=requests.session()
        #user-agent也可以通过fiddler上看到
        self.session.headers={'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.70 Safari/537.36'}
        self.session.verify = True  # 取消证书验证


    def enter5445(self):
        #进去5445需要username转化成su以及获取当前时间戳
        timestamp=int(time.time()*1000)
        #因为之后也用到su，所以这里作为类的变量,js代码指示了他的做法
        self.su=base64.b64encode(self.username.encode())
        url='https://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack' \
            '&su={}&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.19)&_={}'.format(self.su,timestamp)
        #获取response
        response=self.session.get(url).content.decode()
        #可以通过正则表达式从里面抽取nonce,pubkey,rsakv,servertime值提供给5446
        self.nonce = re.findall(r'"nonce":"(.*?)"', response)[0]
        self.pubkey = re.findall(r'"pubkey":"(.*?)"', response)[0]
        self.rsakv = re.findall(r'"rsakv":"(.*?)"', response)[0]
        self.servertime = re.findall(r'"servertime":(.*?),', response)[0]

    def get_sp(self):
        '''同样是看的ssologin.js里面的代码，直接抄写了第一篇博客的代码'''
        publickey = rsa.PublicKey(int(self.pubkey, 16), int('10001', 16))
        message = str(self.servertime) + '\t' + str(self.nonce) + '\n' + str(self.password)
        self.sp = rsa.encrypt(message.encode(), publickey)
        return b2a_hex(self.sp)

    def enter5446(self):
        url='https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.19)'
        #抄写fiddler这个响应的webforms内容
        data={
            'entry':'weibo',
            'gateway':'1',
            'from':'',
            'savestate':'7',
            'qrcode_flag': 'false',
            'useticket': '1',
            'pagerefer': 'https://www.baidu.com/link?url=0IuHDm9TTUkxC4nzqemXsLyaKZxKyWjRplglL41t-xq&wd=&eqid=c9309676000092ff000000065dd649ed',
            'vsnf': '1',
            'su': self.su,
            'service': 'miniblog',
            'servertime': str(int(self.servertime) ),
            'nonce': self.nonce,
            'pwencode': 'rsa2',
            'rsakv': self.rsakv,
            'sp': self.get_sp(),
            'sr': '1920 * 1080',
            'encoding': 'UTF - 8',
            'prelt': '723',
            'url': 'https://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
            'returntype': 'META',
        }
        response = self.session.post(url, data=data, allow_redirects=False).text
        return response

    def enter5448(self,response):
        redirect_url = re.findall(r'location.replace\("(.*?)"\);', response)[0]  # 从5446返回的内容直接得到5448的响应地址，可以看fiddler的syntaxview的具体内容
        result = self.session.get(redirect_url, allow_redirects=False).text
        ticket, ssosavestate = re.findall(r'ticket=(.*?)&ssosavestate=(.*?)"', result)[0] #给5450页面使用
        return ticket,ssosavestate

    def enter5450(self,ticket, ssosavestate):
        timestamp = int(time.time() * 1000)
        url = 'https://passport.weibo.com/wbsso/login?ticket={}&ssosavestate={}&' \
              'callback=sinaSSOController.doCrossDomainCallBack&scriptId=ssoscript0&client=ssologin.js(v1.4.19)&_={}'.format(
            ticket, ssosavestate, timestamp)
        data = self.session.get(url).text

        co=self.session.cookies
        print(co.get_dict())
        uid = re.findall(r'"uniqueid":"(.*?)"', data)[0] #为最后的weibo页面提供id
        return uid



    def login(self):
        #enter 5445
        self.enter5445()
        #enter 5446
        response_5446=self.enter5446()
        #enter 5448
        ticket, ssosavestate =self.enter5448(response_5446)
        #enter 5450
        uid=self.enter5450(ticket, ssosavestate )
 

if __name__ == '__main__':
    username = ''  # 微博账号
    password = ''  # 微博密码
    weibo = LoginWeibo(username, password)
    weibo.login()