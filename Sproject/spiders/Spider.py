# -*- coding:utf-8 -*-
import requests
import scrapy
import re
import time
from hashlib import sha1
import hmac
from scrapy.http.cookies import CookieJar



cookie_jar = CookieJar()

class spider(scrapy.Spider):
	name = 'ZHspider'
	allowed_domains = ['www.zhihu.com']
	# start_urls = ['https://www.zhihu.com/signup?next=%2F'] 

	def start_requests(self):
		headers = {'User-Agent' : r'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.104 Safari/537.36',
					'Referer' : r'https://www.zhihu.com/',
					'accept': 'application/json, text/plain, */*', 
					'Accept-Encoding' : 'gzip, deflate, br', 'Upgrade-Insecure-Requests' : '1'}

		return [scrapy.Request(url = r'https://www.zhihu.com/signup?next=%2F',  headers = headers, callback = self.get_captcha)]				

	def get_captcha(self, response):
		headers = {'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.104 Safari/537.36', 
					'authorization' : 'oauth c3cef7c66a1843f8b3a9e6a1e3160e20'}

		cookie_jar.extract_cookies(response, response.request)
		return [scrapy.Request('https://www.zhihu.com/api/v3/oauth/captcha?lang=cn', meta = {'cookiejar' : cookie_jar}, headers = headers, callback = self.start_login)]

	def start_login(self, response):

		clientId = 'c3cef7c66a1843f8b3a9e6a1e3160e20'
		grantType = 'password'
		source = 'com.zhihu.web'
		timestamp = str(int(time.time()*1000))
		if 'false' in response.text:
			captcha = '' 
		else:
			return

		headers = {'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.104 Safari/537.36', 
					'authorization' : 'oauth c3cef7c66a1843f8b3a9e6a1e3160e20',
					'Referer' : r'https://www.zhihu.com/signup?next=%2F'}

		data = {'client_id' : clientId,
			'grant_type' : grantType,
			'lang' : 'cn', 
			'ref_source' : 'other_',
			'source' : source,
			'timestamp' : timestamp,
			'signature' : self.get_signature(clientId, grantType, timestamp, source),
			'username' : '+8613242311433',
			'password' : 'xieyueying1',
			'utm_source' : 'baidu', 
			'captcha' : ''}

		return [scrapy.FormRequest('https://www.zhihu.com/api/v3/oauth/sign_in', 			
			headers = headers,
			meta = {'cookiejar' : cookie_jar},
			formdata = data,
			callback = self.after_login)]

	def after_login(self, response):
		headers = {'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.104 Safari/537.36', 
					'authorization' : 'oauth c3cef7c66a1843f8b3a9e6a1e3160e20'}
		set_cookies = response.headers.getlist('set-cookie')[0]
		cookies = response.request.headers.getlist('Cookie')[0]

		new_cookies = self.parse_cookies(set_cookies, cookies)
		return [scrapy.Request(url = 'https://www.zhihu.com/', cookies = new_cookies,  headers = headers, callback = self.check_login)]

	def check_login(self, response):
		headers = {'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.104 Safari/537.36', 
					'authorization' : 'oauth c3cef7c66a1843f8b3a9e6a1e3160e20'}
		print(response)

	def parse_cookies(self, set_cookies, cookies):
		new_cookies = {
				'capsion_ticket' : re.search('capsion_ticket=(.+)', str(cookies).split(';')[1]).group(1)}
		
		for i in str(set_cookies).split(';'):
			if re.search('z_c0=(.+)', i) is not None:
				new_cookies['z_c0'] = re.search('z_c0=(.+)', i).group(1)
			if re.search('__DAYU_PP=(.+)', i) is not None:
				new_cookies['__DAYU_PP'] = re.search('__DAYU_PP=(.+)', i).group(1)

		return new_cookies
				
	def get_signature(self, clientId, grantType, timestamp, source):
		hm = hmac.new(b'd1b964811afb40118a12068ff74a12f4', None, sha1)
		hm.update(str.encode(grantType))
		hm.update(str.encode(clientId))
		hm.update(str.encode(source))
		hm.update(str.encode(timestamp))

		return str(hm.hexdigest())