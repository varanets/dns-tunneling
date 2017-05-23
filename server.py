#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  server.py
#  
#  Copyright 2017 Vorontsov <varanets@gui>
# 
#	Программа использует стандартный пакет http для запуска сервера на
#	80-м порту и доступного как с этого компьютера, так и из локальной
#	сети. Сервер принимает http-пакеты, где в качестве содержимого 
#	передаётся байтовый массив DNS-запроса. Если серверу не удается 
#	парсировать содержимое, отправляется код 400 о неккоректности. 
#	Если же всё в порядке, сервер посылает код 200 и от своего имени 
#	отправляет запрос на публичный DNS сервер Google. Из ответа также 
#	выделяется DNS-часть, кодируется в байты и отправляется обратно 
#	клиенту. Скрипт завершает выполнение по сигналу прерывания.

publicdns='8.8.8.8'
from http.server import BaseHTTPRequestHandler, HTTPServer

class HTTProcessor (BaseHTTPRequestHandler):
	def do_POST (self):
		try:
			#print (self.headers)
			dnsq = self.rfile.read(int(self.headers['Content-Length']))
			dnsq = DNS(dnsq)
		except Exception:
			self.send_response_only(400)
		else:
			self.send_response(200)
			self.send_header('content-type', 'application/octet-stream')
			self.end_headers()
			packet = IP(dst=publicdns)/UDP(sport=5353, dport=53)/dnsq
			res = sr1(packet)
			#res[DNS].show()
			self.wfile.write(bytes(res[DNS]))

def main(args):
	try:
		try:
			print ("\nДобро пожаловать!")
			serv = HTTPServer(("",80), HTTProcessor)
			serv.serve_forever()
		except Exception as e:
			print ("Ошибка создания сервера на порту 80:", e)
			sys.exit(1)
	except KeyboardInterrupt:
		print ("\n\nДо свидания!")
		serv.socket.close()
		return 0

if __name__ == '__main__':
	import sys
	from scapy.all import *
	sys.exit(main(sys.argv))
