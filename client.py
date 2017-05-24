#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  client.py
#  
#  Copyright 2017 Vorontsov <varanets@gui>
# 
#	Программа принимает пакеты посылаемые на UDP-порт 53 от команд 
#   nslookup(windows)/dig(linux) (находящихся как на этом же компьютере,
#	так и в локальной сети) и передаёт байтовый массив функции.
#   Функция cook с помощью модуля scapy выделяет из него DNS-часть и 
#	c помощью модуля request переправляет запрос также в байтовом виде
#	на http-сервер, запускаемый на этом же компьютере. Если серверу
#	удаётся разобрать DNS-запрос, из ответа также выделяется DNS-часть 
#	и отправляется обратно в сокет. Скрипт завершает выполнение по 
#	сигналу прерывания.

httpserver="http://localhost/"

def cook (data):
	pkt1=DNS(data) 
	#pkt1.qd.show()
	qtype=dnstypes[pkt1.qd.qtype]
	qname=pkt1.qd.qname.decode("utf-8")
	print ("Запись DNS запроса: %s, %s" % (qtype, qname))
	r = requests.post(httpserver, data=bytes(pkt1), timeout=2)
	if r.status_code==200:
		res = DNS(r.content)
		#res.show()
		status=res.rcode
		if status==0:
			qtype=dnstypes[res.an.type]
			qname=res.an.rrname.decode("utf-8")
			try: res.an.rdata.decode("utf-8")
			except Exception as ex: rdata=res.an.rdata#; print(ex)
			else: rdata=(res.an.rdata).decode("utf-8")
		else:
			qtype=dnstypes[res.qd.qtype]
			qname=res.qd.qname.decode("utf-8")
			rdata=""
		print ("Запись DNS ответа: %s, %s, %s, %s" % (qtype, qname, status, rdata))
		return bytes(res[DNS])
	else:
		print ("Ошибка в DNS запросе")
		return None

def main(args):
	try:
		print ("\nДобро пожаловать!")
		udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		udps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		udps.bind(('',53))
	except Exception as e:
		print ("Ошибка создания сокета UDP на порту 53:", e)
		sys.exit(1)
	else:
		print ("\nDNS-прокси готов для входящих подключений")
	try:
		while 1:
			data, addr = udps.recvfrom(1024)
			print ("\nПолучен DNS-запрос с адреса %s:%i" % addr)
			udps.sendto(cook(data), addr)
	except KeyboardInterrupt:
		print ("\n\nДо свидания!")
		udps.close()
		return 0

if __name__ == '__main__':
	import sys
	import socket
	from scapy.all import DNS, dnstypes
	import requests
	sys.exit(main(sys.argv))
