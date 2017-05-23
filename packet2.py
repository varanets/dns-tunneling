#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  packet2.py
#  
#  Copyright 2017 Vorontsov <varanets@gui>
# 
#	Программа принимает пакеты от команд nslookup(windows)/dig(linux),
#	выделяет из них DNS-часть и переправляет запрос на публичный DNS
#   сервер Google. Из ответа также выделяется DNS-часть и отправляется
#	обратно в сокет. Завершает выполнение по сигналу прерывания.

publicdns='8.8.8.8'

def cook (dnsq):
	packet = IP(dst=publicdns)/UDP(sport=5353, dport=53)/dnsq
	res = sr1(packet)
	#res.show()
	return bytes(res[DNS])

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
			pkt1=DNS(data) 
			pkt1.qd.show()
			udps.sendto(cook(pkt1), addr)
	except KeyboardInterrupt:
		print ("\n\nДо свидания!")
		udps.close()
		return 0

if __name__ == '__main__':
	import sys
	import socket
	from scapy.all import *
	sys.exit(main(sys.argv))
