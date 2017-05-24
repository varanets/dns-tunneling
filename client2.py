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

def cook (qtype, qname):
	pkt1=DNS(rd=1,qd=DNSQR(qtype=qtype, qname=qname)) 
	#pkt1.show()
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
		return (qtype, qname, status, rdata)
	else:
		print ("Ошибка в DNS запросе")
		return None

def main(args):
	f1 = open ('query.txt', 'r')
	f2 = open ('answer.txt', 'w')
	for line in f1:
		line=line.rstrip('\n')
		qtype, qname = line.split(", ")
		print ("Запись DNS запроса: '%s', '%s'" % (qtype, qname))
		mas = cook(qtype,qname)
		string = ", ".join("%s" % i for i in mas)
		print ("Запись DNS ответа: %s" % string)
		f2.write(string+'\n')
	f1.close()
	f2.close()
	print ("\n\nДо свидания!")
	return 0

if __name__ == '__main__':
	import sys
	import socket
	from scapy.all import DNS, DNSQR, dnstypes
	import requests
	sys.exit(main(sys.argv))
