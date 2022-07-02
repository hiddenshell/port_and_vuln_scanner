import socket
import os

class PortScanner:
	
	def __init__(self,target,port,vuln_file):
		self.target = target
		self.port = port
		self.vuln_banner = []
		self.vuln_list = []
		self.result = []
		with open(vuln_file, "r") as file:
			lines = file.readlines()
			for line in lines:
				self.vuln_banner.append(line.strip())
				
				
				
	def check_vuln(self,port,banner):
		if banner in self.vuln_banner:
			self.vuln_list.append(f" {str(port)} --> {str(banner)}")
			return True
		else:
			return False
	
	
	def grab_banner(self,sock):
		try:
			banner = sock.recv(1024).decode().strip()
			if banner == "" or banner == " " or banner == None or banner == "None":
				return "couldn't fatch banner"
			else:
				return banner
		except Exception as e:
			pass
		
	
	
	def show_result(self):
		for result in self.result:
			print(result)
	
	def show_vuln_result(self):
		print(f"\n\n------------------------------")
		print(f"[+] Total {str(len(self.vuln_list))} Vulnability Found:")
		print(f"------------------------------\n")
		num = 1
		for vuln in self.vuln_list:
			print(f" {str(num)}. {vuln}")
			num += 1
		
		
	def scan_port(self,ip,port):
		sock = socket.socket()
		try:
			sock.connect((ip,port))
			sock.settimeout(5)
			banner = self.grab_banner(sock)
			vuln_status = self.check_vuln(port, banner)
			self.result.append(f" {str(port)}	Open	{str(banner)}")
		except Exception as e:
			pass
	
	def scanner(self):
		print(f"\n\n[+] Scanning Started on {str(self.target)} \n")
		
		for port in range(1,self.port):
			self.scan_port(self.target, port)
		if len(self.result) >0:
			print(f"-----------------------")
			print(f"PORT	STATE	SERVICE")
			print(f"-----------------------")
			self.show_result()
		else:
			print(f"[-] All {str(self.port)} are closed")
		if len(self.vuln_list) > 0:
			self.show_vuln_result()
		print("\n")
if __name__ == "__main__":
	
	r_target = input("Enter Target IP: ")
	r_port_range = input("Enter port range: ")
	r_file_name = input(str("Enter banner file path: "))
	target = "192.168.0.1"
	port_range = 1023
	file_name = "vulbanners.txt"
	if r_target != "":
		target = r_target
	if r_port_range != "":
		port_range = int(r_port_range)
	if r_file_name != "":
		file_name = r_file_name

	if "," in target:
		ips = target.split(",")
		for ip in ips:
			scanner = PortScanner(target=ip, port=port_range,vuln_file=file_name)
			scanner.scanner()
			
	else:
			scanner = PortScanner(target=target, port=port_range,vuln_file=file_name)
			scanner.scanner()
			
#	scanner.scan_port(target,80)

# 192.168.0.1,192.168.0.100






	
#	if "/" in target:
#		base_ip = target.split("/")[0][:-1]
#		scanner = PortScanner(target=target.split("/")[0], port=port_range,vuln_file=file_name)
#		scanner.scanner()
#		mask = 100
#		for submask in range(1,150):
#			ip = base_ip+str(mask)
#			scanner = PortScanner(target=ip, port=port_range,vuln_file=file_name)
#			scanner.scanner()
#			mask += 1
#	else:
#		scanner = PortScanner(target=target, port=port_range,vuln_file=file_name)
#		scanner.scanner()