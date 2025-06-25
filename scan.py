import socket
import threading
from scapy.all import *
import argparse
from os import geteuid

class portScan():
    def __init__(self,target,sp=1,ep=1000,spoof=0,time=1,dlen=200,flag="S",msg=""):
        self.ip = socket.gethostbyname(target)
        self.sp = sp
        self.ep = ep
        self.spoof = spoof
        self.time = time
        self.dlen = dlen
        self.flag = flag
        self.msg = msg
        self.__stats__()    


    def __stats__(self):
        print(f"{'\033[94m'}\nTarget: {self.ip} Port:{self.sp}-{self.ep} Spoofing:{self.spoof} Timeout:{self.time} Length:{self.dlen} Flag:{self.flag} Msg:{self.msg}\n")
    
    def __connect__(self,port):

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(self.time)

        if(self.s.connect_ex((self.ip,port)) == 0):

                try:
                    self.s.send(b"GET / HTTP/1.1\r\nHost: www.b00m.haHA\r\nConnection: close\r\n\r\n")
                    data = self.s.recv(self.dlen)
                except:
                    data = b""


                print(f"{'\033[31m'}\r[+] Port {port} {socket.getservbyport(port)}",end="")
                print(f"   |__ {data}")


    def scan(self):

        for i in range(self.sp,self.ep+1):
            if self.spoof:
                self.Spoof(i)

            print(f"{'\033[92m'}[°] Scanning Port {i}",end="\r")
            self.__connect__(i)

        self.s.close()

    def Fscan(self):
        for i in range(self.sp,self.ep+1):
            if self.spoof:
                threading.Thread(target=self.Spoof,args=(i,)).start()

            print(f"{'\033[92m'}[°] Scanning Port {i}",end="\r")
            threading.Thread(target=self.__connect__,args=(i,)).start()
        self.s.close()
    
    def Spoof(self,port):
        for _ in range(self.spoof):
            sendp(Ether(src=str(RandMAC()))/IP(src=str(RandIP()),dst=self.ip,flags="DF")/TCP(sport=int(RandShort()),dport=port,flags=self.flag)/Raw(load=self.msg),verbose=0)             


    def Cscan(self):
        for i in range(self.sp,self.ep+1):

            if self.spoof:
                self.Spoof(i)

            d=srp(Ether()/IP(dst=self.ip,flags="DF")/TCP(sport=int(RandShort()),dport=i,flags=self.flag)/Raw(load=self.msg),verbose=0, timeout=self.time)             

            try:
                if str(d[0][0][1][2].flags) == "SA":
                    print(f"{'\033[92m'}[???] Port {i}       Service:{socket.getservbyport(i)}        Response:{str(d[0][0][1][2].flags)}")
                else:
                    print(f"{'\033[31m'}[???] Port {i}       Service:{socket.getservbyport(i)}        Response:{str(d[0][0][1][2].flags)}")
            except:
                pass

def main():
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-ip", help="Target IP", type=str)
    parser.add_argument("-p", help="Port -p 1,100 or -p 100", type=str, default="1,1000")
    parser.add_argument("-F", help="Activate FastScan", dest="F",action='store_true')
    parser.add_argument("-S", help="Activate Spoofing", type=int, default=0)
    parser.add_argument("-t", help="Set Timeout", type=float, default=1)
    parser.add_argument("-flag", help="Set Flag S,SA,R,F... ", type=str, default="S")
    parser.add_argument("-msg", help="Raw Load", type=str, default="")
    parser.add_argument("-dlen", help="Receive length", type=int, default=200)
    parser.parse_args()
    args = parser.parse_args()

    if  geteuid() != 0 and (args.flag != "S" or args.S > 0) :
        print(f"{'\033[33m'}[-]  Run as root required")
        exit(0)

    if len(args.p.split(",")) == 2:
        sp = int(args.p.split(",")[0])
        ep = int(args.p.split(",")[1])
    else:
        sp = 1
        ep = int(args.p.split(",")[0])

    if args.F == 0 and args.flag == "S":
        portScan(args.ip,sp,ep,args.S,args.t,args.dlen,args.flag,args.msg).scan()

    elif args.F == 1 and args.flag == "S":
        portScan(args.ip,sp,ep,args.S,args.t,args.dlen,args.flag,args.msg).Fscan()

    elif args.F == 0 and args.flag != "S":
        portScan(args.ip,sp,ep,args.S,args.t,args.dlen,args.flag,args.msg).Cscan()

try:
    main()
except Exception as e:
    print(f"[-] {'\033[33m'} {e}")
