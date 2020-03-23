import struct
import socket
#f=open("filemac.txt","w")
def main():
    conn=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
    while True:
        raw_data,addr=conn.recvfrom(65536)
        #print(addr)
        dest_mac,src_mac,proto,data=ethernet_frame(raw_data)
        #f.write(dest_mac+' '+src_mac+'\n')
        #print('{},{},{},'.format(dest_mac,src_mac,'\n'))
        #ip(data)
        #print(data)
        data1=ip(data)
        if(data1):
           tcp(data1)
           print('destination_mac:{},src_mac:{},{},'.format(dest_mac,src_mac,'\n'))
def tcp(data):
    #print(data[0:2])
    port_no=struct.unpack(' 2s ',data[0:2])
    src_port_no=struct.unpack('H',port_no[0])
    des_port_no=struct.unpack(' 2s ',data[2:4])
    des_port_no=struct.unpack('H',des_port_no[0])
    
    print('src_port:',''.join(map(str,src_port_no)))
    print('dest_port:',''.join(map(str,des_port_no)))

def ip(data):
    #version=struct.unpack('B',data[0:1])
    #print(''.join(map(str,version)))
    if((bin(data[0])[2:].zfill(8))[:4]=='0100'):
       ihl=int(bin(data[0])[2:].zfill(8)[4:],2)
       #print(ihl)
       dest_ip=struct.unpack(' 4s ',data[12:16])
       dest_ip=struct.unpack('BBBB',dest_ip[0])
       print('dest_ip:','.'.join(map(str,dest_ip)))
    
       src_ip=struct.unpack(' 4s ',data[16:20])
       src_ip=struct.unpack('BBBB',src_ip[0])
       print('src_ip:','.'.join(map(str,src_ip)))
       return data[ihl*4:]
    else:
       return 0
    #version=struct.unpack('')
    #port_no=struct.unpack('2s',data[20:22])
    #port_no=struct.unpack('BB',port_no[0])
    #print(''.join(map(str,port_no)))
    #print('.'.join(dest_ip))
def ethernet_frame(data):
    dest_mac,src_mac,proto=struct.unpack('! 6s 6s H',data[:14])  
    #print(proto)
    return get_mac_addr(dest_mac),get_mac_addr(src_mac),socket.htons(proto),data[14:]
def get_mac_addr(bytes_addr):
    bytes_str=map('{:02x}'.format,bytes_addr)
    #print(type(bytes_str))
    return ':'.join(bytes_str).upper()
main()
