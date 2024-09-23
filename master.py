from functools import reduce
import serial
ACK=0x79
NACK=0x1F
class SerialPort:
    def __init__(self, port, baudrate,parity,timeout):
        try:
            self.ser = serial.Serial(port, baudrate,parity=parity,timeout=timeout)
            print("Serial port opened successfully")
        except:
            print("Error opening serial port")
    def calculate_checksum(self,data):
        return reduce(lambda x, y: x ^ y, data, 0x00) if data else 0x00
    def get_reverse(self,data):
        return ~data & 0xFF
    def read_reg(self,addr,length):
        send_data = bytes([0x11,0xee])
        self.ser.write(send_data)
        ack= self.ser.read(1)[0]
        print("Ack received:",ack)
        if(ack!=ACK):
            print("Error in sending data1")
            return
        addr_bytes=bytes.fromhex(addr)
        addr_bytes+=(bytes([self.calculate_checksum(addr_bytes)]))
        
        self.ser.write(addr_bytes)
        ack= self.ser.read(1)[0]
        print("Ack received:",ack)
        if(ack!=ACK):
            print("Error in sending data2")
            return
        send_data=bytes()
        send_data+=bytes([length-1])
        send_data+=bytes([self.get_reverse(length-1)])
        self.ser.write(send_data)
        ack= self.ser.read(1)[0]
        print("Ack received:",ack)
        if(ack!=ACK):
            print("Error in sending data3")
            return
        data=self.ser.read_all()
        print("Data received:",data)
        
    def write_reg(self,addr,data,length):
        send_data=bytes([0x31,0xce])
        self.ser.write(send_data)
        ack= self.ser.read(1)[0]
        print("Ack received:",ack)
        if(ack!=ACK):
            print("Error in sending data1")
            return 
        addr_bytes=bytes.fromhex(addr)
        addr_bytes+=(bytes([self.calculate_checksum(addr_bytes)]))
        
        self.ser.write(addr_bytes)
        ack= self.ser.read(1)[0]
        print("Ack received:",ack)
        if(ack!=ACK):
            print("Error in sending data2")
            return
        
        send_data=bytes([length-1])
        data_bytes=bytes.fromhex(data)
        send_data+=data_bytes
        send_data+=(bytes([self.calculate_checksum(send_data)]))
        self.ser.write(send_data)
        ack= self.ser.read(1)[0]
        print("Ack received:",ack)
        if(ack!=ACK):
            print("Error in sending data3")
            return
        print("Data sent successfully")
          
        
        
if __name__ == '__main__':
    port = "COM10"
    baudrate = 115200
    parity = serial.PARITY_EVEN
    timeout = 114
    serialport=SerialPort(port,baudrate,parity,timeout)
    
    serialport.write_reg("08000000","01020304",4)
    serialport.read_reg("08000000",20)
    
