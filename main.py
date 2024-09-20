import serial
import threading
import time
from functools import reduce

# 配置串口参数
SERIAL_PORT = 'COM2'  # 修改为实际使用的串口，如 '/dev/ttyUSB0'
BAUDRATE = 115200
TIMEOUT = 1  # 超时时间（秒）

# 常量定义
ACK = 0x79
NACK = 0x1F

# 内存区域定义
FLASH_START = 0x08000000
FLASH_SIZE = 0x00100000  # 1MB 假设FLASH为1MB
FLASH = bytearray([0xFF] * FLASH_SIZE)

SRAM_START = 0x20000000
SRAM_SIZE = 0x00020000  # 128KB 假设SRAM为128KB
SRAM = bytearray([0xFF] * SRAM_SIZE)

# 内存区域列表
memory_regions = [
    ('FLASH', FLASH_START, FLASH_SIZE, FLASH),
    ('SRAM', SRAM_START, SRAM_SIZE, SRAM),
    # 可以根据需要添加更多内存区域
]

def calculate_checksum(data):
    """计算简单的XOR校验和"""
    return reduce(lambda x, y: x ^ y, data, 0x00) if data else 0x00

def get_memory_region(address):
    """根据地址获取对应的内存区域及偏移"""
    for region_name, start, size, mem in memory_regions:
        if start <= address < start + size:
            return (region_name, address - start, mem)
    return None

class STM32Simulator:
    # 定义状态
    STATE_WAIT_INIT = 'WAIT_INIT'
    STATE_WAIT_COMMAND = 'WAIT_COMMAND'
    STATE_WAIT_COMMAND_COMP = 'WAIT_COMMAND_COMP'
    STATE_COMMAND_RECEIVED = 'COMMAND_RECEIVED'

    # 针对不同命令的子状态
    STATE_READ_MEMORY_WAIT_ADDR = 'READ_MEMORY_WAIT_ADDR'
    STATE_READ_MEMORY_WAIT_ADDR_CHK = 'READ_MEMORY_WAIT_ADDR_CHK'
    STATE_READ_MEMORY_WAIT_N = 'READ_MEMORY_WAIT_N'
    STATE_READ_MEMORY_WAIT_N_COMP = 'READ_MEMORY_WAIT_N_COMP'

    STATE_WRITE_MEMORY_WAIT_ADDR = 'WRITE_MEMORY_WAIT_ADDR'
    STATE_WRITE_MEMORY_WAIT_ADDR_CHK = 'WRITE_MEMORY_WAIT_ADDR_CHK'
    STATE_WRITE_MEMORY_WAIT_N = 'WRITE_MEMORY_WAIT_N'
    STATE_WRITE_MEMORY_WAIT_N_COMP = 'WRITE_MEMORY_WAIT_N_COMP'
    STATE_WRITE_MEMORY_WAIT_DATA = 'WRITE_MEMORY_WAIT_DATA'
    STATE_WRITE_MEMORY_WAIT_DATA_CHK = 'WRITE_MEMORY_WAIT_DATA_CHK'

    STATE_ERASE_MEMORY_WAIT_N = 'ERASE_MEMORY_WAIT_N'
    STATE_ERASE_MEMORY_WAIT_PAGES = 'ERASE_MEMORY_WAIT_PAGES'
    STATE_ERASE_MEMORY_WAIT_CHK = 'ERASE_MEMORY_WAIT_CHK'

    def __init__(self, port, baudrate, timeout=1):
        try:
            self.ser = serial.Serial(port, baudrate, timeout=timeout)
            print(f"Successfully opened serial port {port} at {baudrate} baud.")
        except serial.SerialException as e:
            print(f"Error opening serial port {port}: {e}")
            exit(1)
        
        self.state = self.STATE_WAIT_INIT
        self.current_command = None
        self.buffer = []
        self.lock = threading.Lock()

    def send_ack(self):
        self.ser.write(bytes([ACK]))
        print("Sent ACK")

    def send_nack(self):
        self.ser.write(bytes([NACK]))
        print("Sent NACK")

    def handle_get_command(self):
        """处理Get命令 (0x00)"""
        protocol_version = 0x40  # 假设协议版本为4.0
        supported_commands = [
            0x00,  # Get
            0x01,  # Get Version
            0x02,  # Get ID
            0x11,  # Read Memory
            0x21,  # Go
            0x31,  # Write Memory
            0x43,  # Erase Memory
            0x44,  # Extended Erase Memory
            0x63,  # Write Protect
            0x73,  # Write Unprotect
            0x82,  # Readout Protect
            0x92   # Readout Unprotect
        ]
        response = bytearray()
        response.append(ACK)
        response.append(len(supported_commands) + 2)  # N = number of bytes to follow -1
        response.append(protocol_version)
        for cmd in supported_commands:
            response.append(cmd)
        self.ser.write(response)
        print("Handled Get Command")
        self.send_ack()

    def handle_read_memory_ack(self):
        """发送ACK后，进入等待地址部分"""
        self.state = self.STATE_READ_MEMORY_WAIT_ADDR
        self.buffer = []

    def handle_read_memory_address(self, byte):
        self.buffer.append(byte)
        if len(self.buffer) == 4:
            # 等待校验和
            self.state = self.STATE_READ_MEMORY_WAIT_ADDR_CHK

    def handle_read_memory_address_checksum(self, byte):
        address_bytes = self.buffer
        received_checksum = byte
        calculated_checksum = calculate_checksum(address_bytes)
        if calculated_checksum != received_checksum:
            self.send_nack()
            print(f"Read Memory: Address checksum invalid: {calculated_checksum:02X} != {received_checksum:02X}")
            self.state = self.STATE_WAIT_COMMAND
            self.buffer = []
            return
        address = int.from_bytes(address_bytes, byteorder='big')
        region = get_memory_region(address)
        if not region:
            self.send_nack()
            print(f"Read Memory: Address {address:#010X} out of range")
            self.state = self.STATE_WAIT_COMMAND
            self.buffer = []
            return
        region_name, offset, mem = region
        print(f"Read Memory: Region {region_name}, Offset {offset:#06X}")
        self.send_ack()
        self.state = self.STATE_READ_MEMORY_WAIT_N
        self.buffer = {'region': region, 'address': address}

    def handle_read_memory_n(self, byte):
        N = byte
        self.buffer['N'] = N
        self.state = self.STATE_READ_MEMORY_WAIT_N_COMP

    def handle_read_memory_n_complement(self, byte):
        N = self.buffer['N']
        complement = byte
        if (N ^ complement) != 0xFF:
            self.send_nack()
            print(f"Read Memory: N checksum invalid: {N ^ complement:#04X} != 0xFF")
            self.state = self.STATE_WAIT_COMMAND
            self.buffer = {}
            return
        self.send_ack()
        self.state = 'SENDING_READ_MEMORY_DATA'
        self.read_memory_data()

    def read_memory_data(self):
        """发送读取的数据、校验和和ACK"""
        region, offset, mem = self.buffer['region']
        N = self.buffer['N']
        num_bytes = N +1
        data = mem[offset:offset + num_bytes]
        self.ser.write(data)
        print(f"Read Memory: Sent {num_bytes} bytes from address {self.buffer['address']:#010X}")
        # data_checksum = calculate_checksum(data)
        # self.ser.write(bytes([data_checksum]))
        # self.send_ack()
        # 结束命令处理
        self.state = self.STATE_WAIT_COMMAND
        self.buffer = {}

    def handle_write_memory_ack(self):
        """发送ACK后，进入等待地址部分"""
        self.state = self.STATE_WRITE_MEMORY_WAIT_ADDR
        self.buffer = []

    def handle_write_memory_address(self, byte):
        self.buffer.append(byte)
        if len(self.buffer) == 4:
            # 等待校验和
            self.state = self.STATE_WRITE_MEMORY_WAIT_ADDR_CHK

    def handle_write_memory_address_checksum(self, byte):
        address_bytes = self.buffer
        received_checksum = byte
        calculated_checksum = calculate_checksum(address_bytes)
        if calculated_checksum != received_checksum:
            self.send_nack()
            print(f"Write Memory: Address checksum invalid: {calculated_checksum:02X} != {received_checksum:02X}")
            self.state = self.STATE_WAIT_COMMAND
            self.buffer = []
            return
        address = int.from_bytes(address_bytes, byteorder='big')
        region = get_memory_region(address)
        if not region:
            self.send_nack()
            print(f"Write Memory: Address {address:#010X} out of range")
            self.state = self.STATE_WAIT_COMMAND
            self.buffer = []
            return
        region_name, offset, mem = region
        print(f"Write Memory: Region {region_name}, Offset {offset:#06X}")
        self.send_ack()
        self.state = self.STATE_WRITE_MEMORY_WAIT_N
        self.buffer = {'region': region, 'address': address}

    def handle_write_memory_n(self, byte):
        N = byte
        self.buffer['N'] = N
        self.state = self.STATE_WRITE_MEMORY_WAIT_N_COMP

    def handle_write_memory_n_complement(self, byte):
        N = self.buffer['N']
        complement = byte
        if (N ^ complement) != 0xFF:
            self.send_nack()
            print(f"Write Memory: N checksum invalid: {N ^ complement:#04X} != 0xFF")
            self.state = self.STATE_WAIT_COMMAND
            self.buffer = {}
            return
        self.send_ack()
        self.state = self.STATE_WRITE_MEMORY_WAIT_DATA
        self.buffer['num_bytes'] = N +1
        self.buffer['data'] = []
    
    def handle_write_memory_data(self, byte):
        self.buffer['data'].append(byte)
        if len(self.buffer['data']) == self.buffer['num_bytes'] +1:  # 数据 + checksum
            data = self.buffer['data'][:-1]
            received_checksum = self.buffer['data'][-1]
            calculated_checksum = calculate_checksum([self.buffer['N']] + list(data))
            if calculated_checksum != received_checksum:
                self.send_nack()
                print(f"Write Memory: Data checksum invalid: {calculated_checksum:#04X} != {received_checksum:#04X}")
                self.state = self.STATE_WAIT_COMMAND
                self.buffer = {}
                return
            address = self.buffer['address']
            region, offset, mem = self.buffer['region']
            end_address = offset + self.buffer['num_bytes']
            if end_address > len(mem):
                self.send_nack()
                print(f"Write Memory: End address {address + self.buffer['num_bytes']:#010X} exceeds memory region size")
                self.state = self.STATE_WAIT_COMMAND
                self.buffer = {}
                return
            mem[offset:end_address] = bytes(data)
            print(f"Write Memory: Written {self.buffer['num_bytes']} bytes to address {address:#010X}")
            self.send_ack()
            self.state = self.STATE_WAIT_COMMAND
            self.buffer = {}

    def handle_erase_memory_ack(self):
        """发送ACK后，进入等待页数部分"""
        self.state = self.STATE_ERASE_MEMORY_WAIT_N
        self.buffer = []

    def handle_erase_memory_n(self, byte):
        N = byte
        self.buffer['N'] = N
        if N == 0xFF:
            # 全局擦除
            self.state = 'ERASING_GLOBAL_MEMORY'
            self.erase_global_memory()
        else:
            self.state = self.STATE_ERASE_MEMORY_WAIT_PAGES
            self.buffer['num_pages'] = N +1

    def handle_erase_memory_pages(self, byte):
        self.buffer.setdefault('pages', []).append(byte)
        if len(self.buffer['pages']) == self.buffer['num_pages']:
            self.state = self.STATE_ERASE_MEMORY_WAIT_CHK

    def handle_erase_memory_checksum(self, byte):
        N = self.buffer['N']
        pages = self.buffer['pages']
        received_checksum = byte
        calculated_checksum = calculate_checksum([N] + pages)
        if calculated_checksum != received_checksum:
            self.send_nack()
            print(f"Erase Memory: Checksum invalid: {calculated_checksum:#04X} != {received_checksum:#04X}")
            self.state = self.STATE_WAIT_COMMAND
            self.buffer = {}
            return
        # 执行擦除操作
        PAGE_SIZE = 256  # 假设每页256字节
        for page in pages:
            address = FLASH_START + page * PAGE_SIZE
            region = get_memory_region(address)
            if not region:
                print(f"Erase Memory: Page {page} address {address:#010X} out of range")
                continue
            region_name, offset, mem = region
            if offset + PAGE_SIZE > len(mem):
                print(f"Erase Memory: Page {page} exceeds memory region size")
                continue
            mem[offset:offset + PAGE_SIZE] = b'\xFF' * PAGE_SIZE
            print(f"Erase Memory: Erased page {page} in region {region_name}")
        self.send_ack()
        self.state = self.STATE_WAIT_COMMAND
        self.buffer = {}

    def erase_global_memory(self):
        """执行全局擦除"""
        try:
            for region_name, start, size, mem in memory_regions:
                mem[:] = b'\xFF' * size
                print(f"Erase Memory: Global erase for region {region_name}")
            self.send_ack()
            self.state = self.STATE_WAIT_COMMAND
            self.buffer = {}
        except Exception as e:
            self.send_nack()
            print(f"Erase Global Memory Error: {e}")
            self.state = self.STATE_WAIT_COMMAND
            self.buffer = {}

    def handle_command(self, command):
        """根据命令码处理命令"""
        if command == 0x00:  # Get
            print("Processing Get Command")
            self.handle_get_command()
        elif command == 0x11:  # Read Memory
            print("Processing Read Memory Command")
            self.handle_read_memory_ack()
        elif command == 0x31:  # Write Memory
            print("Processing Write Memory Command")
            self.handle_write_memory_ack()
        elif command == 0x43:  # Erase Memory
            print("Processing Erase Memory Command")
            self.handle_erase_memory_ack()
        else:
            self.send_nack()
            print(f"Unsupported Command: {command:#04X}")

    def listen(self):
        """监听串口并处理命令"""
        print(f"Listening on {SERIAL_PORT} at {BAUDRATE} baud rate.")
        while True:
            try:
                byte = self.ser.read(1)
                if not byte:
                    continue
                byte = byte[0]
                if self.state == self.STATE_WAIT_INIT:
                    if byte == 0x7F:
                        print("Initialization frame received.")
                        self.send_ack()
                        self.state = self.STATE_WAIT_COMMAND
                    else:
                        print(f"Unknown initialization byte: {byte:#04X}")
                elif self.state == self.STATE_WAIT_COMMAND:
                    self.current_command = byte
                    self.state = self.STATE_WAIT_COMMAND_COMP
                elif self.state == self.STATE_WAIT_COMMAND_COMP:
                    complement = byte
                    if (self.current_command ^ complement) != 0xFF:
                        self.send_nack()
                        print(f"Command {self.current_command:#04X} complement {complement:#04X} mismatch")
                        self.state = self.STATE_WAIT_COMMAND
                        self.current_command = None
                    else:
                        self.send_ack()
                        self.handle_command(self.current_command)
                elif self.state == self.STATE_READ_MEMORY_WAIT_ADDR:
                    self.handle_read_memory_address(byte)
                elif self.state == self.STATE_READ_MEMORY_WAIT_ADDR_CHK:
                    self.handle_read_memory_address_checksum(byte)
                elif self.state == self.STATE_READ_MEMORY_WAIT_N:
                    self.handle_read_memory_n(byte)
                elif self.state == self.STATE_READ_MEMORY_WAIT_N_COMP:
                    self.handle_read_memory_n_complement(byte)
                elif self.state == self.STATE_WRITE_MEMORY_WAIT_ADDR:
                    self.handle_write_memory_address(byte)
                elif self.state == self.STATE_WRITE_MEMORY_WAIT_ADDR_CHK:
                    self.handle_write_memory_address_checksum(byte)
                elif self.state == self.STATE_WRITE_MEMORY_WAIT_N:
                    self.handle_write_memory_n(byte)
                elif self.state == self.STATE_WRITE_MEMORY_WAIT_N_COMP:
                    self.handle_write_memory_n_complement(byte)
                elif self.state == self.STATE_WRITE_MEMORY_WAIT_DATA:
                    self.handle_write_memory_data(byte)
                elif self.state == self.STATE_WRITE_MEMORY_WAIT_DATA_CHK:
                    self.handle_write_memory_data_checksum(byte)
                elif self.state == self.STATE_ERASE_MEMORY_WAIT_N:
                    self.handle_erase_memory_n(byte)
                elif self.state == self.STATE_ERASE_MEMORY_WAIT_PAGES:
                    self.handle_erase_memory_pages(byte)
                elif self.state == self.STATE_ERASE_MEMORY_WAIT_CHK:
                    self.handle_erase_memory_checksum(byte)
                elif self.state == 'SENDING_READ_MEMORY_DATA':
                    pass  # 数据已经发送，无需处理
                elif self.state == 'ERASING_GLOBAL_MEMORY':
                    pass  # 全局擦除已经处理，无需处理
                else:
                    print(f"Unknown state: {self.state}")
            except Exception as e:
                self.send_nack()
                print(f"Serial Error: {e}")
                self.state = self.STATE_WAIT_INIT
                self.current_command = None
                self.buffer = []
                time.sleep(1)

if __name__ == "__main__":
    simulator = STM32Simulator(SERIAL_PORT, BAUDRATE, TIMEOUT)
    simulator_thread = threading.Thread(target=simulator.listen, daemon=True)
    simulator_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Exiting...")
