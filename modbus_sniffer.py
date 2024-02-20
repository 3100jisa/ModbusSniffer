#!/usr/bin/env python

"""
Python modbus sniffer implementation
---------------------------------------------------------------------------

The following is a modbus RTU sniffer program,
made without the use of modbus specific library.
"""
# --------------------------------------------------------------------------- #
# import the various needed libraries
# --------------------------------------------------------------------------- #
import signal
import sys
import getopt
import logging
import serial
from config import *

# --------------------------------------------------------------------------- #
# configure the logging system
# --------------------------------------------------------------------------- #
class LogFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.INFO:
            self._style._fmt = "%(asctime)-15s %(message)s"
        elif record.levelno == logging.DEBUG:
            self._style._fmt = f"%(asctime)-15s \033[36m%(levelname)-8s\033[0m: %(message)s"
        else:
            color = {
                logging.WARNING: 33,
                logging.ERROR: 31,
                logging.FATAL: 31,
            }.get(record.levelno, 0)
            self._style._fmt = f"%(asctime)-15s \033[{color}m%(levelname)-8s %(threadName)-15s-%(module)-15s:%(lineno)-8s\033[0m: %(message)s"
        return super().format(record)


log = logging.getLogger(__name__)  # added module name
logging.basicConfig(filename='example.log', filemode='w', encoding='utf-8', errors='strict', level=logging.INFO)  # logging to file, write always (overwrite), strict character checking
handler = logging.StreamHandler()
handler.setFormatter(LogFormatter())
log.setLevel(logging.INFO)
log.addHandler(handler)


# --------------------------------------------------------------------------- #
# declare the sniffer
# --------------------------------------------------------------------------- #
class SerialSnooper:

    def __init__(self, serial_port_no, serial_port_baud_rate=57600, serial_port_parity=serial.PARITY_EVEN,
                 serial_port_timeout=0):
        self.port = serial_port_no
        self.baud = serial_port_baud_rate
        self.timeout = serial_port_timeout

        log.info("Opening serial interface: \n" + "\tport: {} \n".format(serial_port_no) + "\tbaudrate: {}\n".format(
            serial_port_baud_rate) + "\tbytesize: 8\n" + "\tparity: even\n" + "\tstopbits: 1\n" + "\ttimeout: {}\n".format(
            serial_port_timeout))
        self.connection = serial.Serial(port=serial_port_no, baudrate=serial_port_baud_rate, bytesize=serial.EIGHTBITS,
                                        parity=serial_port_parity,
                                        stopbits=serial.STOPBITS_ONE, timeout=serial_port_timeout)
        log.debug(self.connection)

        # Global variables
        self.data = bytearray(0)
        self.trash_data = False
        self.trash_data_f = bytearray(0)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def open(self):
        self.connection.open()

    def close(self):
        self.connection.close()

    def read_raw(self, n=1):
        return self.connection.read(n)

    # --------------------------------------------------------------------------- #
    # Bufferise the data and call the decoder if the interframe timeout occur.
    # --------------------------------------------------------------------------- #
    def process_data(self, data_to_process):
        if len(data_to_process) <= 0:
            if len(self.data) > 2:
                self.data = self.decode_modbus(self.data)
            return
        for dat in data_to_process:
            self.data.append(dat)

    # --------------------------------------------------------------------------- #
    # Debuffer and decode the modbus frames (Request, Response, Exception)
    # --------------------------------------------------------------------------- #
    def decode_modbus(self, input_data):
        modbus_data = input_data
        buffer_index = 0

        while True:
            unit_identifier = 0
            function_code = 0
            read_address = 0
            read_quantity = 0
            read_byte_count = 0
            read_data = bytearray(0)
            write_address = 0
            write_quantity = 0
            write_byte_count = 0
            write_data = bytearray(0)
            exception_code = 0
            crc16 = 0
            request = False
            response = False
            error = False
            need_more_data = False

            frame_start_index = buffer_index

            id_format = get_configuration().get_slave_id_format()

            if len(modbus_data) > (frame_start_index + 2):
                # Unit Identifier (Slave Address)
                unit_identifier = modbus_data[buffer_index]
                buffer_index += 1
                # Function Code
                function_code = modbus_data[buffer_index]
                buffer_index += 1
                # FC01 (0x01) Read Coils / FC02 (0x02) Read Discrete Inputs
                if function_code in (1, 2):
                    # Request size: UnitIdentifier (1) + FunctionCode (1) + ReadAddress (2) + ReadQuantity (2) + CRC (2)
                    expected_length = 8  # 8
                    if len(modbus_data) >= (frame_start_index + expected_length):
                        buffer_index = frame_start_index + 2
                        # Read Address (2)
                        read_address = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                        buffer_index += 2
                        # Read Quantity (2)
                        read_quantity = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                        buffer_index += 2
                        # CRC16 (2)
                        crc16 = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                        met_crc16 = self.calcCRC16(modbus_data, buffer_index)
                        buffer_index += 2
                        if crc16 == met_crc16:
                            if self.trash_data:
                                self.trash_data = False
                                self.trash_data_f += "]"
                                log.info(self.trash_data_f)
                            request = True
                            response = False
                            error = False
                            if function_code == 1:
                                function_code_message = 'Read Coils'
                            else:
                                function_code_message = 'Read Discrete Inputs'
                            format_string = (
                                    "Master\t\t-> ID: " + id_format +
                                    ", {}: 0x{:02x}, Read address: {}, Read Quantity: {}")
                            log.info(format_string.format(unit_identifier, function_code_message, function_code,
                                                          read_address, read_quantity))
                            modbus_data = modbus_data[buffer_index:]
                            buffer_index = 0
                    else:
                        need_more_data = True
                    if request is False:
                        # Response size:
                        # UnitIdentifier (1) + FunctionCode (1) + ReadByteCount (1) + ReadData (n) + CRC (2)
                        expected_length = 7  # 5 + n (n >= 2)
                        if len(modbus_data) >= (frame_start_index + expected_length):
                            buffer_index = frame_start_index + 2
                            # Read Byte Count (1)
                            read_byte_count = modbus_data[buffer_index]
                            buffer_index += 1
                            expected_length = (5 + read_byte_count)
                            if len(modbus_data) >= (frame_start_index + expected_length):
                                # Read Data (n)
                                index = 1
                                while index <= read_byte_count:
                                    read_data.append(modbus_data[buffer_index])
                                    buffer_index += 1
                                    index += 1
                                # CRC16 (2)
                                crc16 = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                                met_crc16 = self.calcCRC16(modbus_data, buffer_index)
                                buffer_index += 2
                                if crc16 == met_crc16:
                                    if self.trash_data:
                                        self.trash_data = False
                                        self.trash_data_f += "]"
                                        log.info(self.trash_data_f)
                                    request = False
                                    response = True
                                    error = False
                                    if function_code == 1:
                                        function_code_message = 'Read Coils'
                                    else:
                                        function_code_message = 'Read Discrete Inputs'
                                    format_string = "Slave\t-> ID: " + id_format + ", {}: 0x{:02x}, Read byte count: {}, Read data: [{}]"
                                    log.info(format_string.format(
                                        unit_identifier, function_code_message, function_code, read_byte_count,
                                        " ".join(["{:02x}".format(x) for x in read_data])))
                                    modbus_data = modbus_data[buffer_index:]
                                    buffer_index = 0
                            else:
                                need_more_data = True
                        else:
                            need_more_data = True

                # FC03 (0x03) Read Holding Registers / FC04 (0x04) Read Input Registers
                elif function_code in (3, 4):
                    # Request size: UnitIdentifier (1) + FunctionCode (1) + ReadAddress (2) + ReadQuantity (2) + CRC (2)
                    expected_length = 8  # 8
                    if len(modbus_data) >= (frame_start_index + expected_length):
                        buffer_index = frame_start_index + 2
                        # Read Address (2)
                        read_address = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                        buffer_index += 2
                        # Read Quantity (2)
                        read_quantity = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                        buffer_index += 2
                        # CRC16 (2)
                        crc16 = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                        met_crc16 = self.calcCRC16(modbus_data, buffer_index)
                        buffer_index += 2
                        if crc16 == met_crc16:
                            if self.trash_data:
                                self.trash_data = False
                                self.trash_data_f += "]"
                                log.info(self.trash_data_f)
                            request = True
                            response = False
                            error = False
                            if function_code == 3:
                                function_code_message = 'Read Holding Registers'
                            else:
                                function_code_message = 'Read Input Registers'
                            format_string = "Master\t-> ID: " + id_format + ", {}: 0x{:02x}, Read address: {}, Read Quantity: {}"
                            log.info(format_string.format(
                                unit_identifier, function_code_message, function_code, read_address, read_quantity))
                            modbus_data = modbus_data[buffer_index:]
                            buffer_index = 0
                    else:
                        need_more_data = True
                    if request is False:
                        # Response size:
                        # UnitIdentifier (1) + FunctionCode (1) + ReadByteCount (1) + ReadData (n) + CRC (2)
                        expected_length = 7  # 5 + n (n >= 2)
                        if len(modbus_data) >= (frame_start_index + expected_length):
                            buffer_index = frame_start_index + 2
                            # Read Byte Count (1)
                            read_byte_count = modbus_data[buffer_index]
                            buffer_index += 1
                            expected_length = (5 + read_byte_count)
                            if len(modbus_data) >= (frame_start_index + expected_length):
                                # Read Data (n)
                                index = 1
                                while index <= read_byte_count:
                                    read_data.append(modbus_data[buffer_index])
                                    buffer_index += 1
                                    index += 1
                                # CRC16 (2)
                                crc16 = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                                met_crc16 = self.calcCRC16(modbus_data, buffer_index)
                                buffer_index += 2
                                if crc16 == met_crc16:
                                    if self.trash_data:
                                        self.trash_data = False
                                        self.trash_data_f += "]"
                                        log.info(self.trash_data_f)
                                    request = False
                                    response = True
                                    error = False
                                    if function_code == 3:
                                        function_code_message = 'Read Holding Registers'
                                    else:
                                        function_code_message = 'Read Input Registers'
                                    format_string = "Slave\t-> ID: " + id_format + ", {}: 0x{:02x}, Read byte count: {}, Read data: [{}]"
                                    log.info(format_string.format(
                                        unit_identifier, function_code_message, function_code, read_byte_count,
                                        " ".join(["{:02x}".format(x) for x in read_data])))
                                    modbus_data = modbus_data[buffer_index:]
                                    buffer_index = 0
                            else:
                                need_more_data = True
                        else:
                            need_more_data = True

                # FC05 (0x05) Write Single Coil
                elif function_code == 5:
                    # Request size: UnitIdentifier (1) + FunctionCode (1) + WriteAddress (2) + WriteData (2) + CRC (2)
                    expected_length = 8
                    if len(modbus_data) >= (frame_start_index + expected_length):
                        buffer_index = frame_start_index + 2
                        # Write Address (2)
                        write_address = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                        buffer_index += 2
                        # Write Data (2)
                        write_data.append(modbus_data[buffer_index])
                        buffer_index += 1
                        write_data.append(modbus_data[buffer_index])
                        buffer_index += 1
                        # CRC16 (2)
                        crc16 = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                        met_crc16 = self.calcCRC16(modbus_data, buffer_index)
                        buffer_index += 2
                        if crc16 == met_crc16:
                            if self.trash_data:
                                self.trash_data = False
                                self.trash_data_f += "]"
                                log.info(self.trash_data_f)
                            request = True
                            response = False
                            error = False
                            format_string = "Master\t-> ID: " + id_format + ", Write Single Coil: 0x{:02x}, Write address: {}, Write data: [{}]"
                            log.info(format_string.format(
                                unit_identifier, function_code, write_address,
                                " ".join(["{:02x}".format(x) for x in write_data])))
                            modbus_data = modbus_data[buffer_index:]
                            buffer_index = 0
                    else:
                        need_more_data = True

                    if request is False:
                        # Response size: UnitIdentifier (1) + FunctionCode (1) + WriteAddress (2) + CRC (2)
                        expected_length = 6
                        if len(modbus_data) >= (frame_start_index + expected_length):
                            buffer_index = frame_start_index + 2
                            # Write Address (2)
                            write_address = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                            buffer_index += 2
                            # CRC16 (2)
                            crc16 = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                            met_crc16 = self.calcCRC16(modbus_data, buffer_index)
                            buffer_index += 2
                            if crc16 == met_crc16:
                                if self.trash_data:
                                    self.trash_data = False
                                    self.trash_data_f += "]"
                                    log.info(self.trash_data_f)
                                request = False
                                response = True
                                error = False
                                format_string = "Slave\t-> ID: " + id_format + ", Write Single Coil: 0x{:02x}, Write address: {}"
                                log.info(format_string.format(
                                    unit_identifier, function_code, write_address))
                                modbus_data = modbus_data[buffer_index:]
                                buffer_index = 0
                        else:
                            need_more_data = True

                # FC06 (0x06) Write Single Register
                elif function_code == 6:
                    # Request size: UnitIdentifier (1) + FunctionCode (1) + WriteAddress (2) + WriteData (2) + CRC (2)
                    expected_length = 8
                    if len(modbus_data) >= (frame_start_index + expected_length):
                        buffer_index = frame_start_index + 2
                        # Write Address (2)
                        write_address = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                        buffer_index += 2
                        # Write Data (2)
                        write_data.append(modbus_data[buffer_index])
                        buffer_index += 1
                        write_data.append(modbus_data[buffer_index])
                        buffer_index += 1
                        # CRC16 (2)
                        crc16 = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                        met_crc16 = self.calcCRC16(modbus_data, buffer_index)
                        buffer_index += 2
                        if crc16 == met_crc16:
                            if self.trash_data:
                                self.trash_data = False
                                self.trash_data_f += "]"
                                log.info(self.trash_data_f)
                            request = True
                            response = False
                            error = False
                            format_string = "Master\t-> ID: " + id_format + ", Write Single Register: 0x{:02x}, Write address: {}, Write data: [{}]"
                            log.info(
                                format_string.format(
                                    unit_identifier, function_code, write_address,
                                    " ".join(["{:02x}".format(x) for x in write_data])))
                            modbus_data = modbus_data[buffer_index:]
                            buffer_index = 0
                    else:
                        need_more_data = True

                    if request is False:
                        # Response size:
                        # UnitIdentifier (1) + FunctionCode (1) + WriteAddress (2) + WriteData (2) + CRC (2)
                        expected_length = 8
                        if len(modbus_data) >= (frame_start_index + expected_length):
                            buffer_index = frame_start_index + 2
                            # Write Address (2)
                            write_address = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                            buffer_index += 2
                            # Write Data (2)
                            write_data.append(modbus_data[buffer_index])
                            buffer_index += 1
                            write_data.append(modbus_data[buffer_index])
                            buffer_index += 1
                            # CRC16 (2)
                            crc16 = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                            met_crc16 = self.calcCRC16(modbus_data, buffer_index)
                            buffer_index += 2
                            if crc16 == met_crc16:
                                if self.trash_data:
                                    self.trash_data = False
                                    self.trash_data_f += "]"
                                    log.info(self.trash_data_f)
                                request = False
                                response = True
                                error = False
                                format_string = "Slave\t-> ID: " + id_format + ", Write Single Register: 0x{:02x}, Write address: {}, Write data: [{}]"
                                log.info(
                                    format_string.format(
                                        unit_identifier, function_code, write_address,
                                        " ".join(["{:02x}".format(x) for x in write_data])))
                                modbus_data = modbus_data[buffer_index:]
                                buffer_index = 0
                        else:
                            need_more_data = True

                # FC07 (0x07) Read Exception Status (Serial Line only)
                # elif (functionCode == 7):

                # FC08 (0x08) Diagnostics (Serial Line only)
                # elif (functionCode == 8):

                # FC11 (0x0B) Get Comm Event Counter (Serial Line only)
                # elif (functionCode == 11):

                # FC12 (0x0C) Get Comm Event Log (Serial Line only)
                # elif (functionCode == 12):

                # FC15 (0x0F) Write Multiple Coils
                elif function_code == 15:
                    # Request size:
                    # UnitIdentifier (1) + FunctionCode (1) + WriteAddress (2) + WriteQuantity (2) + WriteByteCount (1) + WriteData (n) + CRC (2)
                    expected_length = 10  # n >= 1
                    if len(modbus_data) >= (frame_start_index + expected_length):
                        buffer_index = frame_start_index + 2
                        # Write Address (2)
                        write_address = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                        buffer_index += 2
                        # Write Quantity (2)
                        write_quantity = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                        buffer_index += 2
                        # Write Byte Count (1)
                        write_byte_count = modbus_data[buffer_index]
                        buffer_index += 1
                        expected_length = (9 + write_byte_count)
                        if len(modbus_data) >= (frame_start_index + expected_length):
                            # Write Data (n)
                            index = 1
                            while index <= write_byte_count:
                                write_data.append(modbus_data[buffer_index])
                                buffer_index += 1
                                index += 1
                            # CRC16 (2)
                            crc16 = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                            met_crc16 = self.calcCRC16(modbus_data, buffer_index)
                            buffer_index += 2
                            if crc16 == met_crc16:
                                if self.trash_data:
                                    self.trash_data = False
                                    self.trash_data_f += "]"
                                    log.info(self.trash_data_f)
                                request = True
                                response = False
                                error = False
                                format_string = "Master\t-> ID: " + id_format + ", Write Multiple Coils: 0x{:02x}, Write address: {}, Write quantity: {}, Write data: [{}]"
                                log.info(
                                    format_string.format(
                                        unit_identifier, function_code, write_address, write_quantity,
                                        " ".join(["{:02x}".format(x) for x in write_data])))
                                modbus_data = modbus_data[buffer_index:]
                                buffer_index = 0
                        else:
                            need_more_data = True
                    else:
                        need_more_data = True
                    if request is False:
                        # Response size:
                        # UnitIdentifier (1) + FunctionCode (1) + WriteAddress (2) + WriteQuantity (2) + CRC (2)
                        expected_length = 8
                        if len(modbus_data) >= (frame_start_index + expected_length):
                            buffer_index = frame_start_index + 2
                            # Write Address (2)
                            write_address = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                            buffer_index += 2
                            # Write Quantity (2)
                            write_quantity = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                            buffer_index += 2
                            # CRC16 (2)
                            crc16 = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                            met_crc16 = self.calcCRC16(modbus_data, buffer_index)
                            buffer_index += 2
                            if crc16 == met_crc16:
                                if self.trash_data:
                                    self.trash_data = False
                                    self.trash_data_f += "]"
                                    log.info(self.trash_data_f)
                                request = False
                                response = True
                                error = False
                                format_string = "Slave\t-> ID: " + id_format + ", Write Multiple Coils: 0x{:02x}, Write address: {}, Write Quantity: {}"
                                log.info(
                                    format_string.format(
                                        unit_identifier, function_code, write_address, write_quantity))
                                modbus_data = modbus_data[buffer_index:]
                                buffer_index = 0
                        else:
                            need_more_data = True

                # FC16 (0x10) Write Multiple registers
                elif function_code == 16:
                    # Request size:
                    # UnitIdentifier (1) + FunctionCode (1) + WriteAddress (2) + WriteQuantity (2) + WriteByteCount (1) + WriteData (n) + CRC (2)
                    expected_length = 11  # n >= 2
                    if len(modbus_data) >= (frame_start_index + expected_length):
                        buffer_index = frame_start_index + 2
                        # Write Address (2)
                        write_address = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                        buffer_index += 2
                        # Write Quantity (2)
                        write_quantity = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                        buffer_index += 2
                        # Write Byte Count (1)
                        write_byte_count = modbus_data[buffer_index]
                        buffer_index += 1
                        expected_length = (9 + write_byte_count)
                        if len(modbus_data) >= (frame_start_index + expected_length):
                            # Write Data (n)
                            index = 1
                            while index <= write_byte_count:
                                write_data.append(modbus_data[buffer_index])
                                buffer_index += 1
                                index += 1
                            # CRC16 (2)
                            crc16 = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                            met_crc16 = self.calcCRC16(modbus_data, buffer_index)
                            buffer_index += 2
                            if crc16 == met_crc16:
                                if self.trash_data:
                                    self.trash_data = False
                                    self.trash_data_f += "]"
                                    log.info(self.trash_data_f)
                                request = True
                                response = False
                                error = False
                                format_string = "Master\t-> ID: " + id_format + ", Write Multiple registers: 0x{:02x}, Write address: {}, Write quantity: {}, Write data: [{}]"
                                log.info(
                                    format_string.format(
                                        unit_identifier, function_code, write_address, write_quantity,
                                        " ".join(["{:02x}".format(x) for x in write_data])))
                                modbus_data = modbus_data[buffer_index:]
                                buffer_index = 0
                        else:
                            need_more_data = True
                    else:
                        need_more_data = True
                    if request is False:
                        # Response size:
                        # UnitIdentifier (1) + FunctionCode (1) + WriteAddress (2) + WriteQuantity (2) + CRC (2)
                        expected_length = 8
                        if len(modbus_data) >= (frame_start_index + expected_length):
                            buffer_index = frame_start_index + 2
                            # Write Address (2)
                            write_address = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                            buffer_index += 2
                            # Write Quantity (2)
                            write_quantity = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                            buffer_index += 2
                            # CRC16 (2)
                            crc16 = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                            met_crc16 = self.calcCRC16(modbus_data, buffer_index)
                            buffer_index += 2
                            if crc16 == met_crc16:
                                if self.trash_data:
                                    self.trash_data = False
                                    self.trash_data_f += "]"
                                    log.info(self.trash_data_f)
                                request = False
                                response = True
                                error = False
                                format_string = "Slave\t-> ID: " + id_format + ", Write Multiple registers: 0x{:02x}, Write address: {}, Write quantity: {}"
                                log.info(
                                    format_string.format(
                                        unit_identifier, function_code, write_address, write_quantity))
                                modbus_data = modbus_data[buffer_index:]
                                buffer_index = 0
                        else:
                            need_more_data = True
                    if (request is False) & (response is False):
                        # Error size: UnitIdentifier (1) + FunctionCode (1) + ExceptionCode (1) + CRC (2)
                        expected_length = 5  # 5
                        if len(modbus_data) >= (frame_start_index + expected_length):
                            buffer_index = frame_start_index + 2
                            # Exception Code (1)
                            exception_code = modbus_data[buffer_index]
                            buffer_index += 1

                            # CRC16 (2)
                            crc16 = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                            met_crc16 = self.calcCRC16(modbus_data, buffer_index)
                            buffer_index += 2
                            if crc16 == met_crc16:
                                if self.trash_data:
                                    self.trash_data = False
                                    self.trash_data_f += "]"
                                    log.info(self.trash_data_f)
                                request = False
                                response = False
                                error = True
                                format_string = "Slave\t-> ID: " + id_format + ", Write Multiple registers: 0x{:02x}, Exception: {}"
                                log.info(format_string.format(
                                    unit_identifier, function_code, exception_code))
                                modbus_data = modbus_data[buffer_index:]
                                buffer_index = 0
                        else:
                            need_more_data = True

                # FC17 (0x11) Report Server ID (Serial Line only)
                # elif (functionCode == 17):

                # FC20 (0x14) Read File Record
                # elif (functionCode == 20):

                # FC21 (0x15) Write File Record
                # elif (functionCode == 21):

                # FC22 (0x16) Mask Write Register
                # elif (functionCode == 22):

                # FC23 (0x17) Read/Write Multiple registers
                elif function_code == 23:
                    # Request size:
                    # UnitIdentifier (1) + FunctionCode (1) + ReadAddress (2) + ReadQuantity (2) + WriteAddress (2) + WriteQuantity (2) + WriteByteCount (1) + WriteData (n) + CRC (2)
                    expected_length = 15  # 13 + n (n >= 2)
                    if len(modbus_data) >= (frame_start_index + expected_length):
                        buffer_index = frame_start_index + 2
                        # Read Address (2)
                        read_address = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                        buffer_index += 2
                        # Read Quantity (2)
                        read_quantity = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                        buffer_index += 2
                        # Write Address (2)
                        write_address = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                        buffer_index += 2
                        # Write Quantity (2)
                        write_quantity = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                        buffer_index += 2
                        # Write Byte Count (1)
                        write_byte_count = modbus_data[buffer_index]
                        buffer_index += 1
                        expected_length = (13 + write_byte_count)
                        if len(modbus_data) >= (frame_start_index + expected_length):
                            # Write Data (n)
                            index = 1
                            while index <= write_byte_count:
                                write_data.append(modbus_data[buffer_index])
                                buffer_index += 1
                                index += 1
                            # CRC16 (2)
                            crc16 = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                            met_crc16 = self.calcCRC16(modbus_data, buffer_index)
                            buffer_index += 2
                            if crc16 == met_crc16:
                                if self.trash_data:
                                    self.trash_data = False
                                    self.trash_data_f += "]"
                                    log.info(self.trash_data_f)
                                request = True
                                response = False
                                error = False
                                format_string = "Master\t-> ID: " + id_format + ", Read/Write Multiple registers: 0x{:02x}, Read address: {}, Read Quantity: {}, Write address: {}, Write quantity: {}, Write data: [{}]"
                                log.info(
                                    format_string.format(
                                        unit_identifier, function_code, read_address, write_address, read_quantity,
                                        write_quantity, " ".join(["{:02x}".format(x) for x in write_data])))
                                modbus_data = modbus_data[buffer_index:]
                                buffer_index = 0
                        else:
                            need_more_data = True
                    else:
                        need_more_data = True
                    if not request:
                        # Response size:
                        # UnitIdentifier (1) + FunctionCode (1) + ReadByteCount (1) + ReadData (n) + CRC (2)
                        expected_length = 7  # 5 + n (n >= 2)
                        if len(modbus_data) >= (frame_start_index + expected_length):
                            buffer_index = frame_start_index + 2
                            # Read Byte Count (1)
                            read_byte_count = modbus_data[buffer_index]
                            buffer_index += 1
                            expected_length = (5 + read_byte_count)
                            if len(modbus_data) >= (frame_start_index + expected_length):
                                # Read Data (n)
                                index = 1
                                while index <= read_byte_count:
                                    read_data.append(modbus_data[buffer_index])
                                    buffer_index += 1
                                    index += 1
                                # CRC16 (2)
                                crc16 = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                                met_crc16 = self.calcCRC16(modbus_data, buffer_index)
                                buffer_index += 2
                                if crc16 == met_crc16:
                                    if self.trash_data:
                                        self.trash_data = False
                                        self.trash_data_f += "]"
                                        log.info(self.trash_data_f)
                                    request = False
                                    response = True
                                    error = False
                                    format_string = "Slave\t-> ID: " + id_format + ", Read/Write Multiple registers: 0x{:02x}, Read byte count: {}, Read data: [{}]"
                                    log.info(
                                        format_string.format(
                                            unit_identifier, function_code, read_byte_count,
                                            " ".join(["{:02x}".format(x) for x in read_data])))
                                    modbus_data = modbus_data[buffer_index:]
                                    buffer_index = 0
                            else:
                                need_more_data = True
                        else:
                            need_more_data = True

                # FC24 (0x18) Read FIFO Queue
                # elif (functionCode == 24):

                # FC43 ( 0x2B) Encapsulated Interface Transport
                # elif (functionCode == 43):

                # FC80+ ( 0x80 + FC) Exception
                elif function_code >= 0x80:
                    # Error size: UnitIdentifier (1) + FunctionCode (1) + ExceptionCode (1) + CRC (2)
                    expected_length = 5  # 5
                    if len(modbus_data) >= (frame_start_index + expected_length):
                        buffer_index = frame_start_index + 2
                        # Exception Code (1)
                        exception_code = modbus_data[buffer_index]
                        buffer_index += 1
                        # CRC16 (2)
                        crc16 = (modbus_data[buffer_index] * 0x0100) + modbus_data[buffer_index + 1]
                        met_crc16 = self.calcCRC16(modbus_data, buffer_index)
                        buffer_index += 2
                        if crc16 == met_crc16:
                            if self.trash_data:
                                self.trash_data = False
                                self.trash_data_f += "]"
                                log.info(self.trash_data_f)
                            request = False
                            response = False
                            error = True
                            format_string = "Slave\t-> ID: " + id_format + ", Exception: 0x{:02x}, Code: {}"
                            log.info(
                                format_string.format(unit_identifier, function_code,
                                                     exception_code))
                            modbus_data = modbus_data[buffer_index:]
                            buffer_index = 0
                    else:
                        need_more_data = True
            else:
                need_more_data = True
            if need_more_data:
                return modbus_data
            elif (request is False) & (response is False) & (error is False):
                if self.trash_data:
                    self.trash_data_f += " {:02x}".format(modbus_data[frame_start_index])
                else:
                    self.trash_data = True
                    self.trash_data_f = "\033[33mWarning \033[0m: Ignoring data: [{:02x}".format(
                        modbus_data[frame_start_index])
                buffer_index = frame_start_index + 1
                modbus_data = modbus_data[buffer_index:]
                buffer_index = 0

    # --------------------------------------------------------------------------- #
    # Calculate the modbus CRC
    # --------------------------------------------------------------------------- #
    def calcCRC16(self, data, size):
        crc_hi = 0XFF
        crc_lo = 0xFF

        crc_hi_table = [0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
                      0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
                      0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
                      0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
                      0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
                      0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
                      0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
                      0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
                      0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
                      0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
                      0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
                      0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
                      0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
                      0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
                      0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
                      0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
                      0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
                      0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
                      0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
                      0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
                      0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
                      0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
                      0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
                      0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
                      0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
                      0x80, 0x41, 0x00, 0xC1, 0x81, 0x40]

        crc_lo_table = [0x00, 0xC0, 0xC1, 0x01, 0xC3, 0x03, 0x02, 0xC2, 0xC6, 0x06,
                      0x07, 0xC7, 0x05, 0xC5, 0xC4, 0x04, 0xCC, 0x0C, 0x0D, 0xCD,
                      0x0F, 0xCF, 0xCE, 0x0E, 0x0A, 0xCA, 0xCB, 0x0B, 0xC9, 0x09,
                      0x08, 0xC8, 0xD8, 0x18, 0x19, 0xD9, 0x1B, 0xDB, 0xDA, 0x1A,
                      0x1E, 0xDE, 0xDF, 0x1F, 0xDD, 0x1D, 0x1C, 0xDC, 0x14, 0xD4,
                      0xD5, 0x15, 0xD7, 0x17, 0x16, 0xD6, 0xD2, 0x12, 0x13, 0xD3,
                      0x11, 0xD1, 0xD0, 0x10, 0xF0, 0x30, 0x31, 0xF1, 0x33, 0xF3,
                      0xF2, 0x32, 0x36, 0xF6, 0xF7, 0x37, 0xF5, 0x35, 0x34, 0xF4,
                      0x3C, 0xFC, 0xFD, 0x3D, 0xFF, 0x3F, 0x3E, 0xFE, 0xFA, 0x3A,
                      0x3B, 0xFB, 0x39, 0xF9, 0xF8, 0x38, 0x28, 0xE8, 0xE9, 0x29,
                      0xEB, 0x2B, 0x2A, 0xEA, 0xEE, 0x2E, 0x2F, 0xEF, 0x2D, 0xED,
                      0xEC, 0x2C, 0xE4, 0x24, 0x25, 0xE5, 0x27, 0xE7, 0xE6, 0x26,
                      0x22, 0xE2, 0xE3, 0x23, 0xE1, 0x21, 0x20, 0xE0, 0xA0, 0x60,
                      0x61, 0xA1, 0x63, 0xA3, 0xA2, 0x62, 0x66, 0xA6, 0xA7, 0x67,
                      0xA5, 0x65, 0x64, 0xA4, 0x6C, 0xAC, 0xAD, 0x6D, 0xAF, 0x6F,
                      0x6E, 0xAE, 0xAA, 0x6A, 0x6B, 0xAB, 0x69, 0xA9, 0xA8, 0x68,
                      0x78, 0xB8, 0xB9, 0x79, 0xBB, 0x7B, 0x7A, 0xBA, 0xBE, 0x7E,
                      0x7F, 0xBF, 0x7D, 0xBD, 0xBC, 0x7C, 0xB4, 0x74, 0x75, 0xB5,
                      0x77, 0xB7, 0xB6, 0x76, 0x72, 0xB2, 0xB3, 0x73, 0xB1, 0x71,
                      0x70, 0xB0, 0x50, 0x90, 0x91, 0x51, 0x93, 0x53, 0x52, 0x92,
                      0x96, 0x56, 0x57, 0x97, 0x55, 0x95, 0x94, 0x54, 0x9C, 0x5C,
                      0x5D, 0x9D, 0x5F, 0x9F, 0x9E, 0x5E, 0x5A, 0x9A, 0x9B, 0x5B,
                      0x99, 0x59, 0x58, 0x98, 0x88, 0x48, 0x49, 0x89, 0x4B, 0x8B,
                      0x8A, 0x4A, 0x4E, 0x8E, 0x8F, 0x4F, 0x8D, 0x4D, 0x4C, 0x8C,
                      0x44, 0x84, 0x85, 0x45, 0x87, 0x47, 0x46, 0x86, 0x82, 0x42,
                      0x43, 0x83, 0x41, 0x81, 0x80, 0x40]

        index = 0
        while index < size:
            crc = crc_hi ^ data[index]
            crc_hi = crc_lo ^ crc_hi_table[crc]
            crc_lo = crc_lo_table[crc]
            index += 1

        met_crc16 = (crc_hi * 0x0100) + crc_lo
        return met_crc16


# --------------------------------------------------------------------------- #
# Print the usage help
# --------------------------------------------------------------------------- #
def print_help(baud, timeout_for_info):
    if timeout_for_info is None:
        timeout_for_info = calculate_timeout(baud)
    print("\nUsage:")
    print("  python modbus_sniffer.py [arguments]")
    print("")
    print("Arguments:")
    print("  -p, --port        select the serial port (Required)")
    print("  -b, --baudrate    set the communication baud rate, default = {} (Option)".format(baud))
    print("  -t, --timeout     override the calculated inter frame timeout, default = {}s (Option)".format(
        timeout_for_info))
    print("  -h, --help        print the documentation")
    print("")
    print("  python3 {} -p <serial port> [-b baudrate, default={}] [-t timeout, default={}]".format(sys.argv[0], baud,
                                                                                                    timeout_for_info))


# --------------------------------------------------------------------------- #
# Calculate the timeout with the baud rate
# --------------------------------------------------------------------------- #
def calculate_timeout(configured_baud_rate):
    # Modbus states that a baud rate higher than 19200 should use a 1.75 ms for a frame delay.
    # For baud rates below 19200 the timeing is more critical and has to be calculated.
    # In modbus a character is made of a data byte that appends a start bit, stop bit,
    # and parity bit which mean in RTU mode, there are 11 bits per character.
    # Though the "Character-Time" calculation is 11 bits/char / [baud rate] bits/sec.
    # Modbus standard states a frame delay must be 3.5T or 3.5 times longer than 
    # a normal character.
    # E.g. for 9600 baud:
    # "Character-Time": 11 / 9600 = 0.0011458s 
    # "Frame delay": 11 * 3.5 = 38.5
    #                38.5 / 9600 = 0.0040104s
    if configured_baud_rate < 19200:
        inter_frame_timeout = 33 / configured_baud_rate  # changed the ratio from 3.5 to 3
    else:
        inter_frame_timeout = 0.001750
    return inter_frame_timeout


# --------------------------------------------------------------------------- #
# configure a clean exit (even with the use of kill, 
# may be useful if saving the data to a file)
# --------------------------------------------------------------------------- #
def signal_handler(sig, frame):
    print('\nGoodbye\n')
    sys.exit(0)


# --------------------------------------------------------------------------- #
# main routine
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    print(" ")
    # init the signal handler for a clean exit
    signal.signal(signal.SIGINT, signal_handler)

    port = None
    baud_rate = 57600
    parity = serial.PARITY_EVEN
    timeout = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hp:b:a:t:", ["help", "port=", "baudrate=", "parity=", "timeout="])
    except getopt.GetoptError as e:
        log.debug(e)
        print_help(baud_rate, timeout)
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print_help(baud_rate, timeout)
            sys.exit()
        elif opt in ("-p", "--port"):
            port = arg
        elif opt in ("-b", "--baudrate"):
            baud_rate = int(arg)
        elif opt in ("-a", "--parity"):
            parity = arg
        elif opt in ("-t", "--timeout"):
            timeout = float(arg)

    if port is None:
        print("Serial Port not defined please use:")
        print_help(baud_rate, timeout)
        sys.exit(2)

    if timeout is None:
        timeout = calculate_timeout(baud_rate)

    with SerialSnooper(port, baud_rate, parity, timeout) as sniffer:
        while True:
            data = sniffer.read_raw()
            sniffer.process_data(data)
