import logging
from enum import Enum

from contextlib import contextmanager, closing
from platform_driver.interfaces import BaseInterface, BaseRegister, BasicRevert, DriverInterfaceError
from platform_driver.driver_locks import socket_lock

from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ConnectionException, ModbusIOException, ModbusException

modbus_logger = logging.getLogger("pymodbus3")
modbus_logger.setLevel(logging.WARNING)

_log = logging.getLogger(__name__)

@contextmanager
def modbus_client(address, port):
    with socket_lock():
        with closing(ModbusTcpClient(host=address, port=port)) as client:
            yield client

class ModbusInterfaceException(ModbusException):
    pass

class ModbusRegister(BaseRegister):
    def __init__(self, address, read_only, pointName, units, register_type, description='', slave_id=1):
        super(ModbusRegister, self).__init__("byte", read_only, pointName, units, description=description)
        self.address = address
        self.slave_id = slave_id
        self.data_type = self.get_data_type(register_type)

    def get_state(self, client):
        data_type = self.data_type
        count = data_type.value[1]
        # var_type = data_type.name
        response = client.read_holding_registers(self.address, count=count, slave=self.slave_id)

        if response is None:
            raise ModbusInterfaceException("pymodbus returned None")
        
        value = client.convert_from_registers(response.registers, data_type)
        return value

    def set_state(self, client, value):
        if not self.read_only:
            client.write_registers(address=self.address, values=[value], slave=self.slave_id)
            return self.get_state(client)
        return None
    
    def get_data_type(self, format: str) -> Enum:
        """Return the ModbusTcpClient.DATATYPE according to the format"""
        for data_type in ModbusTcpClient.DATATYPE:
            if data_type.value[0] == format:
                return data_type

class Interface(BasicRevert, BaseInterface):
    def __init__(self, **kwargs):
        super(Interface, self).__init__(**kwargs)

    def configure(self, config_dict, registry_config_str):
        self.slave_id = config_dict.get("slave_id", 1)
        self.ip_address = config_dict["device_address"]
        self.port = config_dict.get("port", 502)
        self.parse_config(registry_config_str)

    def get_point(self, point_name):
        register = self.get_register_by_name(point_name)
        with modbus_client(self.ip_address, self.port) as client:
            try:
                result = register.get_state(client)
            except (ConnectionException, ModbusIOException, ModbusInterfaceException):
                result = None
        return result

    def _set_point(self, point_name, value):
        register = self.get_register_by_name(point_name)
        if register.read_only:
            raise  IOError("Trying to write to a point configured read only: "+point_name)

        with modbus_client(self.ip_address, self.port) as client:
            try:
                result = register.set_state(client, value)
            except (ConnectionException, ModbusIOException, ModbusInterfaceException) as ex:
                raise IOError("Error encountered trying to write to point {}: {}".format(point_name, ex))
        return result

    def _scrape_all(self):
        result_dict = {}
        read_registers = self.get_registers_by_type("byte", True)
        write_registers = self.get_registers_by_type("byte", False)
        # For each register, create an entry in the results dictionary with its name as the key and state as the value
        for register in read_registers + write_registers:
            with modbus_client(self.ip_address, self.port) as client:
                try:
                    result_dict[register.point_name] = register.get_state(client)
                except (ConnectionException, ModbusIOException, ModbusInterfaceException) as e:
                    raise DriverInterfaceError("Failed to scrape device at " + self.ip_address + ":" + str(self.port) +
                                            " ID: " + str(self.slave_id) + str(e))
        return result_dict

    def parse_config(self, configDict):
        if configDict is None:
            return

        for regDef in configDict:
            # Skip lines that have no address yet.
            if not regDef['Volttron Point Name']:
                continue
            io_type = regDef['Modbus Register']
            read_only = regDef['Writable'].lower() != 'true'
            point_path = regDef['Volttron Point Name']
            address = int(regDef['Point Address'])
            description = regDef.get('Notes', '')
            units = regDef['Units']
            register = ModbusRegister(address, read_only, point_path, units, io_type, description=description, slave_id=self.slave_id)
            self.insert_register(register)