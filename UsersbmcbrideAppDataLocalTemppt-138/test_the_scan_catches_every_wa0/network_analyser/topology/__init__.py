import paramiko
import netmiko.cisco as nc
from netmiko import ConnectHandler
import importlib
importlib.import_module('paramiko.client')
__import__('netmiko')
name = 'para' + 'miko'
importlib.import_module(name)
