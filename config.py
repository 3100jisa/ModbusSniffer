import json
import os


class ConfigurationMissingFileException(Exception):
    def __init__(self, message: str):
        super().__init__(f"Missing configuration file: {message}")


class ConfigurationInvalidJsonFile(Exception):
    def __init__(self, message: str):
        super().__init__(f"Invalid JSON file: {message}")


class ConfigurationMissingEntryException(Exception):
    def __init__(self, message: str):
        super().__init__(f"Config exception: {message}")


class Configuration:
    def __init__(self, file_path: str):
        abspath = os.path.abspath(file_path)
        try:
            with open(abspath, "r") as file:
                self._file_path = file_path
                try:
                    self._data = json.load(file)
                except FileNotFoundError:
                    file.close()
                    raise ConfigurationInvalidJsonFile(abspath)
                file.close()
        except FileNotFoundError:
            raise ConfigurationMissingFileException(abspath)

    def _get_key(self, key, default=None) -> str:
        parameter = self._data.get(key, None)
        if parameter is not None:
            return parameter
        else:
            if default is None:
                raise ConfigurationMissingEntryException(
                    f"While parsing '{self._file_path}' file: Invalid configuration file. Missing {key} key.")
            else:
                return default

    def get_slave_id_format(self) -> str:
        return Configuration._get_key(self, "slaveIdFormat")

    def get_register_address_format(self) -> str:
        return Configuration._get_key(self, "registerAddressFormat", "{}")


_CONFIGURATION: Configuration = None  # capital letters - global variable (but private due to used underscore)


def get_configuration() -> Configuration:
    global _CONFIGURATION
    if _CONFIGURATION is None:
        _CONFIGURATION = Configuration("config.json")
    return _CONFIGURATION
