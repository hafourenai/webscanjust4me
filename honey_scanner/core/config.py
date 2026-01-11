import yaml
import os
import logging

class ConfigLoader:
    _instance = None
    _config = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigLoader, cls).__new__(cls)
            cls._instance._load_config()
        return cls._instance

    def _load_config(self):
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'config.yaml')
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    self._config = yaml.safe_load(f)
            except Exception as e:
                logging.error(f"Failed to load config.yaml: {e}")
                self._config = {}
        else:
            logging.warning("config.yaml not found, using defaults")
            self._config = {}

    def get(self, key_path, default=None):
        """Get value from config using dot notation (e.g. 'scanning.timeout')"""
        keys = key_path.split('.')
        value = self._config
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

config = ConfigLoader()
