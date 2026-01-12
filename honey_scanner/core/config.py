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
        from .paths import find_config
        config_path = find_config()
        if config_path:
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    self._config = yaml.safe_load(f)
            except Exception as e:
                logging.error(f"Failed to load config.yaml at {config_path}: {e}")
                self._config = {}
        else:
            logging.warning("config.yaml not found in standard locations, using defaults")
            self._config = {}

    def get(self, key_path, default=None):
        """
        Get value from config using dot notation (e.g. 'scanning.timeout').
        Supports environment variable overrides using HONEY_ prefix and underscores.
        Example: HONEY_SCANNING_TIMEOUT=30 will override scanning.timeout
        """
        # Check environment variable first
        env_key = f"HONEY_{key_path.replace('.', '_').upper()}"
        env_value = os.getenv(env_key)
        
        if env_value is not None:
            # Try to cast to int or float if appropriate
            try:
                if '.' in env_value:
                    return float(env_value)
                return int(env_value)
            except ValueError:
                if env_value.lower() == 'true': return True
                if env_value.lower() == 'false': return False
                return env_value

        # Fallback to YAML config
        keys = key_path.split('.')
        value = self._config
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

config = ConfigLoader()
