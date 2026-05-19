import os
import sys

DEFAULT_CONFIG = {
    "entropy_threshold": 4.5,
    "entropy_min_length": 20,
    "custom_patterns": [],
    "ignore_paths": [],
}


def load_config(config_path=None):
    config = DEFAULT_CONFIG.copy()

    if not config_path or not os.path.isfile(config_path):
        return config

    try:
        import yaml
        with open(config_path) as f:
            user_config = yaml.safe_load(f)
        if user_config:
            config.update(user_config)
    except ImportError:
        print(
            "Warning: pyyaml not installed, config file ignored. Run: pip install pyyaml",
            file=sys.stderr,
        )
    except Exception as e:
        print(f"Warning: could not load config: {e}", file=sys.stderr)

    return config
