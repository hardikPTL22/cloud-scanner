import json
import os

BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "..", "grc_data")


def load_registry():
    path = os.path.join(DATA_DIR, "control_registry.json")
    with open(path, "r") as f:
        return json.load(f)


CONTROL_REGISTRY = load_registry()


def map_control(control_type: str):
    return CONTROL_REGISTRY.get(control_type)
