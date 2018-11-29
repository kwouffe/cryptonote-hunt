#!/usr/bin/env python
import sys
import json
import os

def config():
    with open('config.json', 'r') as config_file:
        config = json.load(config_file)
        return config
