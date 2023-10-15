#!/usr/bin/python3
#coding:utf-8

from setuptools import setup, find_packages
from mitm import __version__

setup(
    name        = "SAE24",
    version     = __version__,
    description = "Un paquet pour réaliser une attaque de type 'ARP Poisoning'.",
    packages    = find_packages()
)
