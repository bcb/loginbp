"""setup.py"""

from setuptools import setup

setup(
    name='loginbp',
    py_modules=['loginbp'],
    install_requires=['flask', 'flask_assets', 'flask_login', \
        'flask_principal', 'flask_wtf', 'wtforms', 'jsonrpcclient']
    )
