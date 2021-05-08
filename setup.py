from setuptools import setup, find_packages
from setuptools.command.install import install
import os


setup(
    name='pkns',
    version='0.5.2',
    description='PKNS Framework and CLI',
    author='Anubhav Mattoo',
    author_email='anubhavmattoo@outlook.com',
    packages=find_packages(),
    entry_points={
        'console_scripts': ['pkns_cli=pkns.cli:main']
    },
    install_requires=[
        'daemonocle',
        'sqlitedict',
        'pycryptodome>=3.7',
        'click'
    ],
    license=open('./LICENSE', 'r').read(),
    long_description=open('./README.md', 'r').read()
)