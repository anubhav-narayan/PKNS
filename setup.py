from setuptools import setup, find_packages
from setuptools.command.install import install
import os


setup(
    name='pkns',
    version='0.5.7',
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
    long_description=open('./README.md', 'r').read(),
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Communications',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
        'Development Status :: 4 - Beta'
    ]
)
