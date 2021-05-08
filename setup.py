from setuptools import setup, find_packages
from setuptools.command.install import install
import os


def post_install():
    print('Creating Directories', end='...')
    if not os.path.exists(os.environ['HOME'] + '/.pkns'):
        os.mkdir(os.path.abspath(os.environ['HOME'] + '/.pkns'))
    print('OK!')
    print('You are Good To Go!')


setup(
    name='pkns',
    version='0.4.0',
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

# Forece Post Install
post_install()
