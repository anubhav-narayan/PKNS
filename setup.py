from setuptools import setup


setup(
    name='pkns',
    version='0.4.0',
    decription='PKNS Framework and CLI',
    author='Anubhav Mattoo',
    author_email='anubhavmattoo@outlook.com',
    packages=['pkns'],
    scripts=['scripts/pkns_cli'],
    install_requires=[
        'daemonocle',
        'sqlitedict',
        'pycryptodome>=3.7'
    ],
    license=open('./LICENSE', 'r').read(),
    long_description=open('./README.md', 'r').read()
)
