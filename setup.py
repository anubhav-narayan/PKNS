from setuptools import setup


setup(
    name='pkns',
    version='0.4.0',
    decription='PKNS Framework and CLI',
    author='Anubhav Mattoo',
    author_email='anubhavmattoo@outlook.com',
    packages=['pkns'],
    scripts=['pkns_cli'],
    install_requires=[
        'daemonocle',
        'sqlitedict',
        'pycrptodome>=3.7'
    ],
    license='AGPLv3',
    long_description=open('./LICENSE', 'r').read()
)
