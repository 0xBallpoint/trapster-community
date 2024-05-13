from setuptools import setup, find_packages
import codecs
import os

def read(rel_path):
    here = os.path.abspath(os.path.dirname(__file__))
    with codecs.open(os.path.join(here, rel_path), 'r', encoding='utf-8') as fp:
        return fp.read()

def get_version(rel_path):
    """
    Reading the package version dynamically.
    https://packaging.python.org/en/latest/guides/single-sourcing-package-version/
    """
    for line in read(rel_path).splitlines():
        if line.startswith('__version__'):
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]
    raise RuntimeError("Unable to find version string.")

setup(
    name='trapster',
    version=get_version("trapster/__init__.py"),
    install_requires=[
        "anyio>=3.6.2",
        "async-timeout>=4.0.2",
        "asyncssh>=2.13.1",
        "certifi>=2023.5.7",
        "cffi>=1.15.1",
        "cryptography>=40.0.2",
        "h11>=0.14.0",
        "httpcore>=0.17.0",
        "httpx>=0.24.0",
        "idna>=3.4",
        "netifaces>=0.11.0",
        "nmcli>=1.2.0",
        "pycparser>=2.21",
        "redis>=4.5.5",
        "sniffio>=1.3.0",
        "typing_extensions>=4.5.0",
        "packaging",
        "securesystemslib",
        "pyasn1"
    ],
    url='https://trapster.cloud/',
    author='0xBallpoint',
    author_email='contact@ballpoint.fr',
    description='Trapster Daemon',
    long_description=read('README.md'),
    long_description_content_type='text/markdown',
    packages=find_packages(include=['trapster', 'trapster.*', 'trapsterd']),
    include_package_data=True,
    platforms=['linux'],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Framework :: AsyncIO",
        "Topic :: System :: Networking",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)"
    ],
    keywords=["trapster", "ballpoint", "deceptive", "security", "network"],
    entry_points={
        'console_scripts': [
             'trapster=trapster.trapster:main',
        ],
    },
)
