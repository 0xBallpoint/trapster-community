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

requirements = read('requirements.txt').splitlines()

setup(
    name='trapster',
    version=get_version("trapster/__init__.py"),
    install_requires=requirements,
    url='https://trapster.cloud/',
    author='0xBallpoint',
    author_email='contact@ballpoint.fr',
    description='Trapster Daemon',
    long_description=read('README.md'),
    long_description_content_type='text/markdown',
    license="AGPL3",
    packages=find_packages(include=['trapster', 'trapster.*', 'trapsterd']),
    include_package_data=True,
    package_data={
        '': ['requirements.txt'],
    },
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
    keywords=["trapster", "honeypot", "ballpoint", "deceptive", "security", "network"],
    entry_points={
        'console_scripts': [
             'trapster=trapster.trapster:main',
        ],
    },
)
