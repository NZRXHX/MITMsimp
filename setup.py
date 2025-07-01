from setuptools import setup, find_packages

setup(
    name="mitmsimp",
    version="0.2.0",
    packages=find_packages(),
    install_requires=[
        'scapy>=2.4.5',
        'python-nmap>=0.7.1',
        'beautifulsoup4>=4.9.3',
        'requests>=2.25.1',
        'pyOpenSSL>=20.0.1',
        'colorama>=0.4.4',
        'jinja2>=2.11.3',
        'dnspython>=2.1.0',
        'concurrent-log-handler>=0.9.20',
        'python-whois>=0.8.0'
    ],
    entry_points={
        'console_scripts': [
            'mitmsimp=mitmsimp.core.scanner:main',
        ],
    },
    package_data={
        'mitmsimp': ['templates/*.html'],
    },
    author="NZRXHX",
    description="Automated MITM weak point detection tool",
    keywords="security pentest mitm network",
    url="https://github.com/NZRXHX/MITMsimp",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring"
    ],
)
