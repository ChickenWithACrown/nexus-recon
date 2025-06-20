import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="nexus-recon",
    version="1.0.0",
    author="ChickenWithACrown",
    author_email="",  # Using GitHub Issues and Discord for contact
    description="Advanced Network Reconnaissance & Security Assessment Toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ChickenWithACrown/nexus-recon",
    project_urls={
        "Bug Tracker": "https://github.com/ChickenWithACrown/nexus-recon/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.1",
        "python-whois>=0.9.3",
        "dnspython>=2.3.0",
        "ipaddress>=1.0.23",
        "beautifulsoup4>=4.9.3",
        "cryptography>=3.4.7",
        "geoip2>=4.1.0",
        "python-nmap>=0.7.1",
        "colorama>=0.4.4",
    ],
    entry_points={
        "console_scripts": [
            "nexus-recon=nexus_recon.cli:main",
        ],
    },
)
