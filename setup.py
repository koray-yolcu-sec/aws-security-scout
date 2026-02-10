"""AWS Security Scout - Setup Script"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="aws-security-scout",
    version="1.0.0",
    author="Koray Yolcu",
    author_email="kkyolcu@gmail.com",
    description="AWS Bulut Güvenlik Misconfiguration Tespit Aracı",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/koray-yolcu-sec/aws-security-scout",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "boto3>=1.26.0",
        "botocore>=1.29.0",
        "jinja2>=3.1.0",
    ],
    entry_points={
        "console_scripts": [
            "aws-scout=aws_scout.cli:main",
        ],
    },
)