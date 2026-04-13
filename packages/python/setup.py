from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="hivetrust",
    version="1.0.0",
    author="HiveAgent IQ",
    author_email="sdk@hiveagentiq.com",
    description="Official Python SDK for the HiveTrust KYA Identity Verification, Trust Scoring & Parametric Insurance API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://hivetrust.hiveagentiq.com",
    project_urls={
        "Documentation": "https://hivetrust.hiveagentiq.com/docs",
        "Source": "https://github.com/hiveagentiq/hivetrust",
        "Tracker": "https://github.com/hiveagentiq/hivetrust/issues",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Typing :: Typed",
    ],
    python_requires=">=3.10",
    install_requires=[
        "httpx>=0.27.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0",
            "pytest-asyncio>=0.23",
            "respx>=0.21",
        ]
    },
    keywords=[
        "hivetrust",
        "hiveagent",
        "ai-agent",
        "trust-score",
        "kya",
        "identity-verification",
        "parametric-insurance",
        "a2a",
        "mcp",
        "did",
        "verifiable-credentials",
    ],
    license="MIT",
)
