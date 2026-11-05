from setuptools import setup, find_packages

setup(
    name="aegis-agent-sdk",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
    ],
    extras_require={
        "langchain": ["langchain-core>=0.1.0"],
        "crewai": ["crewai>=0.1.0"],
    },
)
