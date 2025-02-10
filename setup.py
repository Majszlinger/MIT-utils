from setuptools import setup, find_packages

setup(
    name="mit_utils",
    version="0.0.0",
    packages=find_packages(),
    author="MIT Solutions",
    description="Utility Bundle for development",
    python_requires=">=3.7",
    install_requires=[],
    extras_require={
        "auth": ["pyjwt"],
    }
)