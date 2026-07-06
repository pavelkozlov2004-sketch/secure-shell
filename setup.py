from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="secure-shell",
    version="1.0.0",
    author="Pavel Kozlov",
    author_email="pavelkozlov2004@example.com",
    description="A secure desktop shell application with access control",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pavelkozlov2004-sketch/secure-shell",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
    install_requires=[
        "PyQt5>=5.15.0",
        "pydantic>=2.0.0",
        "python-dotenv>=1.0.0",
    ],
)
