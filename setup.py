from pathlib import Path
from setuptools import setup, find_packages

root = Path(__file__).parent
setup(
    name='secure-shell', version='1.6.0',
    description='Secure Shell application modules',
    long_description=(root / 'README.md').read_text(encoding='utf-8'),
    long_description_content_type='text/markdown',
    author='Pavel Kozlov',
    package_dir={'': 'src'}, packages=find_packages('src'),
    py_modules=['config', 'main', 'bootstrap'],
    package_data={'database': ['*.sql']},
    python_requires='>=3.10',
    install_requires=['PyQt5>=5.15,<6', 'qtawesome>=1.2,<2',
                      'pydantic>=2,<3', 'python-dotenv>=1,<2',
                      'openpyxl>=3.1,<4', 'python-docx>=1.1,<2', 'cryptography>=42'],
    entry_points={'console_scripts': ['secure-shell=main:main', 'secure-shell-bootstrap=bootstrap:main']},
)
