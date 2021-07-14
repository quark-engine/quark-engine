import os
import setuptools

from quark import __version__

with open("README.md") as fh:
    long_description = fh.read()

required_requirements = [
    "prettytable",
    "androguard==3.4.0a1",
    "tqdm",
    "colorama",
    "graphviz",
    "pandas",
    "prompt-toolkit==3.0.19",
    "plotly",
    "rzpipe",
]
without_cli_support = os.environ.get("QUARK_WITHOUT_CLI", default=0)
if not without_cli_support:
    required_requirements.append("click==8.0.1")

setuptools.setup(
    name="quark-engine",  # Replace with your own username
    version=__version__,
    author="JunWei Song, KunYu Chen",
    author_email="sungboss2004@gmail.com",
    description="An Obfuscation-Neglect Android Malware Scoring System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/quark-engine/quark-engine",
    packages=setuptools.find_packages(),
    entry_points={
        "console_scripts": [
            "quark=quark.cli:entry_point",
            "freshquark=quark.freshquark:entry_point",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
    install_requires=required_requirements,
)
