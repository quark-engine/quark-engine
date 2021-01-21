import setuptools

from quark import __version__

with open("README.md") as fh:
    long_description = fh.read()

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
    entry_points={"console_scripts": ["quark=quark.cli:entry_point",
                                      "freshquark=quark.freshquark:entry_point",
                                      ]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
    install_requires=[
        "prettytable",
        "androguard==3.4.0a1",
        "tqdm",
        "colorama",
        "click==7.1.2",
        "graphviz",
        "gitpython",
    ],
)
