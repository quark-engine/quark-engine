import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="quark-engine",  # Replace with your own username
    version="19.10",
    author="JunWei Song, KunYu Chen",
    author_email="sungboss2004@gmail.com",
    description="An Obfuscation-Neglect Android Malware Scoring System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/quark-engine/quark-engine",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
)
