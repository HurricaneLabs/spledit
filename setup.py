from setuptools import setup


VERSION = "0.1.0"


setup(
    name="spledit",
    version=VERSION,
    author="Steve McMaster",
    author_email="mcmaster@hurricanelabs.com",
    py_modules=["spledit"],
    description="spledit - Modify Splunk configuration files via REST API",
    install_requires=[
        "pyotp",
        "requests"
    ],
    entry_points={
        "console_scripts": [
            "spledit = spledit:main",
        ]
    },
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Environment :: Console",
        "Programming Language :: Python :: 3",
        "Development Status :: 3 - Alpha",
    ],
    bugtrack_url="https://github.com/HurricaneLabs/spledit/issues",
)
