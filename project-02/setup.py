from setuptools import setup, find_packages

setup(
    name="gray-sentinel-project-02",
    version="1.0.0",
    description="Web Security Findings Reporter CLI",
    author="GraySentinel Security Engineer",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "gray-sentinel=gray_sentinel.cli:main",
            "graysentinel=gray_sentinel.cli:main",
        ],
    },
)
