import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="aws_jupyter_proxy",
    version="0.2.0",
    url="https://github.com/aws/aws-jupyter-proxy",
    author="Amazon Web Services",
    description="A Jupyter server extension to proxy requests with AWS SigV4 authentication",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    license="Apache License 2.0",
    install_requires=["notebook >=6.0, <7.0", "botocore >=1.0, <2.0"],
    extras_require={
        "dev": ["asynctest", "black", "pytest", "pytest-asyncio", "pytest-cov"]
    },
    python_requires=">=3.6",
    data_files=[
        (
            "etc/jupyter/jupyter_notebook_config.d",
            ["aws_jupyter_proxy/etc/aws_jupyter_proxy.json"],
        )
    ],
    classifiers=["Development Status :: 4 - Beta"],
    include_package_data=True,
)
