# AWS Jupyter Proxy

![CodeBuild](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiZGVqcG5MVEZZYkd2aFBBZnlSZ1R6d0s3U1JKR3pwOWR0UGJTdEp5bW9QWlVlMmdnTEJlenZUdVVkQjNzcVViMmlLQ1NGNS9yLzJEWkRpMzF5WUxnZTJVPSIsIml2UGFyYW1ldGVyU3BlYyI6Ikw5ck5kZk50ai9UU2pYanMiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master)
[![Version](https://img.shields.io/pypi/v/aws_jupyter_proxy.svg)](https://pypi.org/project/aws-jupyter-proxy/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A Jupyter server extension to proxy requests with AWS SigV4 authentication.

## Overview

This server extension enables the usage of the [AWS JavaScript/TypeScript SDK](https://github.com/aws/aws-sdk-js) to write Jupyter frontend extensions without having to export AWS credentials to the browser.

A single `/awsproxy` endpoint is added on the Jupyter server which receives incoming requests from the browser, uses the credentials on the server to add [SigV4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html) authentication to the request, and then proxies the request to the actual AWS service endpoint.

All requests are proxied back-and-forth as-is, e.g., a 4xx status code from the AWS service will be relayed back as-is to the browser.

NOTE: This project is still under active development

## Install

Installing the package from PyPI will install and enable the server extension on the Jupyter server.

```bash
pip install aws-jupyter-proxy
```

## Usage

Using this requries no additional dependencies in the client-side code. Just use the regular AWS JavaScript/TypeScript SDK methods and add any dummy credentials and change the endpoint to the `/awsproxy` endpoint.

```typescript
    import * as AWS from 'aws-sdk';
    import SageMaker from 'aws-sdk/clients/sagemaker';


    // These credentials are *not* used for the actual AWS service call but you have
    // to provide any dummy credentials (Not real ones!)
    AWS.config.secretAccessKey = 'IGNOREDIGNORE/IGNOREDIGNOREDIGNOREDIGNOR';
    AWS.config.accessKeyId = 'IGNOREDIGNO';

    // Change the endpoint in the client to the "awsproxy" endpoint on the Jupyter server.
    const proxyEndpoint = 'http://localhost:8888/awsproxy';

    const sageMakerClient = new SageMaker({
        region: 'us-west-2',
        endpoint: proxyEndpoint,
    });

    // Make the API call!
    await sageMakerClient
        .listNotebookInstances({
            NameContains: 'jaipreet'
        })
        .promise();
```

### Usage with S3

For S3, use the `s3ForcePathStyle` parameter during the client initialization

```typescript
    import S3 from 'aws-sdk/clients/s3';

    const s3Client = new S3({
        region: 'us-west-2',
        endpoint: proxyEndpoint,
        s3ForcePathStyle: true
    });

    await s3Client.getObject({
        Bucket: 'my-bucket',
        Key: 'my-object'
    }).promise();
```

## Development

Install all dev dependencies

```bash
pip install -e ".[dev]"
jupyter serverextension enable --py aws_jupyter_proxy
```

Run unit tests using pytest

```bash
pytest tests/unit
```

## License

This library is licensed under the Apache 2.0 License.
