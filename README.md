# AWS Jupyter Proxy

A Jupyter server extension to proxy requests with AWS SigV4 authentication. 

## Overview

This server extension enables the usage of the [AWS JavaScript/TypeScript SDK](https://github.com/aws/aws-sdk-js)  without having to export AWS credentials to the browser.

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
    import S3 from 'aws-sdk/clients/s3';


    // Configure any fake credentials
    AWS.config.secretAccessKey = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
    AWS.config.accessKeyId = 'AKIDEXAMPLE';

    // Change the endpoint in the client to the "awsproxy" endpoint on the Jupyter server.
    const proxyEndpoint = 'http://localhost:8888/awsproxy';

    const sageMakerClient = new SageMaker({
        region: 'us-west-2',
        endpoint: proxyEndpoint,
    });

    // Make the API call!
    await proxySageMaker
        .listNotebookInstances({
            NameContains: 'jaipreet'
        })
        .promise();

    // For S3, enable the "s3ForcePathStyle" flag in the client.
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
