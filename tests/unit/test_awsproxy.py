import pytest
import pkg_resources
from asynctest import Mock, patch, CoroutineMock
from tornado.httpclient import HTTPRequest, HTTPClientError, HTTPError
from tornado.httputil import HTTPServerRequest, HTTPHeaders

from botocore.credentials import Credentials

from aws_jupyter_proxy.awsproxy import AwsProxyRequest, create_endpoint_resolver

version = pkg_resources.require("aws_jupyter_proxy")[0].version


@pytest.fixture
def mock_session():
    session = Mock()
    session.get_credentials.return_value = Credentials(
        "access_key", "secret_key", "session_token"
    )
    return session


@pytest.mark.asyncio
@patch("tornado.httpclient.AsyncHTTPClient.fetch", new_callable=CoroutineMock)
async def test_post_with_body(mock_fetch, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method="POST",
        uri="/awsproxy",
        headers=HTTPHeaders(
            {
                "Authorization": "AWS4-HMAC-SHA256 "
                "Credential=AKIDEXAMPLE/20190816/us-west-2/sagemaker/aws4_request, "
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-target;x-amz-user-agent, "
                "Signature=cfe54b727d00698b9940531b1c9e456fd70258adc41fb338896455fddd6f3f2f",
                "Host": "localhost:8888",
                "X-Amz-User-Agent": "aws-sdk-js/2.507.0 promise",
                "X-Amz-Content-Sha256": "a83a35dcbd19cfad5b714cb12b5275a4cfa7e1012b633d9206300f09e058e7fa",
                "X-Amz-Target": "SageMaker.ListNotebookInstances",
                "X-Amz-Date": "20190816T204930Z",
            }
        ),
        body=b'{"NameContains":"myname"}',
        host="localhost:8888",
    )

    # When
    await AwsProxyRequest(
        upstream_request, create_endpoint_resolver(), mock_session
    ).execute_downstream()

    # Then
    expected = HTTPRequest(
        url="https://api.sagemaker.us-west-2.amazonaws.com/",
        method=upstream_request.method,
        body=b'{"NameContains":"myname"}',
        headers={
            "Authorization": "AWS4-HMAC-SHA256 "
            "Credential=access_key/20190816/us-west-2/sagemaker/aws4_request, "
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date;"
            "x-amz-security-token;x-amz-target;x-amz-user-agent, "
            "Signature="
            "215b2e3656147651194acb6cca20d5cb01dd8f396ac941533fc3e52b7cb563dc",
            "X-Amz-User-Agent": "aws-sdk-js/2.507.0 promise",
            "X-Amz-Content-Sha256": "a83a35dcbd19cfad5b714cb12b5275a4cfa7e1012b633d9206300f09e058e7fa",
            "X-Amz-Target": "SageMaker.ListNotebookInstances",
            "X-Amz-Date": "20190816T204930Z",
            "X-Amz-Security-Token": "session_token",
            "Host": "api.sagemaker.us-west-2.amazonaws.com",
            "User-Agent": "aws-jupyter-proxy/" + version,
        },
        follow_redirects=False,
        allow_nonstandard_methods=True,
    )

    assert_http_response(mock_fetch, expected)


@pytest.mark.asyncio
@patch("tornado.httpclient.AsyncHTTPClient.fetch", new_callable=CoroutineMock)
async def test_errors_passed_through(mock_fetch, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method="GET",
        uri="/awsproxy/clusters/myname",
        headers=HTTPHeaders(
            {
                "Authorization": "AWS4-HMAC-SHA256 "
                "Credential=AKIDEXAMPLE/20190816/us-east-2/eks/aws4_request, "
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, "
                "Signature=f176ff82da6efc539bb8a2860be6ea19a99adf93d87be8ba96f25f1d29c91ba9",
                "Host": "localhost:8888",
                "X-Amz-User-Agent": "aws-sdk-js/2.507.0 promise",
                "X-Amz-Content-Sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "X-Amz-Date": "20190816T224244Z",
            }
        ),
        body=b"",
        host="localhost:8888",
    )
    mock_fetch.side_effect = HTTPClientError(code=500, message="Something bad")

    # When
    with pytest.raises(HTTPClientError) as e:
        await AwsProxyRequest(
            upstream_request, create_endpoint_resolver(), mock_session
        ).execute_downstream()

        assert 500 == e.value.code
        assert "Something bad" == e.value.message


@pytest.mark.asyncio
@patch("tornado.httpclient.AsyncHTTPClient.fetch", new_callable=CoroutineMock)
async def test_get_with_path(mock_fetch, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method="GET",
        uri="/awsproxy/clusters/myname",
        headers=HTTPHeaders(
            {
                "Authorization": "AWS4-HMAC-SHA256 "
                "Credential=AKIDEXAMPLE/20190816/us-east-2/eks/aws4_request, "
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, "
                "Signature=f176ff82da6efc539bb8a2860be6ea19a99adf93d87be8ba96f25f1d29c91ba9",
                "Host": "localhost:8888",
                "X-Amz-User-Agent": "aws-sdk-js/2.507.0 promise",
                "X-Amz-Content-Sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "X-Amz-Date": "20190816T224244Z",
            }
        ),
        body=b"",
        host="localhost:8888",
    )

    # When
    await AwsProxyRequest(
        upstream_request, create_endpoint_resolver(), mock_session
    ).execute_downstream()

    # Then
    expected = HTTPRequest(
        url="https://eks.us-east-2.amazonaws.com/clusters/myname",
        method=upstream_request.method,
        body=None,
        headers={
            "Authorization": "AWS4-HMAC-SHA256 "
            "Credential=access_key/20190816/us-east-2/eks/aws4_request, "
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date;"
            "x-amz-security-token;x-amz-user-agent, "
            "Signature="
            "0bab991ebb02f7f2ea44e3687778e930e5f66e1111b958a9c2ff88aba2eaf3da",
            "X-Amz-User-Agent": upstream_request.headers["X-Amz-User-Agent"],
            "X-Amz-Content-Sha256": upstream_request.headers["X-Amz-Content-Sha256"],
            "X-Amz-Date": upstream_request.headers["X-Amz-Date"],
            "X-Amz-Security-Token": "session_token",
            "Host": "eks.us-east-2.amazonaws.com",
            "User-Agent": "aws-jupyter-proxy/" + version,
        },
        follow_redirects=False,
        allow_nonstandard_methods=True,
    )

    assert_http_response(mock_fetch, expected)


@pytest.mark.asyncio
@patch("tornado.httpclient.AsyncHTTPClient.fetch", new_callable=CoroutineMock)
async def test_get_with_query(mock_fetch, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method="GET",
        uri="/awsproxy/clusters?maxResults=1",
        headers=HTTPHeaders(
            {
                "Authorization": "AWS4-HMAC-SHA256 "
                "Credential=AKIDEXAMPLE/20190816/us-east-2/eks/aws4_request, "
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, "
                "Signature=24203e07130d74b28845f756f5440603d24400d53d07ddda9d7add99d5ec7c8d",
                "Host": "localhost:8888",
                "X-Amz-User-Agent": "aws-sdk-js/2.507.0 promise",
                "X-Amz-Content-Sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "X-Amz-Date": "20190816T224244Z",
            }
        ),
        body=b"",
        host="localhost:8888",
    )

    # When
    await AwsProxyRequest(
        upstream_request, create_endpoint_resolver(), mock_session
    ).execute_downstream()

    # Then
    expected = HTTPRequest(
        url="https://eks.us-east-2.amazonaws.com/clusters?maxResults=1",
        method=upstream_request.method,
        body=None,
        headers={
            "Authorization": "AWS4-HMAC-SHA256 "
            "Credential=access_key/20190816/us-east-2/eks/aws4_request, "
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date;"
            "x-amz-security-token;x-amz-user-agent, "
            "Signature="
            "61315054f93efa316230cbe77497522b8db692969104ec4c935235e14ad1c23f",
            "X-Amz-User-Agent": upstream_request.headers["X-Amz-User-Agent"],
            "X-Amz-Content-Sha256": upstream_request.headers["X-Amz-Content-Sha256"],
            "X-Amz-Date": upstream_request.headers["X-Amz-Date"],
            "X-Amz-Security-Token": "session_token",
            "Host": "eks.us-east-2.amazonaws.com",
            "User-Agent": "aws-jupyter-proxy/" + version,
        },
        follow_redirects=False,
        allow_nonstandard_methods=True,
    )

    assert_http_response(mock_fetch, expected)


@pytest.mark.asyncio
@patch("tornado.httpclient.AsyncHTTPClient.fetch", new_callable=CoroutineMock)
async def test_delete(mock_fetch, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method="DELETE",
        uri="/awsproxy/clusters/myname",
        headers=HTTPHeaders(
            {
                "Authorization": "AWS4-HMAC-SHA256 "
                "Credential=AKIDEXAMPLE/20190816/us-east-2/eks/aws4_request, "
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, "
                "Signature=24203e07130d74b28845f756f5440603d24400d53d07ddda9d7add99d5ec7c8d",
                "Host": "localhost:8888",
                "X-Amz-User-Agent": "aws-sdk-js/2.507.0 promise",
                "X-Amz-Content-Sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "X-Amz-Date": "20190816T224244Z",
            }
        ),
        body=b"",
        host="localhost:8888",
    )

    # When
    await AwsProxyRequest(
        upstream_request, create_endpoint_resolver(), mock_session
    ).execute_downstream()

    # Then
    expected = HTTPRequest(
        url="https://eks.us-east-2.amazonaws.com/clusters/myname",
        method=upstream_request.method,
        body=None,
        headers={
            "Authorization": "AWS4-HMAC-SHA256 "
            "Credential=access_key/20190816/us-east-2/eks/aws4_request, "
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date;"
            "x-amz-security-token;x-amz-user-agent, "
            "Signature="
            "6fde2ff4f8aa9582d8740b6b7108a1a7f24ec3807a15c79f6e688ef4f4eaae35",
            "X-Amz-User-Agent": upstream_request.headers["X-Amz-User-Agent"],
            "X-Amz-Content-Sha256": upstream_request.headers["X-Amz-Content-Sha256"],
            "X-Amz-Date": upstream_request.headers["X-Amz-Date"],
            "X-Amz-Security-Token": "session_token",
            "Host": "eks.us-east-2.amazonaws.com",
            "User-Agent": "aws-jupyter-proxy/" + version,
        },
        follow_redirects=False,
        allow_nonstandard_methods=True,
    )

    assert_http_response(mock_fetch, expected)


@pytest.mark.asyncio
@patch("tornado.httpclient.AsyncHTTPClient.fetch", new_callable=CoroutineMock)
async def test_put(mock_fetch, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method="PUT",
        uri="/awsproxy/clusters/myname",
        headers=HTTPHeaders(
            {
                "Authorization": "AWS4-HMAC-SHA256 "
                "Credential=AKIDEXAMPLE/20190816/us-east-2/eks/aws4_request, "
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, "
                "Signature=24203e07130d74b28845f756f5440603d24400d53d07ddda9d7add99d5ec7c8d",
                "Host": "localhost:8888",
                "X-Amz-User-Agent": "aws-sdk-js/2.507.0 promise",
                "X-Amz-Content-Sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "X-Amz-Date": "20190816T224244Z",
            }
        ),
        body=b'{"Name":"Foo","Id":"Bar"}',
        host="localhost:8888",
    )

    # When
    await AwsProxyRequest(
        upstream_request, create_endpoint_resolver(), mock_session
    ).execute_downstream()

    # Then
    expected = HTTPRequest(
        url="https://eks.us-east-2.amazonaws.com/clusters/myname",
        method=upstream_request.method,
        body=upstream_request.body,
        headers={
            "Authorization": "AWS4-HMAC-SHA256 "
            "Credential=access_key/20190816/us-east-2/eks/aws4_request, "
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date;"
            "x-amz-security-token;x-amz-user-agent, "
            "Signature="
            "b6d04b91fa9e1993657806821321eb10a665e89d6de2f390fa39d40d77015971",
            "X-Amz-User-Agent": upstream_request.headers["X-Amz-User-Agent"],
            "X-Amz-Content-Sha256": upstream_request.headers["X-Amz-Content-Sha256"],
            "X-Amz-Date": upstream_request.headers["X-Amz-Date"],
            "X-Amz-Security-Token": "session_token",
            "Host": "eks.us-east-2.amazonaws.com",
            "User-Agent": "aws-jupyter-proxy/" + version,
        },
        follow_redirects=False,
        allow_nonstandard_methods=True,
    )

    assert_http_response(mock_fetch, expected)


@pytest.mark.asyncio
@patch("tornado.httpclient.AsyncHTTPClient.fetch", new_callable=CoroutineMock)
async def test_post_with_query_params_and_body(mock_fetch, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method="POST",
        uri="/awsproxy/bucket-name-1/Hello.txt?select&select-type=2",
        headers=HTTPHeaders(
            {
                "Authorization": "AWS4-HMAC-SHA256 "
                "Credential=AKIDEXAMPLE/20190828/us-west-2/s3/aws4_request, "
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, "
                "Signature=451d7037903cee381c6a5d2c61c6ee2b5d36f35650e95abcf5e8af11b57c0cf8",
                "Host": "localhost:8888",
                "X-Amz-User-Agent": "aws-sdk-js/2.507.0 promise",
                "X-Amz-Content-Sha256": "f5b0fecc75eeaba2a9c92703363f4b9e3efa3f7811d3904f0b71cf05c3895228",
                "X-Amz-Date": "20190828T173626Z",
            }
        ),
        body=b'<SelectObjectContentRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        b"<Expression>select * from S3Object</Expression>"
        b"<ExpressionType>SQL</ExpressionType>"
        b"<InputSerialization><JSON>"
        b"<Type>Lines</Type>"
        b"</JSON></InputSerialization>"
        b"<OutputSerialization><JSON><RecordDelimiter>,</RecordDelimiter></JSON></OutputSerialization>"
        b"</SelectObjectContentRequest>",
        host="localhost:8888",
    )

    # When
    await AwsProxyRequest(
        upstream_request, create_endpoint_resolver(), mock_session
    ).execute_downstream()

    # Then
    expected = HTTPRequest(
        url="https://s3.us-west-2.amazonaws.com/bucket-name-1/Hello.txt?select&select-type=2",
        method=upstream_request.method,
        body=upstream_request.body,
        headers={
            "Authorization": "AWS4-HMAC-SHA256 "
            "Credential=access_key/20190828/us-west-2/s3/aws4_request, "
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date;"
            "x-amz-security-token;x-amz-user-agent, "
            "Signature="
            "e55d97f45ca6862d9c2518868dd2a8c383007df1c991e42ef5950a46a4c13f8e",
            "X-Amz-User-Agent": upstream_request.headers["X-Amz-User-Agent"],
            "X-Amz-Content-Sha256": upstream_request.headers["X-Amz-Content-Sha256"],
            "X-Amz-Date": upstream_request.headers["X-Amz-Date"],
            "X-Amz-Security-Token": "session_token",
            "Host": "s3.us-west-2.amazonaws.com",
            "User-Agent": "aws-jupyter-proxy/" + version,
        },
        follow_redirects=False,
        allow_nonstandard_methods=True,
    )

    assert_http_response(mock_fetch, expected)


@pytest.mark.asyncio
@patch("tornado.httpclient.AsyncHTTPClient.fetch", new_callable=CoroutineMock)
async def test_post_with_query_params_no_body(mock_fetch, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method="POST",
        uri="/awsproxy/bucket-name-1/Multipart-0.16441670919496487.txt?uploads",
        headers=HTTPHeaders(
            {
                "Authorization": "AWS4-HMAC-SHA256 "
                "Credential=AKIDEXAMPLE/20190828/us-west-2/s3/aws4_request, "
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, "
                "Signature=451d7037903cee381c6a5d2c61c6ee2b5d36f35650e95abcf5e8af11b57c0cf8",
                "Host": "localhost:8888",
                "X-Amz-User-Agent": "aws-sdk-js/2.507.0 promise",
                "X-Amz-Content-Sha256": "a08b81ef3b4ec5e1f65ca97d00928105c3d7eb6d50ae59fc15f0d14b64c9ec3b",
                "X-Amz-Date": "20190828T173626Z",
            }
        ),
        body=b"",
        host="localhost:8888",
    )

    # When
    await AwsProxyRequest(
        upstream_request, create_endpoint_resolver(), mock_session
    ).execute_downstream()

    # Then
    expected = HTTPRequest(
        url="https://s3.us-west-2.amazonaws.com/bucket-name-1/Multipart-0.16441670919496487.txt"
        "?uploads",
        method=upstream_request.method,
        body=None,
        headers={
            "Authorization": "AWS4-HMAC-SHA256 "
            "Credential=access_key/20190828/us-west-2/s3/aws4_request, "
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date;"
            "x-amz-security-token;x-amz-user-agent, "
            "Signature="
            "ba2062818cb4cd80a73dd43d006f141ede069b8ccc2ece16c20504587bd5045b",
            "X-Amz-User-Agent": upstream_request.headers["X-Amz-User-Agent"],
            "X-Amz-Content-Sha256": upstream_request.headers["X-Amz-Content-Sha256"],
            "X-Amz-Date": upstream_request.headers["X-Amz-Date"],
            "X-Amz-Security-Token": "session_token",
            "Host": "s3.us-west-2.amazonaws.com",
            "User-Agent": "aws-jupyter-proxy/" + version,
        },
        follow_redirects=False,
        allow_nonstandard_methods=True,
    )

    assert_http_response(mock_fetch, expected)


@pytest.mark.asyncio
@patch("tornado.httpclient.AsyncHTTPClient.fetch", new_callable=CoroutineMock)
async def test_head_request(mock_fetch, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method="HEAD",
        uri="/awsproxy/bucket-name-1",
        headers=HTTPHeaders(
            {
                "Authorization": "AWS4-HMAC-SHA256 "
                "Credential=AKIDEXAMPLE/20190828/us-west-2/s3/aws4_request, "
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, "
                "Signature=0d02795c4feed38e5a4cd80aec3a2c67886b11797a23c307e4f52c2cfe0c137e",
                "Host": "localhost:8888",
                "X-Amz-User-Agent": "aws-sdk-js/2.507.0 promise",
                "X-Amz-Content-Sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "X-Amz-Date": "20190828T173626Z",
            }
        ),
        body=None,
        host="localhost:8888",
    )

    # When
    await AwsProxyRequest(
        upstream_request, create_endpoint_resolver(), mock_session
    ).execute_downstream()

    # Then
    expected = HTTPRequest(
        url="https://s3.us-west-2.amazonaws.com/bucket-name-1",
        method=upstream_request.method,
        body=None,
        headers={
            "Authorization": "AWS4-HMAC-SHA256 "
            "Credential=access_key/20190828/us-west-2/s3/aws4_request, "
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date;"
            "x-amz-security-token;x-amz-user-agent, "
            "Signature="
            "6d724e3bd64390d5d84010d6fc0f8147b3e3917c5befa3f8d1efb691b408e821",
            "X-Amz-User-Agent": upstream_request.headers["X-Amz-User-Agent"],
            "X-Amz-Content-Sha256": upstream_request.headers["X-Amz-Content-Sha256"],
            "X-Amz-Date": upstream_request.headers["X-Amz-Date"],
            "X-Amz-Security-Token": "session_token",
            "Host": "s3.us-west-2.amazonaws.com",
            "User-Agent": "aws-jupyter-proxy/" + version,
        },
        follow_redirects=False,
        allow_nonstandard_methods=True,
    )

    assert_http_response(mock_fetch, expected)


@pytest.mark.asyncio
@patch("tornado.httpclient.AsyncHTTPClient.fetch", new_callable=CoroutineMock)
async def test_get_with_encoded_uri(mock_fetch, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method="GET",
        uri="/awsproxy/bucket-name-1/ll%3A%3Askeleton%201.png",
        headers=HTTPHeaders(
            {
                "Authorization": "AWS4-HMAC-SHA256 "
                "Credential=AKIDEXAMPLE/20190816/us-west-2/s3/aws4_request, "
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, "
                "Signature=822f116d22d577aa2dc1033f354fa2a6fd3a2b6a0fd51885472b57daf45d605e",
                "Host": "localhost:8888",
                "X-Amz-User-Agent": "aws-sdk-js/2.507.0 promise",
                "X-Amz-Content-Sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "X-Amz-Date": "20190816T224244Z",
            }
        ),
        body=b"",
        host="localhost:8888",
    )

    # When
    await AwsProxyRequest(
        upstream_request, create_endpoint_resolver(), mock_session
    ).execute_downstream()

    # Then
    expected = HTTPRequest(
        url="https://s3.us-west-2.amazonaws.com/bucket-name-1/ll%3A%3Askeleton%201.png",
        method=upstream_request.method,
        body=None,
        headers={
            "Authorization": "AWS4-HMAC-SHA256 "
            "Credential=access_key/20190816/us-west-2/s3/aws4_request, "
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date;"
            "x-amz-security-token;x-amz-user-agent, "
            "Signature="
            "4715991ba2461bfda29bda8a53747a13448c1303c2e03d8ee8a4992df08f5551",
            "X-Amz-User-Agent": upstream_request.headers["X-Amz-User-Agent"],
            "X-Amz-Content-Sha256": upstream_request.headers["X-Amz-Content-Sha256"],
            "X-Amz-Date": upstream_request.headers["X-Amz-Date"],
            "X-Amz-Security-Token": "session_token",
            "Host": "s3.us-west-2.amazonaws.com",
            "User-Agent": "aws-jupyter-proxy/" + version,
        },
        follow_redirects=False,
        allow_nonstandard_methods=True,
    )

    assert_http_response(mock_fetch, expected)


@pytest.mark.asyncio
@patch("os.getenv")
async def test_request_not_whitelisted(mock_getenv, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method="HEAD",
        uri="/awsproxy/bucket-name-1",
        headers=HTTPHeaders(
            {
                "Authorization": "AWS4-HMAC-SHA256 "
                "Credential=AKIDEXAMPLE/20190828/us-west-2/s3/aws4_request, "
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, "
                "Signature=0d02795c4feed38e5a4cd80aec3a2c67886b11797a23c307e4f52c2cfe0c137e",
                "Host": "localhost:8888",
                "X-Amz-User-Agent": "aws-sdk-js/2.507.0 promise",
                "X-Amz-Content-Sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "X-Amz-Date": "20190828T173626Z",
            }
        ),
        body=None,
        host="localhost:8888",
    )
    mock_getenv.return_value = "sagemaker,eks,"

    # When
    with pytest.raises(HTTPError) as e:
        await AwsProxyRequest(
            upstream_request, create_endpoint_resolver(), mock_session
        ).execute_downstream()

        # Then
        assert 403 == e.value.code
        assert "Service s3 is not whitelisted for proxying requests" == e.value.message


@pytest.mark.asyncio
@patch("os.getenv")
async def test_nothing_whitelisted(mock_getenv, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method="HEAD",
        uri="/awsproxy/bucket-name-1",
        headers=HTTPHeaders(
            {
                "Authorization": "AWS4-HMAC-SHA256 "
                "Credential=AKIDEXAMPLE/20190828/us-west-2/s3/aws4_request, "
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, "
                "Signature=0d02795c4feed38e5a4cd80aec3a2c67886b11797a23c307e4f52c2cfe0c137e",
                "Host": "localhost:8888",
                "X-Amz-User-Agent": "aws-sdk-js/2.507.0 promise",
                "X-Amz-Content-Sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "X-Amz-Date": "20190828T173626Z",
            }
        ),
        body=None,
        host="localhost:8888",
    )
    mock_getenv.return_value = ""

    # When
    with pytest.raises(HTTPError) as e:
        await AwsProxyRequest(
            upstream_request, create_endpoint_resolver(), mock_session
        ).execute_downstream()

        # Then
        assert 403 == e.value.code
        assert "Service s3 is not whitelisted for proxying requests" == e.value.message


@pytest.mark.asyncio
@patch("tornado.httpclient.AsyncHTTPClient.fetch", new_callable=CoroutineMock)
@patch("os.getenv")
async def test_request_whitelisted(mock_getenv, mock_fetch, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method="HEAD",
        uri="/awsproxy/bucket-name-1",
        headers=HTTPHeaders(
            {
                "Authorization": "AWS4-HMAC-SHA256 "
                "Credential=AKIDEXAMPLE/20190828/us-west-2/s3/aws4_request, "
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, "
                "Signature=0d02795c4feed38e5a4cd80aec3a2c67886b11797a23c307e4f52c2cfe0c137e",
                "Host": "localhost:8888",
                "X-Amz-User-Agent": "aws-sdk-js/2.507.0 promise",
                "X-Amz-Content-Sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "X-Amz-Date": "20190828T173626Z",
            }
        ),
        body=None,
        host="localhost:8888",
    )
    mock_getenv.return_value = "s3,"

    # When
    await AwsProxyRequest(
        upstream_request, create_endpoint_resolver(), mock_session
    ).execute_downstream()

    # Then
    expected = HTTPRequest(
        url="https://s3.us-west-2.amazonaws.com/bucket-name-1",
        method=upstream_request.method,
        body=None,
        headers={
            "Authorization": "AWS4-HMAC-SHA256 "
            "Credential=access_key/20190828/us-west-2/s3/aws4_request, "
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date;"
            "x-amz-security-token;x-amz-user-agent, "
            "Signature="
            "6d724e3bd64390d5d84010d6fc0f8147b3e3917c5befa3f8d1efb691b408e821",
            "X-Amz-User-Agent": upstream_request.headers["X-Amz-User-Agent"],
            "X-Amz-Content-Sha256": upstream_request.headers["X-Amz-Content-Sha256"],
            "X-Amz-Date": upstream_request.headers["X-Amz-Date"],
            "X-Amz-Security-Token": "session_token",
            "Host": "s3.us-west-2.amazonaws.com",
            "User-Agent": "aws-jupyter-proxy/" + version,
        },
        follow_redirects=False,
        allow_nonstandard_methods=True,
    )

    assert_http_response(mock_fetch, expected)


@pytest.mark.asyncio
@patch("tornado.httpclient.AsyncHTTPClient.fetch", new_callable=CoroutineMock)
@patch("os.getenv")
async def test_request_with_base_url(mock_getenv, mock_fetch, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method="HEAD",
        uri="/base-url/awsproxy/bucket-name-1",
        headers=HTTPHeaders(
            {
                "Authorization": "AWS4-HMAC-SHA256 "
                "Credential=AKIDEXAMPLE/20190828/us-west-2/s3/aws4_request, "
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, "
                "Signature=0d02795c4feed38e5a4cd80aec3a2c67886b11797a23c307e4f52c2cfe0c137e",
                "Host": "localhost:8888",
                "X-Amz-User-Agent": "aws-sdk-js/2.507.0 promise",
                "X-Amz-Content-Sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "X-Amz-Date": "20190828T173626Z",
            }
        ),
        body=None,
        host="localhost:8888",
    )
    mock_getenv.return_value = "s3,"

    # When
    await AwsProxyRequest(
        upstream_request, create_endpoint_resolver(), mock_session
    ).execute_downstream()

    # Then
    expected = HTTPRequest(
        url="https://s3.us-west-2.amazonaws.com/bucket-name-1",
        method=upstream_request.method,
        body=None,
        headers={
            "Authorization": "AWS4-HMAC-SHA256 "
            "Credential=access_key/20190828/us-west-2/s3/aws4_request, "
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date;"
            "x-amz-security-token;x-amz-user-agent, "
            "Signature="
            "6d724e3bd64390d5d84010d6fc0f8147b3e3917c5befa3f8d1efb691b408e821",
            "X-Amz-User-Agent": upstream_request.headers["X-Amz-User-Agent"],
            "X-Amz-Content-Sha256": upstream_request.headers["X-Amz-Content-Sha256"],
            "X-Amz-Date": upstream_request.headers["X-Amz-Date"],
            "X-Amz-Security-Token": "session_token",
            "Host": "s3.us-west-2.amazonaws.com",
            "User-Agent": "aws-jupyter-proxy/" + version,
        },
        follow_redirects=False,
        allow_nonstandard_methods=True,
    )

    assert_http_response(mock_fetch, expected)


@pytest.mark.asyncio
@patch("tornado.httpclient.AsyncHTTPClient.fetch", new_callable=CoroutineMock)
@patch("os.getenv")
async def test_request_with_user_agent(mock_getenv, mock_fetch, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method="HEAD",
        uri="/base-url/awsproxy/bucket-name-1",
        headers=HTTPHeaders(
            {
                "Authorization": "AWS4-HMAC-SHA256 "
                "Credential=AKIDEXAMPLE/20190828/us-west-2/s3/aws4_request, "
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, "
                "Signature=0d02795c4feed38e5a4cd80aec3a2c67886b11797a23c307e4f52c2cfe0c137e",
                "Host": "localhost:8888",
                "X-Amz-User-Agent": "aws-sdk-js/2.507.0 promise",
                "X-Amz-Content-Sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "X-Amz-Date": "20190828T173626Z",
                "User-Agent": "product/0.0.0",
            }
        ),
        body=None,
        host="localhost:8888",
    )
    mock_getenv.return_value = "s3,"

    # When
    await AwsProxyRequest(
        upstream_request, create_endpoint_resolver(), mock_session
    ).execute_downstream()

    # Then
    expected = HTTPRequest(
        url="https://s3.us-west-2.amazonaws.com/bucket-name-1",
        method=upstream_request.method,
        body=None,
        headers={
            "Authorization": "AWS4-HMAC-SHA256 "
            "Credential=access_key/20190828/us-west-2/s3/aws4_request, "
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date;"
            "x-amz-security-token;x-amz-user-agent, "
            "Signature="
            "6d724e3bd64390d5d84010d6fc0f8147b3e3917c5befa3f8d1efb691b408e821",
            "X-Amz-User-Agent": upstream_request.headers["X-Amz-User-Agent"],
            "X-Amz-Content-Sha256": upstream_request.headers["X-Amz-Content-Sha256"],
            "X-Amz-Date": upstream_request.headers["X-Amz-Date"],
            "X-Amz-Security-Token": "session_token",
            "Host": "s3.us-west-2.amazonaws.com",
            "User-Agent": "product/0.0.0 aws-jupyter-proxy/" + version,
        },
        follow_redirects=False,
        allow_nonstandard_methods=True,
    )

    assert_http_response(mock_fetch, expected)


def assert_http_response(mock_fetch, expected_http_request):
    mock_fetch.assert_awaited_once()
    actual_http_request: HTTPRequest = mock_fetch.await_args[0][0]
    assert expected_http_request.url == actual_http_request.url
    assert expected_http_request.body == actual_http_request.body
    assert expected_http_request.method == actual_http_request.method
    assert (
        expected_http_request.follow_redirects == actual_http_request.follow_redirects
    )
    assert (
        expected_http_request.allow_nonstandard_methods
        == actual_http_request.allow_nonstandard_methods
    )
    assert expected_http_request.headers == actual_http_request.headers
