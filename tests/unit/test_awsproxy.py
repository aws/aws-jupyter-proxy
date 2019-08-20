import pytest
from asynctest import Mock, patch, CoroutineMock
from tornado.httpclient import HTTPRequest, HTTPClientError
from tornado.httputil import HTTPServerRequest, HTTPHeaders

from botocore.credentials import Credentials

from aws_jupyter_proxy.awsproxy import AwsProxyRequest, create_endpoint_resolver


@pytest.fixture
def mock_session():
    session = Mock()
    session.get_credentials.return_value = Credentials('access_key', 'secret_key', 'session_token')
    return session


@pytest.mark.asyncio
@patch('tornado.httpclient.AsyncHTTPClient.fetch', new_callable=CoroutineMock)
async def test_post_with_body(mock_fetch, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method='POST',
        uri='/awsproxy',
        headers=HTTPHeaders({
            'Authorization': 'AWS4-HMAC-SHA256 '
                             'Credential=AKIDEXAMPLE/20190816/us-west-2/sagemaker/aws4_request, '
                             'SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-target;x-amz-user-agent, '
                             'Signature=cfe54b727d00698b9940531b1c9e456fd70258adc41fb338896455fddd6f3f2f',
            'Host': 'localhost:8888',
            'X-Amz-User-Agent': 'aws-sdk-js/2.507.0 promise',
            'X-Amz-Content-Sha256': 'a83a35dcbd19cfad5b714cb12b5275a4cfa7e1012b633d9206300f09e058e7fa',
            'X-Amz-Target': 'SageMaker.ListNotebookInstances',
            'X-Amz-Date': '20190816T204930Z'

        }),
        body=b'{"NameContains":"myname"}',
        host='localhost:8888'
    )

    # When
    await AwsProxyRequest(upstream_request, create_endpoint_resolver(), mock_session).execute_downstream()

    # Then
    expected = HTTPRequest(url='https://api.sagemaker.us-west-2.amazonaws.com/',
                           method=upstream_request.method,
                           body=b'{"NameContains":"myname"}',
                           headers={
                               'Authorization': 'AWS4-HMAC-SHA256 '
                                                'Credential=access_key/20190816/us-west-2/sagemaker/aws4_request, '
                                                'SignedHeaders=host;x-amz-content-sha256;x-amz-date;'
                                                'x-amz-security-token;x-amz-target;x-amz-user-agent, '
                                                'Signature='
                                                '215b2e3656147651194acb6cca20d5cb01dd8f396ac941533fc3e52b7cb563dc',
                               'X-Amz-User-Agent': 'aws-sdk-js/2.507.0 promise',
                               'X-Amz-Content-Sha256': 'a83a35dcbd19cfad5b714cb12b5275a4cfa7e1012b633d9206300f09e058e7fa',
                               'X-Amz-Target': 'SageMaker.ListNotebookInstances',
                               'X-Amz-Date': '20190816T204930Z',
                               'X-Amz-Security-Token': 'session_token',
                               'Host': 'api.sagemaker.us-west-2.amazonaws.com'
                           },
                           follow_redirects=False
                           )

    assert_http_response(mock_fetch, expected)

@pytest.mark.asyncio
@patch('tornado.httpclient.AsyncHTTPClient.fetch', new_callable=CoroutineMock)
async def test_errors_passed_through(mock_fetch, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method='GET',
        uri='/awsproxy/clusters/myname',
        headers=HTTPHeaders({
            'Authorization': 'AWS4-HMAC-SHA256 '
                             'Credential=AKIDEXAMPLE/20190816/us-east-2/eks/aws4_request, '
                             'SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, '
                             'Signature=f176ff82da6efc539bb8a2860be6ea19a99adf93d87be8ba96f25f1d29c91ba9',
            'Host': 'localhost:8888',
            'X-Amz-User-Agent': 'aws-sdk-js/2.507.0 promise',
            'X-Amz-Content-Sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'X-Amz-Date': '20190816T224244Z'

        }),
        body=b'',
        host='localhost:8888'
    )
    mock_fetch.side_effect = HTTPClientError(code=500, message='Something bad')

    # When
    with pytest.raises(HTTPClientError) as e:
        await AwsProxyRequest(upstream_request, create_endpoint_resolver(), mock_session).execute_downstream()

        assert 500 == e.value.code
        assert 'Something bad' == e.value.message


@pytest.mark.asyncio
@patch('tornado.httpclient.AsyncHTTPClient.fetch', new_callable=CoroutineMock)
async def test_get_with_path(mock_fetch, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method='GET',
        uri='/awsproxy/clusters/myname',
        headers=HTTPHeaders({
            'Authorization': 'AWS4-HMAC-SHA256 '
                             'Credential=AKIDEXAMPLE/20190816/us-east-2/eks/aws4_request, '
                             'SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, '
                             'Signature=f176ff82da6efc539bb8a2860be6ea19a99adf93d87be8ba96f25f1d29c91ba9',
            'Host': 'localhost:8888',
            'X-Amz-User-Agent': 'aws-sdk-js/2.507.0 promise',
            'X-Amz-Content-Sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'X-Amz-Date': '20190816T224244Z'

        }),
        body=b'',
        host='localhost:8888'
    )

    # When
    await AwsProxyRequest(upstream_request, create_endpoint_resolver(), mock_session).execute_downstream()

    # Then
    expected = HTTPRequest(url='https://eks.us-east-2.amazonaws.com/clusters/myname',
                           method=upstream_request.method,
                           body=None,
                           headers={
                               'Authorization': 'AWS4-HMAC-SHA256 '
                                                'Credential=access_key/20190816/us-east-2/eks/aws4_request, '
                                                'SignedHeaders=host;x-amz-content-sha256;x-amz-date;'
                                                'x-amz-security-token;x-amz-user-agent, '
                                                'Signature='
                                                '0bab991ebb02f7f2ea44e3687778e930e5f66e1111b958a9c2ff88aba2eaf3da',
                               'X-Amz-User-Agent': upstream_request.headers['X-Amz-User-Agent'],
                               'X-Amz-Content-Sha256': upstream_request.headers['X-Amz-Content-Sha256'],
                               'X-Amz-Date': upstream_request.headers['X-Amz-Date'],
                               'X-Amz-Security-Token': 'session_token',
                               'Host': 'eks.us-east-2.amazonaws.com'
                           },
                           follow_redirects=False
                           )

    assert_http_response(mock_fetch, expected)

@pytest.mark.asyncio
@patch('tornado.httpclient.AsyncHTTPClient.fetch', new_callable=CoroutineMock)
async def test_get_with_query(mock_fetch, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method='GET',
        uri='/awsproxy/clusters?maxResults=1',
        headers=HTTPHeaders({
            'Authorization': 'AWS4-HMAC-SHA256 '
                             'Credential=AKIDEXAMPLE/20190816/us-east-2/eks/aws4_request, '
                             'SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, '
                             'Signature=24203e07130d74b28845f756f5440603d24400d53d07ddda9d7add99d5ec7c8d',
            'Host': 'localhost:8888',
            'X-Amz-User-Agent': 'aws-sdk-js/2.507.0 promise',
            'X-Amz-Content-Sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'X-Amz-Date': '20190816T224244Z'

        }),
        body=b'',
        host='localhost:8888'
    )

    # When
    await AwsProxyRequest(upstream_request, create_endpoint_resolver(), mock_session).execute_downstream()

    # Then
    expected = HTTPRequest(url='https://eks.us-east-2.amazonaws.com/clusters?maxResults=1',
                           method=upstream_request.method,
                           body=None,
                           headers={
                               'Authorization': 'AWS4-HMAC-SHA256 '
                                                'Credential=access_key/20190816/us-east-2/eks/aws4_request, '
                                                'SignedHeaders=host;x-amz-content-sha256;x-amz-date;'
                                                'x-amz-security-token;x-amz-user-agent, '
                                                'Signature='
                                                '61315054f93efa316230cbe77497522b8db692969104ec4c935235e14ad1c23f',
                               'X-Amz-User-Agent': upstream_request.headers['X-Amz-User-Agent'],
                               'X-Amz-Content-Sha256': upstream_request.headers['X-Amz-Content-Sha256'],
                               'X-Amz-Date': upstream_request.headers['X-Amz-Date'],
                               'X-Amz-Security-Token': 'session_token',
                               'Host': 'eks.us-east-2.amazonaws.com'
                           },
                           follow_redirects=False
                           )

    assert_http_response(mock_fetch, expected)

@pytest.mark.asyncio
@patch('tornado.httpclient.AsyncHTTPClient.fetch', new_callable=CoroutineMock)
async def test_delete(mock_fetch, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method='DELETE',
        uri='/awsproxy/clusters/myname',
        headers=HTTPHeaders({
            'Authorization': 'AWS4-HMAC-SHA256 '
                             'Credential=AKIDEXAMPLE/20190816/us-east-2/eks/aws4_request, '
                             'SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, '
                             'Signature=24203e07130d74b28845f756f5440603d24400d53d07ddda9d7add99d5ec7c8d',
            'Host': 'localhost:8888',
            'X-Amz-User-Agent': 'aws-sdk-js/2.507.0 promise',
            'X-Amz-Content-Sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'X-Amz-Date': '20190816T224244Z'

        }),
        body=b'',
        host='localhost:8888'
    )

    # When
    await AwsProxyRequest(upstream_request, create_endpoint_resolver(), mock_session).execute_downstream()

    # Then
    expected = HTTPRequest(url='https://eks.us-east-2.amazonaws.com/clusters/myname',
                           method=upstream_request.method,
                           body=None,
                           headers={
                               'Authorization': 'AWS4-HMAC-SHA256 '
                                                'Credential=access_key/20190816/us-east-2/eks/aws4_request, '
                                                'SignedHeaders=host;x-amz-content-sha256;x-amz-date;'
                                                'x-amz-security-token;x-amz-user-agent, '
                                                'Signature='
                                                '6fde2ff4f8aa9582d8740b6b7108a1a7f24ec3807a15c79f6e688ef4f4eaae35',
                               'X-Amz-User-Agent': upstream_request.headers['X-Amz-User-Agent'],
                               'X-Amz-Content-Sha256': upstream_request.headers['X-Amz-Content-Sha256'],
                               'X-Amz-Date': upstream_request.headers['X-Amz-Date'],
                               'X-Amz-Security-Token': 'session_token',
                               'Host': 'eks.us-east-2.amazonaws.com'
                           },
                           follow_redirects=False
                           )

    assert_http_response(mock_fetch, expected)

@pytest.mark.asyncio
@patch('tornado.httpclient.AsyncHTTPClient.fetch', new_callable=CoroutineMock)
async def test_put(mock_fetch, mock_session):
    # Given
    upstream_request = HTTPServerRequest(
        method='PUT',
        uri='/awsproxy/clusters/myname',
        headers=HTTPHeaders({
            'Authorization': 'AWS4-HMAC-SHA256 '
                             'Credential=AKIDEXAMPLE/20190816/us-east-2/eks/aws4_request, '
                             'SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, '
                             'Signature=24203e07130d74b28845f756f5440603d24400d53d07ddda9d7add99d5ec7c8d',
            'Host': 'localhost:8888',
            'X-Amz-User-Agent': 'aws-sdk-js/2.507.0 promise',
            'X-Amz-Content-Sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'X-Amz-Date': '20190816T224244Z'

        }),
        body=b'{"Name":"Foo","Id":"Bar"}',
        host='localhost:8888'
    )

    # When
    await AwsProxyRequest(upstream_request, create_endpoint_resolver(), mock_session).execute_downstream()

    # Then
    expected = HTTPRequest(url='https://eks.us-east-2.amazonaws.com/clusters/myname',
                           method=upstream_request.method,
                           body=upstream_request.body,
                           headers={
                               'Authorization': 'AWS4-HMAC-SHA256 '
                                                'Credential=access_key/20190816/us-east-2/eks/aws4_request, '
                                                'SignedHeaders=host;x-amz-content-sha256;x-amz-date;'
                                                'x-amz-security-token;x-amz-user-agent, '
                                                'Signature='
                                                'b6d04b91fa9e1993657806821321eb10a665e89d6de2f390fa39d40d77015971',
                               'X-Amz-User-Agent': upstream_request.headers['X-Amz-User-Agent'],
                               'X-Amz-Content-Sha256': upstream_request.headers['X-Amz-Content-Sha256'],
                               'X-Amz-Date': upstream_request.headers['X-Amz-Date'],
                               'X-Amz-Security-Token': 'session_token',
                               'Host': 'eks.us-east-2.amazonaws.com'
                           },
                           follow_redirects=False
                           )

    assert_http_response(mock_fetch, expected)


def assert_http_response(mock_fetch, expected_http_request):
    mock_fetch.assert_awaited_once()
    actual_http_request = mock_fetch.await_args[0][0]
    assert expected_http_request.url == actual_http_request.url
    assert expected_http_request.headers == actual_http_request.headers
    assert expected_http_request.body == actual_http_request.body
    assert expected_http_request.method == actual_http_request.method
    assert expected_http_request.follow_redirects == actual_http_request.follow_redirects
