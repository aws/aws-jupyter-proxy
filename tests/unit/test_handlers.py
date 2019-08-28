from io import BytesIO

import tornado.web
from asynctest import CoroutineMock
from unittest.mock import patch
from tornado.httpclient import HTTPClientError, HTTPResponse, HTTPRequest
from tornado.httputil import HTTPHeaders
from tornado.testing import AsyncHTTPTestCase

from aws_jupyter_proxy.handlers import awsproxy_handlers


class TestAwsProxyHandler(AsyncHTTPTestCase):
    @patch("aws_jupyter_proxy.awsproxy.AwsProxyRequest")
    def test_downstream_error_no_body(self, mock_awsproxy):
        # Given
        mock_instance = mock_awsproxy.return_value
        mock_instance.execute_downstream = CoroutineMock()
        mock_instance.execute_downstream.side_effect = HTTPClientError(code=500)

        # When
        response = self.fetch("/awsproxy")

        # Then
        assert 500 == response.code
        assert b"" == response.body

    @patch("aws_jupyter_proxy.awsproxy.AwsProxyRequest")
    def test_downstream_error_with_body(self, mock_awsproxy):
        # Given
        mock_execute_downstream = CoroutineMock()
        mock_execute_downstream.side_effect = HTTPClientError(
            code=403,
            response=HTTPResponse(
                request=HTTPRequest("/foo"), code=403, buffer=BytesIO(b"AccessDenied")
            ),
        )

        mock_instance = mock_awsproxy.return_value
        mock_instance.execute_downstream = mock_execute_downstream

        # When
        response = self.fetch("/awsproxy")

        # Then
        mock_execute_downstream.assert_awaited_once()
        assert 403 == response.code
        assert b"AccessDenied" == response.body

    @patch("aws_jupyter_proxy.awsproxy.AwsProxyRequest")
    def test_downstream_success_blacklisted_headers_removed(self, mock_awsproxy):
        # Given
        mock_execute_downstream = CoroutineMock()
        mock_execute_downstream.return_value = HTTPResponse(
            request=HTTPRequest(url="https://awsservice.amazonaws.com/"),
            code=200,
            headers=HTTPHeaders(
                {
                    "Host": "awsservice.amazonaws.com",
                    "X-Amz-RequestId": "foo-abc",
                    "Transfer-Encoding": "chunked",
                }
            ),
            buffer=BytesIO(b"SomeResponse"),
        )

        mock_instance = mock_awsproxy.return_value
        mock_instance.execute_downstream = mock_execute_downstream

        # When
        response = self.fetch("/awsproxy")

        # Then
        mock_execute_downstream.assert_awaited_once()
        assert 200 == response.code
        assert b"SomeResponse" == response.body
        assert "Transfer-Encoding" not in response.headers
        assert "foo-abc" == response.headers["X-Amz-RequestId"]
        assert "awsservice.amazonaws.com" == response.headers["Host"]

    def get_app(self):
        return tornado.web.Application(awsproxy_handlers)
