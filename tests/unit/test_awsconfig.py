from unittest.mock import patch
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application
from aws_jupyter_proxy.awsconfig import AwsConfigHandler
from aws_jupyter_proxy.handlers import awsproxy_handlers


class TestHelloApp(AsyncHTTPTestCase):
    def get_app(self):
        return Application(awsproxy_handlers)

    @patch("aws_jupyter_proxy.awsconfig.get_session")
    def test_valid_region(self, mock_get_session):
        mock_get_session.return_value.get_config_variable.return_value = "us-west-1"
        response = self.fetch("/awsproxy/awsconfig")
        self.assertEqual(response.code, 200)
        self.assertEqual(response.body, b'{"region": "us-west-1"}')

    @patch("aws_jupyter_proxy.awsconfig.get_session")
    def test_default_region(self, mock_get_session):
        mock_get_session.return_value.get_config_variable.return_value = ""
        response = self.fetch("/awsproxy/awsconfig")
        self.assertEqual(response.code, 200)
        self.assertEqual(response.body, b'{"region": null}')

    @patch("aws_jupyter_proxy.awsconfig.get_session")
    def test_no_region(self, mock_get_session):
        mock_get_session.return_value.get_config_variable.return_value = None
        response = self.fetch("/awsproxy/awsconfig")
        self.assertEqual(response.code, 200)
        self.assertEqual(response.body, b'{"region": null}')
