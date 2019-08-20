from boto3 import Session
from notebook.base.handlers import APIHandler
from notebook.utils import url_path_join


class AwsProxyHandler(APIHandler):

    def initialize(self, session: Session):
        """
        Hook for Tornado handler initialization.
        :param session: the botocore session
        """
        self.session = session

    def get(self, *args):
        self.log.info('GET invoked')


awsproxy_handlers = [(r'/awsproxy(.*)',
                      AwsProxyHandler,
                      dict(session=Session()))]


def setup_handlers(web_app):
    base_url = web_app.settings['base_url']
    web_app.add_handlers(".*", [(url_path_join(base_url, path), handler, data) for (path, handler, data) in
                                awsproxy_handlers])
