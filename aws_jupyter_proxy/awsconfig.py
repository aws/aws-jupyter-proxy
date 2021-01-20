import json
from botocore.session import get_session
from notebook.base.handlers import APIHandler


class AwsConfigHandler(APIHandler):
    async def get(self, *args):
        response = {"region": self._get_aws_region()}
        self.write(json.dumps(response))

    def _get_aws_region(self):
        session = get_session()
        return session.get_config_variable("region") or None
