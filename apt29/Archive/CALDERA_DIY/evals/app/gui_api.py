from aiohttp_jinja2 import template

from app.service.auth_svc import check_authorization
from app.utility.base_world import BaseWorld

class GuiApi(BaseWorld):

    def __init__(self, services):
        self.auth_svc = services.get('auth_svc')

    @check_authorization
    @template('evals.html')
    async def splash(self, request):
        return dict()
