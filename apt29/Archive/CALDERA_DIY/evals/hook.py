from plugins.evals.app.gui_api import GuiApi

name = 'Evals'
description = 'A plugin to start the DIY ATT&CK Based Evaluations with CALDERA'
address = '/plugin/evals/gui'

async def enable(services):
    app = services.get('app_svc').application
    file_svc = services.get('file_svc')
    gui_api = GuiApi(services=services)

    #app.router.add_static('/evals', 'plugins/evals/static/', append_version=True)
    app.router.add_route('GET', '/plugin/evals/gui', gui_api.splash)
