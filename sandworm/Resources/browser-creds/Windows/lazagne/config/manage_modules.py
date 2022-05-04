# Browsers
from lazagne.config.soft_import_module import soft_import
from lazagne.softwares.browsers.chromium_browsers import chromium_browsers
from lazagne.softwares.browsers.firefox_browsers import firefox_browsers


def get_modules_names():
    return [
        ("lazagne.softwares.browsers.ie", "IE"),
        ("lazagne.softwares.browsers.ucbrowser", "UCBrowser")
    ]


def get_categories():
    category = {
        'browsers': {'help': 'Web browsers supported'}
    }
    return category




def get_modules():
    modules = [soft_import(package_name, module_name)() for package_name, module_name in get_modules_names()]
    return modules + chromium_browsers + firefox_browsers
