# Configuration file for the Sphinx documentation builder.
# http://www.sphinx-doc.org/en/stable/config

from datetime import datetime

project = 'The B.T.P.S Security Package'
author = 'OsbornePro LLC.'

# The full version, including alpha/beta/rc tags
version = "0.1.0"
release = version
now = datetime.now()
today = f"{now.year}-{now.month:02}-{now.day:02} {now.hour:02}H{now.minute:02}"
copyright = f"2023-{now.year}, {author}"
source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}
master_doc = "index"
language = None
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store", ".venv"]
html_theme = "bizstyle"
pygments_style = "sphinx"
extensions = ["sphinx.ext.intersphinx", "recommonmark", "sphinx_tabs.tabs"]
intersphinx_mapping = {
    "python": ("https://docs.python.org/", None),
    "official_sphinx": ("http://www.sphinx-doc.org/", None),
    "https://gdevops.gitlab.io/tuto_python/": None,
    "https://gdevops.gitlab.io/tuto_django/": None,
    "docker": ("https://gdevops.gitlab.io/tuto_docker/", None),
    "https://gdevops.gitlab.io/tuto_cli/": None,
    "https://gdevops.gitlab.io/tuto_build/": None,
    "https://gdevops.gitlab.io/tuto_kubernetes/": None,
    "http://blockdiag.com/en/": None,
}
extensions = extensions + ["sphinx.ext.todo"]
todo_include_todos = True




###########################################################################
#          auto-created readthedocs.org specific configuration            #
###########################################################################


#
# The following code was added during an automated build on readthedocs.org
# It is auto created and injected for every build. The result is based on the
# conf.py.tmpl file found in the readthedocs.org codebase:
# https://github.com/rtfd/readthedocs.org/blob/master/readthedocs/doc_builder/templates/doc_builder/conf.py.tmpl
#


import importlib
import sys
import os.path
from six import string_types

from sphinx import version_info

# Get suffix for proper linking to GitHub
# This is deprecated in Sphinx 1.3+,
# as each page can have its own suffix
if globals().get('source_suffix', False):
    if isinstance(source_suffix, string_types):
        SUFFIX = source_suffix
    elif isinstance(source_suffix, (list, tuple)):
        # Sphinx >= 1.3 supports list/tuple to define multiple suffixes
        SUFFIX = source_suffix[0]
    elif isinstance(source_suffix, dict):
        # Sphinx >= 1.8 supports a mapping dictionary for multiple suffixes
        SUFFIX = list(source_suffix.keys())[0]  # make a ``list()`` for py2/py3 compatibility
    else:
        # default to .rst
        SUFFIX = '.rst'
else:
    SUFFIX = '.rst'

# Add RTD Static Path. Add to the end because it overwrites previous files.
if not 'html_static_path' in globals():
    html_static_path = []
if os.path.exists('_static'):
    html_static_path.append('_static')

# Add RTD Theme only if they aren't overriding it already
using_rtd_theme = (
    (
        'html_theme' in globals() and
        html_theme in ['default'] and
        # Allow people to bail with a hack of having an html_style
        'html_style' not in globals()
    ) or 'html_theme' not in globals()
)
if using_rtd_theme:
    theme = importlib.import_module('sphinx_rtd_theme')
    html_theme = 'sphinx_rtd_theme'
    html_style = None
    html_theme_options = {}
    if 'html_theme_path' in globals():
        html_theme_path.append(theme.get_html_theme_path())
    else:
        html_theme_path = [theme.get_html_theme_path()]

if globals().get('websupport2_base_url', False):
    websupport2_base_url = 'https://readthedocs.org/websupport'
    websupport2_static_url = 'https://assets.readthedocs.org/static/'


#Add project information to the template context.
context = {
    'using_theme': using_rtd_theme,
    'html_theme': html_theme,
    'current_version': "latest",
    'version_slug': "latest",
    'MEDIA_URL': "https://media.readthedocs.org/",
    'STATIC_URL': "https://assets.readthedocs.org/static/",
    'PRODUCTION_DOMAIN': "readthedocs.org",
    'versions': [
    ("latest", "/en/latest/"),
    ("stable", "/en/stable/"),
    ("0.3.0", "/en/0.3.0/"),
    ("0.1.0", "/en/0.1.0/"),
    ],
    'downloads': [ 
    ("pdf", "//devopstutodoc.readthedocs.io/_/downloads/en/latest/pdf/"),
    ("html", "//devopstutodoc.readthedocs.io/_/downloads/en/latest/htmlzip/"),
    ],
    'subprojects': [ 
    ],
    'slug': 'devopstutodoc',
    'name': u'devopstuto_doc',
    'rtd_language': u'en',
    'programming_language': u'py',
    'canonical_url': 'https://devopstutodoc.readthedocs.io/en/latest/',
    'analytics_code': '',
    'single_version': False,
    'conf_py_path': '/',
    'api_host': 'https://readthedocs.org',
    'github_user': 'None',
    'github_repo': 'None',
    'github_version': 'master',
    'display_github': False,
    'bitbucket_user': 'None',
    'bitbucket_repo': 'None',
    'bitbucket_version': 'master',
    'display_bitbucket': False,
    'gitlab_user': 'gdevops',
    'gitlab_repo': 'tuto_documentation',
    'gitlab_version': 'master',
    'display_gitlab': True,
    'READTHEDOCS': True,
    'using_theme': (html_theme == "default"),
    'new_theme': (html_theme == "sphinx_rtd_theme"),
    'source_suffix': SUFFIX,
    'ad_free': False,
    'user_analytics_code': '',
    'global_analytics_code': 'UA-17997319-1',
    'commit': '79bea070',
}




if 'html_context' in globals():
    
    html_context.update(context)
    
else:
    html_context = context

# Add custom RTD extension
if 'extensions' in globals():
    # Insert at the beginning because it can interfere
    # with other extensions.
    # See https://github.com/rtfd/readthedocs.org/pull/4054
    extensions.insert(0, "readthedocs_ext.readthedocs")
else:
    extensions = ["readthedocs_ext.readthedocs"]

# Add External version warning banner to the external version documentation
if 'branch' == 'external':
    extensions.insert(1, "readthedocs_ext.external_version_warning")

project_language = 'en'

# User's Sphinx configurations
language_user = globals().get('language', None)
latex_engine_user = globals().get('latex_engine', None)
latex_elements_user = globals().get('latex_elements', None)

# Remove this once xindy gets installed in Docker image and XINDYOPS
# env variable is supported
# https://github.com/rtfd/readthedocs-docker-images/pull/98
latex_use_xindy = False

chinese = any([
    language_user in ('zh_CN', 'zh_TW'),
    project_language in ('zh_CN', 'zh_TW'),
])

japanese = any([
    language_user == 'ja',
    project_language == 'ja',
])

if chinese:
    latex_engine = latex_engine_user or 'xelatex'

    latex_elements_rtd = {
        'preamble': '\\usepackage[UTF8]{ctex}\n',
    }
    latex_elements = latex_elements_user or latex_elements_rtd
elif japanese:
    latex_engine = latex_engine_user or 'platex'
