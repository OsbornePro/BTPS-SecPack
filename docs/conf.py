import os
from datetime import datetime

project = "BTPS Security Package"
author = "Robert H. Osborne"
copyright = f"{datetime.now().year}, {author}"
release = "2026"

extensions = [
    "myst_parser",
    "sphinx_copybutton",
    "sphinx_design",
]

myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "fieldlist",
    "html_admonition",
    "html_image",
    "linkify",
    "tasklist",
]

source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}

root_doc = "index"
templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

html_theme = "furo"
html_title = "BTPS Security Package"
html_logo = "img/Logo.png"
html_favicon = "img/Logo.png"
html_static_path = ["_static"]
html_css_files = ["custom.css"]
html_baseurl = os.environ.get("READTHEDOCS_CANONICAL_URL", "")

html_theme_options = {
    "source_repository": "https://github.com/OsbornePro/BTPS-SecPack/",
    "source_branch": "master",
    "source_directory": "docs/",
    "footer_icons": [
        {
            "name": "GitHub",
            "url": "https://github.com/OsbornePro/BTPS-SecPack",
            "html": """
                <svg stroke=\"currentColor\" fill=\"currentColor\" stroke-width=\"0\" viewBox=\"0 0 16 16\">
                    <path d=\"M8 0C3.58 0 0 3.64 0 8.13c0 3.59 2.29 6.64 5.47 7.72.4.08.55-.18.55-.39 0-.19-.01-.83-.01-1.5-2.01.38-2.53-.5-2.69-.96-.09-.23-.48-.96-.82-1.15-.28-.16-.68-.56-.01-.57.63-.01 1.08.59 1.23.83.72 1.23 1.87.88 2.33.67.07-.53.28-.88.51-1.08-1.78-.21-3.64-.91-3.64-4.02 0-.89.31-1.62.82-2.19-.08-.21-.36-1.04.08-2.16 0 0 .67-.22 2.2.84A7.5 7.5 0 018 3.96a7.5 7.5 0 012 .28c1.53-1.06 2.2-.84 2.2-.84.44 1.12.16 1.95.08 2.16.51.57.82 1.3.82 2.19 0 3.12-1.87 3.81-3.65 4.02.29.25.54.74.54 1.51 0 1.09-.01 1.97-.01 2.24 0 .21.15.47.55.39A8.03 8.03 0 0016 8.13C16 3.64 12.42 0 8 0z\"/>
                </svg>
            """,
            "class": "",
        }
    ],
}

html_context = {
    "display_github": True,
    "github_user": "OsbornePro",
    "github_repo": "BTPS-SecPack",
    "github_version": "master",
    "conf_py_path": "/docs/",
}

copybutton_prompt_text = r">>> |\.\.\. |PS [^>]*> |\$ "
copybutton_prompt_is_regexp = True

if os.environ.get("READTHEDOCS") == "True":
    html_context["READTHEDOCS"] = True
