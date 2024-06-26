from importlib import metadata


# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx.ext.doctest",
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "myst_parser",
    "notfound.extension",
]

myst_enable_extensions = [
    "colon_fence",
    "smartquotes",
    "deflist",
]

# Move type hints into the description block, instead of the func definition.
autodoc_typehints = "description"
autodoc_typehints_description_target = "documented"

# GitHub has rate limits
linkcheck_ignore = [
    r"https://github.com/.*/(issues|pull|compare)/\d+",
    r"https://twitter.com/.*",
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# The suffix of source filenames.
source_suffix = ".rst"

# The master toctree document.
master_doc = "index"

# General information about the project.
project = "service-identity"
year = 2014
copyright = "2014, Hynek Schlawack"

# The version info for the project you're documenting, acts as replacement for
# |version| and |release|, also used in various other places throughout the
# built documents.

release = metadata.version("service-identity")
# The short X.Y version.
version = release.rsplit(".", 1)[0]

# Avoid confusing in-dev versions.
if "dev" in release:
    release = version = "UNRELEASED"

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = ["_build"]


# -- Options for HTML output ----------------------------------------------

html_theme = "furo"
html_theme_options = {
    "top_of_page_buttons": [],
    "light_css_variables": {
        "font-stack": "Inter, sans-serif",
        "font-stack--monospace": "BerkeleyMono, MonoLisa, ui-monospace, "
        "SFMono-Regular, Menlo, Consolas, Liberation Mono, monospace",
    },
}
html_static_path = ["_static"]
html_css_files = ["custom.css"]

# Output file base name for HTML help builder.
htmlhelp_basename = "service-identitydoc"


# -- Options for LaTeX output ---------------------------------------------

latex_elements = {}

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title,
#  author, documentclass [howto, manual, or own class]).
latex_documents = [
    (
        "index",
        "service-identity.tex",
        "service\\_identity Documentation",
        "Hynek Schlawack",
        "manual",
    )
]

# -- Options for manual page output ---------------------------------------

# One entry per manual page. List of tuples
# (source start file, name, description, authors, manual section).
man_pages = [
    (
        "index",
        "service-identity",
        "service-identity Documentation",
        ["Hynek Schlawack"],
        1,
    )
]

# -- Options for Texinfo output -------------------------------------------

# Grouping the document tree into Texinfo files. List of tuples
# (source start file, target name, title, author,
#  dir menu entry, description, category)
texinfo_documents = [
    (
        "index",
        "service-identity",
        "service-identity Documentation",
        "Hynek Schlawack",
        "service-identity",
        "Service Identity Verification for pyOpenSSL",
        "Miscellaneous",
    )
]


intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "pyopenssl": ("https://www.pyopenssl.org/en/stable/", None),
    "cryptography": ("https://cryptography.io/en/stable/", None),
}
