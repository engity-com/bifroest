import os
import posixpath

from mkdocs.structure.files import Files
from mkdocs.structure.pages import Page


# noinspection PyUnusedLocal
def on_page_markdown(markdown: str, page: Page, config, files: Files):
    is_homepage = page.is_homepage or page.file.dest_path == "index.html"
    title = page.meta.get("title", page.title)
    if not is_homepage:
        title = f"{title} - {config.site_name}"

    description = page.meta["description"] if "description" in page.meta else config.site_description
    url = ("{}".
           format(posixpath.join(config.site_url or ".", config.extra["social_banner"])).
           replace(os.path.sep, "/")
           )

    page.meta["meta"] = page.meta.get("meta", []) + [
        {"property": "og:locale", "content": "en"},
        {"property": "og:type", "content": "website" if is_homepage else "article"},
        {"property": "og:title", "content": title},
        {"property": "og:description", "content": description},
        {"property": "og:image", "content": url},
        {"property": "og:image:type", "content": "image/png"},
        {"property": "og:image:width", "content": "1280"},
        {"property": "og:image:height", "content": "640"},
        {"property": "og:url", "content": page.canonical_url},

        {"name": "twitter:site", "content": "@ENGITY_com"},
        {"name": "twitter:card", "content": "summary_large_image"},
        {"name": "twitter:title", "content": title},
        {"name": "twitter:description", "content": description},
        {"name": "twitter:image", "content": url}
    ]
