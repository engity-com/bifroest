import os
import os.path

repo = "engity-com/bifroest"
repo_http_url = "https://github.com/" + repo
repo_raw_url = "https://raw.githubusercontent.com/" + repo
raw_version = os.getenv('VERSION')
version = raw_version if raw_version is not None else "development"
branch = raw_version if raw_version is not None else "main"
release = raw_version if raw_version is not None else "latest"


def define_env(env):
    @env.macro
    def property_extended(name, data_type, default="", required=False, id_prefix="", heading=3, requirement=False):
        result = "#" * heading
        result += f" [`{name}`](#{id_prefix}property-{name})"
        result += f" {{ #{id_prefix}property-{name} class=property-title }}\n"
        result += "/// html | div.property-description\n"
        result += data_type
        if required:
            result += " :material-asterisk-circle-outline:{ title=\"Required\" data-hint-type=\"required\" }"
        if isinstance(requirement, str):
            result += f" [:material-lock-check-outline:{{ title=\"Requirement\" data-hint-type=\"requirement\" }}](#{requirement})"
        if isinstance(requirement, bool) and required:
            result += " :material-lock-check-outline:{ title=\"Requirement\" data-hint-type=\"requirement\" }"

        if default:
            if isinstance(default, str) and len(default) > 50:
                result += f""" = :material-keyboard-return:\n///\n
```{{.text .property-description-default-block linenums=0}}
{default}
```
"""
            else:
                result += f" = `{default}`" + "\n///"
        else:
            result += "\n///"
        return result

    @env.macro
    def property(name, data_type_title, data_type_reference=None, default="", required=False, id_prefix="", heading=3, requirement=False):
        if data_type_reference is None or data_type_reference == "":
            return property_extended(name, data_type_title, default, required, id_prefix, heading, requirement)

        return property_extended(name, f"[`{data_type_title}`]({data_type_reference})", default, required, id_prefix,
                                 heading, requirement)

    @env.macro
    def property_with_holder(name,
                             data_holder_title, data_holder_reference,
                             data_type_title, data_type_reference=None,
                             default="", required=False, id_prefix="", heading=3, requirement=False):
        holder_content = None
        if data_holder_title is not None and data_type_reference != "":
            if data_holder_reference is not None and data_holder_reference != "":
                holder_content = f"[`{data_holder_title}`]({data_holder_reference})"
            else:
                holder_content = f"`{data_holder_title}`"

        if holder_content is None:
            return property(name, data_type_title, data_type_reference, default, required, id_prefix, requirement)

        if data_type_title is None or data_type_title == "":
            raise ValueError("empty data_type_title")

        if data_type_reference is not None and data_type_reference != "":
            type_content = f"[`{data_type_title}`]({data_type_reference})"
        else:
            type_content = f"`{data_type_title}`"

        return property_extended(name, f"{holder_content}&lt;{type_content}&gt;", default, required, id_prefix, heading, requirement)

    @env.macro
    def asset_url(file, raw=False):
        if raw:
            return f"{repo_raw_url}/{branch}/{file}"

        return f"{repo_http_url}/blob/{branch}/{file}"

    @env.macro
    def asset_link(file, title=None, raw=False):
        url = asset_url(file, raw)
        title = title if title is not None else os.path.basename(file)

        return f"<a href={url}>{title}</a>"

    @env.macro
    def release_name(target=release):
        return target

    @env.macro
    def release_url(target = release):
        return f"{repo_http_url}/releases/{target}"

    @env.macro
    def release_asset_url(asset, target = release):
        return f"{repo_http_url}/releases/download/{target}/{asset}"

    @env.macro
    def rel_file_path(path, start):
        return os.path.relpath(path, os.path.dirname(start))
