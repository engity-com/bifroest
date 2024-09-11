import json
import os
import os.path
from typing import Sequence

from mkdocs_macros.plugin import MacrosPlugin

repo = "engity-com/bifroest"
repo_http_url = "https://github.com/" + repo
repo_raw_url = "https://raw.githubusercontent.com/" + repo
raw_version = os.getenv('VERSION')
version = raw_version if raw_version is not None else "development"
branch = raw_version if raw_version is not None else "main"
release = raw_version if raw_version is not None else "latest"


class TypeRefT:
    @property
    def title(self) -> str:
        pass

    @property
    def ref(self) -> str | None:
        pass

    @property
    def markdown(self) -> str:
        pass


class TypeRef:
    def __init__(
            self,
            title: str,
            ref: str | None = None,
            args: Sequence[TypeRefT] | None = None,
    ):
        self.title = title
        self.ref = ref
        self.args = args

    @property
    def markdown(self) -> str:
        result = self.title
        if isinstance(self.ref, str):
            result = f"[{result}]({self.ref})"

        if isinstance(self.args, Sequence) and len(self.args) > 0:
            result += "<"
            first = True
            for arg in self.args:
                if first:
                    first = False
                else:
                    result += ","
                result += arg.markdown
            result += ">"

        return result


def define_env(env: MacrosPlugin):
    @env.macro
    def property_extended(
            name: str,
            data_type: TypeRefT | TypeRef,
            default=None,
            required: bool = False,
            id_prefix: str | None = None,
            heading: int = 3,
            requirement: bool | str = False,
            optional: bool = False,
    ):
        if id_prefix is None:
            id_prefix = ""
        id = f"{id_prefix}property-{name.replace("*", "any")}"

        result = "#" * heading
        result += f" `{name}`"
        result += f" {{ #{id} class=property-title }}\n"
        result += "/// html | div.property-description\n"
        result += "<span class=\"property-assign\"></span>"
        result += data_type.markdown
        if required:
            result += " :material-asterisk-circle-outline:{ title=\"Required\" data-hint-type=\"required\" }"
        if optional:
            result += " :material-radiobox-indeterminate-variant:{ title=\"Optional\" data-hint-type=\"optional\" }"
        if isinstance(requirement, str):
            result += f" [:material-lock-check-outline:{{ title=\"Requirement\" data-hint-type=\"requirement\" }}](#{requirement})"
        if isinstance(requirement, bool) and requirement:
            result += " :material-lock-check-outline:{ title=\"Requirement\" data-hint-type=\"requirement\" }"

        if default is not None:
            default_str = json.dumps(default, ensure_ascii=False)
            if len(default_str) > 30:
                result += f""" = :material-keyboard-return:\n///\n
```{{.json .property-description-default-block linenums=0}}
{default_str}
```
"""
            else:
                result += f" = `{default_str}`" + "\n///"
        else:
            result += "\n///"
        return result

    @env.macro
    def property(
            name: str,
            data_type_title: str,
            data_type_reference: str | None = None,
            default=None,
            required: bool = False,
            id_prefix: str | None = "",
            heading: int = 3,
            requirement: bool = False,
            optional: bool = False,
    ):
        return property_extended(
            name=name,
            data_type=TypeRef(data_type_title, data_type_reference),
            default=default,
            required=required,
            id_prefix=id_prefix,
            heading=heading,
            requirement=requirement,
            optional=optional
        )

    @env.macro
    def property_with_holder(
            name: str,
            data_holder_title: str, data_holder_reference: str | None,
            data_type_title: str, data_type_reference: str | None = None,
            default=None,
            required: bool = False,
            id_prefix: str = "",
            heading: int = 3,
            requirement: bool = False,
            optional: bool = False,
    ) -> str:
        # noinspection PyTypeChecker
        return property_extended(
            name=name,
            data_type=TypeRef(
                data_holder_title, data_holder_reference,
                [
                    TypeRef(data_type_title, data_type_reference)
                ] if data_type_title is not None and data_type_title != "" else []
            ),
            default=default,
            required=required,
            id_prefix=id_prefix,
            heading=heading,
            requirement=requirement,
            optional=optional
        )

    @env.macro
    def flag_extended(
            name: str,
            data_type: TypeRefT | TypeRef | None,
            default=None,
            required: bool = False,
            id_prefix: str | None = None,
            heading: int = 3,
            aliases: Sequence[str] | None = None
    ):
        if id_prefix is None:
            id_prefix = ""
        id = f"{id_prefix}flag-{name.replace("*", "any")}"

        result = "#" * heading
        result += f" `--{name}`"
        result += f" {{ #{id} class=property-title }}\n"

        if data_type or (aliases is not None and len(aliases) > 0):
            result += "/// html | div.property-description\n"

            if aliases is not None and len(aliases) > 0:
                for alias in aliases:
                    if len(alias) == 1:
                        result += f"`-{alias}`{{. class=property-alias}}"
                    else:
                        result += f"`--{alias}`{{. class=property-alias}}"
            result += "<span class=\"property-assign\"></span>"
            result += data_type.markdown
            if required:
                result += " :material-asterisk-circle-outline:{ title=\"Required\" data-hint-type=\"required\" }"

            if default is not None:
                default_str = json.dumps(default, ensure_ascii=False)
                if len(default_str) > 30:
                    result += f""" = :material-keyboard-return:\n///\n
```{{.json .property-description-default-block linenums=0}}
{default_str}
```
"""
                else:
                    result += f" = `{default_str}`" + "\n///"
            else:
                result += "\n///"
        return result

    @env.macro
    def flag(
            name: str,
            data_type_title: str | None = None,
            data_type_reference: str | None = None,
            default=None,
            required: bool = False,
            id_prefix: str | None = "",
            heading: int = 3,
            aliases: Sequence[str] | None = None
    ):
        return flag_extended(
            name=name,
            data_type=TypeRef(data_type_title, data_type_reference) if data_type_title is not None else None,
            default=default,
            required=required,
            id_prefix=id_prefix,
            heading=heading,
            aliases=aliases,
        )

    @env.macro
    def flag_with_holder(
            name: str,
            data_holder_title: str, data_holder_reference: str | None,
            data_type_title: str, data_type_reference: str | None = None,
            default=None,
            required: bool = False,
            id_prefix: str = "",
            heading: int = 3,
            aliases: Sequence[str] | None = None
    ) -> str:
        # noinspection PyTypeChecker
        return flag_extended(
            name=name,
            data_type=TypeRef(
                data_holder_title, data_holder_reference,
                [
                    TypeRef(data_type_title, data_type_reference)
                ] if data_type_title is not None and data_type_title != "" else []
            ),
            default=default,
            required=required,
            id_prefix=id_prefix,
            heading=heading,
            aliases=aliases,
        )

    @env.macro
    def asset_url(file: str, raw: bool = False) -> str:
        if raw:
            return f"{repo_raw_url}/{branch}/{file}"

        return f"{repo_http_url}/blob/{branch}/{file}"

    @env.macro
    def asset_link(file: str, title: str | None = None, raw: bool = False) -> str:
        url = asset_url(file, raw)
        title = title if title is not None else os.path.basename(file)

        return f"<a href={url}>{title}</a>"

    @env.macro
    def release_name(target: str = release) -> str:
        return target

    @env.macro
    def release_url(target: str = release) -> str:
        return f"{repo_http_url}/releases/{target}"

    @env.macro
    def release_asset_url(asset: str, target: str = release) -> str:
        return f"{repo_http_url}/releases/download/{target}/{asset}"

    @env.macro
    def rel_file_path(path: str, start: str) -> str:
        return os.path.relpath(path, os.path.dirname(start))

    @env.macro
    def compatibility(supported: bool = False) -> str:
        if supported:
            return ":octicons-check-circle-24:{. data-supported=true title='Supported'} `*`"

        return ":octicons-x-circle-24:{. data-supported=false title='Not supported'}"

    @env.macro
    def escape_html(given: str) -> str:
        return str(given.encode('ascii', 'xmlcharrefreplace'), 'UTF-8')

    @env.macro
    def type_of(given):
        return type(given)
