import json
import os as pos
import os.path as path
from collections import OrderedDict
from enum import Enum
from pathlib import PurePath
from typing import Sequence, List

from mkdocs.structure.files import File
from mkdocs_macros.context import Files
from mkdocs_macros.plugin import MacrosPlugin

repo = "engity-com/bifroest"
repo_http_url = "https://github.com/" + repo
repo_raw_url = "https://raw.githubusercontent.com/" + repo
repo_container_uri = "ghcr.io/" + repo
raw_version = pos.getenv('VERSION')
release = (("v" if raw_version.__len__() > 0 and raw_version[0].isdigit() else "") + raw_version) if raw_version is not None and raw_version.__len__() > 0 else "latest"
branch = (("v" if raw_version.__len__() > 0 and raw_version[0].isdigit() else "") + raw_version) if raw_version is not None and raw_version.__len__() > 0 else "main"


class Packaging(str, Enum):
    archive = 'archive'
    image = 'image'

class Os(str, Enum):
    linux = 'linux'
    windows = 'windows'


class Arch(str, Enum):
    i386 = '386'
    amd64 = 'amd64'
    armv6 = 'armv6'
    armv7 = 'armv7'
    arm64 = 'arm64'
    mips64le = 'mips64le'
    riscv64 = 'riscv64'


class EditionKind(str, Enum):
    generic = 'generic'
    extended = 'extended'


class Edition:
    os: Os
    arch: Arch
    kind: EditionKind
    binary_supported: bool
    image_supported: bool

    def __init__(
            self,
            o: Os,
            arch: Arch,
            kind: EditionKind,
            binary_supported: bool = False,
            image_supported: bool = False
    ):
        self.os = o
        self.arch = arch
        self.kind = kind
        self.binary_supported = binary_supported
        self.image_supported = image_supported

        if not binary_supported and image_supported:
            raise Exception(f"image can't be supported if binary isn't")


def editions_of(
        o: Os,
        arch: Arch,
        generic_binary_supported: bool = False,
        generic_image_supported: bool = False,
        extended_binary_supported: bool = False,
        extended_image_supported: bool = False,
) -> List[Edition]:
    if not generic_binary_supported and extended_binary_supported:
        raise Exception(f"extended can't be supported if generic isn't")

    if not generic_binary_supported:
        return []

    generic = Edition(o, arch, EditionKind.generic, generic_binary_supported, generic_image_supported)

    if not extended_binary_supported:
        return [generic]

    return [
        generic,
        Edition(o, arch, EditionKind.extended, extended_binary_supported, extended_image_supported),
    ]


class SupportMatrix:
    entries: OrderedDict[Os, OrderedDict[Arch, OrderedDict[EditionKind, Edition]]]

    def __init__(self, *edss: List[Edition]):
        self.entries: OrderedDict[Os, OrderedDict[Arch, OrderedDict[EditionKind, Edition]]] = OrderedDict({})

        for eds in edss:
            for ed in eds:
                if not self.entries.__contains__(ed.os):
                    self.entries[ed.os] = OrderedDict[Arch, OrderedDict[EditionKind, Edition]]({})
                by_os = self.entries[ed.os]

                if not by_os.__contains__(ed.arch):
                    by_os[ed.arch] = OrderedDict[EditionKind, Edition]({})
                by_arch = by_os[ed.arch]

                by_arch[ed.kind] = ed

    def lookup(
            self,
            os: Os | str,
            arch: Arch | str,
            kind: EditionKind | str
    ) -> Edition | None:

        if type(os) is str:
            os = Os[os]

        if type(arch) is str:
            arch = Arch[arch]

        if type(kind) is str:
            kind = EditionKind[kind]

        if not self.entries.__contains__(os):
            return None

        if not self.entries[os].__contains__(arch):
            return None

        if not self.entries[os][arch].__contains__(kind):
            return None

        return self.entries[os][arch][kind]

    def is_binary_supported(
            self,
            os: Os | str,
            arch: Arch | str,
            kind: EditionKind | str
    ) -> bool:

        ed = self.lookup(os, arch, kind)

        return False if ed.binary_supported is None else ed.binary_supported

    def is_image_supported(
            self,
            os: Os | str,
            arch: Arch | str,
            kind: EditionKind | str
    ) -> bool:

        ed = self.lookup(os, arch, kind)

        return False if ed.image_supported is None else ed.image_supported


support_matrix = SupportMatrix(
    editions_of(
        Os.linux, Arch.i386,
        True, True,
        True, False
    ),
    editions_of(
        Os.linux, Arch.amd64,
        True, True,
        True, True
    ),
    editions_of(
        Os.linux, Arch.armv6,
        True, True,
        True, False
    ),
    editions_of(
        Os.linux, Arch.armv7,
        True, True,
        True, True
    ),
    editions_of(
        Os.linux, Arch.arm64,
        True, True,
        True, True
    ),
    editions_of(
        Os.linux, Arch.mips64le,
        True, True,
        True, False
    ),
    editions_of(
        Os.linux, Arch.riscv64,
        True, True,
        True, False
    ),

    editions_of(
        Os.windows, Arch.amd64,
        True, True,
    ),
    editions_of(
        Os.windows, Arch.arm64,
        True, False,
    )
)


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
    def container_image_uri(
            tag: str | None = None
    ) -> str:
        if tag is not None and tag.find("*") >= 0:
            if raw_version is not None:
                tag = tag.replace("*", f"{"-" if tag.find("*") > 0 else ""}{raw_version}")
            else:
                tag = tag.replace("*", "")

        return f"{repo_container_uri}{f":{tag}" if tag is not None else ""}"

    @env.macro
    def container_packages_url() -> str:
        return f"{repo_http_url}/pkgs/container/bifroest"


    @env.macro
    def asset_url(file: str, raw: bool = False) -> str:
        if raw:
            return f"{repo_raw_url}/{branch}/{file}"

        return f"{repo_http_url}/blob/{branch}/{file}"

    @env.macro
    def asset_link(file: str, title: str | None = None, raw: bool = False) -> str:
        url = asset_url(file, raw)
        title = title if title is not None else path.basename(file)

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
    def rel_file_path(in_path: str, start: str) -> str:
        return path.relpath(in_path, path.dirname(start))

    @env.macro
    def compatibility(
            supported: bool | None = False,
            label: str | None = None,
            os: Os | str | None = None
    ) -> str:
        title = None
        if label is not None:
            title = f"<code>{label}</code>"
        if os is not None:
            if type(os) is str:
                os = Os[os]

            title = f"<code>{os.name}</code>{f"/{title}" if title is not None else ""}"

        if supported is None:
            return f":octicons-circle-24:{{. data-supported=none title='{f"{title} is not supported" if title is not None else "Not supported"}'}}"
        elif supported:
            return f":octicons-check-circle-24:{{. data-supported=true title='{f"{title} is supported" if title is not None else "Supported"}'}}"
        else:
            return f":octicons-x-circle-24:{{. data-supported=false title='{f"{title} is not supported" if title is not None else "Not supported"}'}}"

    @env.macro
    def compatibility_editions(
            generic: bool | None = False,
            extended: bool | None = False,
            os: Os | str | None = None
    ) -> str:
        if os is None:
            return f"{compatibility(generic, "generic")}/{compatibility(extended, "extended")}"
        else:
            if type(os) is str:
                os = Os[os]

            files: Files = env.variables.files
            file: File = files.get_file_from_path("setup/distribution.md")
            dst = PurePath(path.relpath(file.src_path, path.dirname(env.page.file.src_path)))
            return (f"[{compatibility(generic, "generic", os)}]({dst.as_posix()}#{os.name}-generic)/"
                    f"[{compatibility(extended, "extended", os)}]({dst.as_posix()}#{os.name}-extended)")

    @env.macro
    def is_binary_supported(o: Os | str, arch: Arch | str, kind: EditionKind | str) -> bool:
        return support_matrix.is_binary_supported(o, arch, kind)

    @env.macro
    def is_image_supported(o: Os | str, arch: Arch | str, kind: EditionKind | str) -> bool:
        return support_matrix.is_image_supported(o, arch, kind)

    @env.macro
    def compatibility_matrix(
            os: Os | None = None,
            packaging: str | Packaging | None = None,
    ) -> str:
        if type(packaging) is str:
            packaging = Packaging[packaging]

        result = '<table markdown="span" data-kind="compatibility_matrix"><thead markdown="span">'
        result += f'<tr markdown="span"><th{' rowspan="2"' if packaging is None else ''}>Architecture</th>'
        if os is not None:
            result += f'<th{' colspan="2"' if packaging is None else ''} markdown="span">{dist(os)}</th>'
        else:
            for osv in Os:
                result += f'<th{' colspan="2"' if packaging is None else ''} markdown="span">{dist(osv)}</th>'
        result += "</tr>"

        if packaging is None:
            if os is not None:
                result += '<th>Binary</th><th>Image</th>'
            else:
                for _ in Os:
                    result += '<th>Binary</th><th>Image</th>'
            result += '</tr>'

        result += '</thead><tbody markdown="span">'

        for arch in Arch:
            result += f'<tr markdown="span"><td markdown="span">`{arch.name}`</td>'

            if os is not None:
                generic = support_matrix.lookup(os, arch, EditionKind.generic)
                extended = support_matrix.lookup(os, arch, EditionKind.extended)
                if packaging == Packaging.archive or packaging is None:
                    result += f'<td markdown="span">{compatibility_editions(True if generic and generic.binary_supported else None, True if extended and extended.binary_supported else None, os)}</td>'
                if packaging == Packaging.image or packaging is None:
                    result += f'<td markdown="span">{compatibility_editions(True if generic and generic.image_supported else None, True if extended and extended.image_supported else None, os)}</td>'
            else:
                for osv in Os:
                    generic = support_matrix.lookup(osv, arch, EditionKind.generic)
                    extended = support_matrix.lookup(osv, arch, EditionKind.extended)
                    if packaging == Packaging.archive or packaging is None:
                        result += f'<td markdown="span">{compatibility_editions(True if generic and generic.binary_supported else None, True if extended and extended.binary_supported else None, osv)}</td>'
                    if packaging == Packaging.image or packaging is None:
                        result += f'<td markdown="span">{compatibility_editions(True if generic and generic.image_supported else None, True if extended and extended.image_supported else None, osv)}</td>'

            result += '<tr>'

        result += '</tbody>'
        result += '</table>'

        return result

    @env.macro
    def dist(os: Os | str, edition: EditionKind | str | None = None) -> str:
        if type(os) is str:
            os = Os[os]
        if type(edition) is str:
            edition = EditionKind[edition]

        files: Files = env.variables.files
        file: File = files.get_file_from_path("setup/distribution.md")
        dst = PurePath(path.relpath(file.src_path, path.dirname(env.page.file.src_path)))
        if edition is None:
            return f"[`{os.name}`]({dst.as_posix()}#{os.name}){{. class=dist-ref}}"
        else:
            return f"[`{os.name}`/`{edition.name}`]({dst.as_posix()}#{os.name}-{edition.name}){{. class=dist-edition-ref}}"

    @env.macro
    def else_ref() -> str:
        return "<span class=\"else-ref\">anything else</span>"

    @env.macro
    def escape_html(given: str) -> str:
        return str(given.encode('ascii', 'xmlcharrefreplace'), 'UTF-8')

    @env.macro
    def type_of(given):
        return type(given)
