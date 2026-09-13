import html
import json
import os as pos
import os.path as path
import re
from collections import OrderedDict
from enum import Enum
from pathlib import PurePath
from typing import Sequence, List
from urllib.parse import parse_qs, quote, urlparse

from mkdocs.structure.files import File
from mkdocs_macros.context import Files
from mkdocs_macros.plugin import MacrosPlugin

repo = "engity-com/bifroest"
repo_http_url = "https://github.com/" + repo
repo_raw_url = "https://raw.githubusercontent.com/" + repo
repo_container_uri = "ghcr.io/" + repo
raw_version = pos.getenv('VERSION')
release = (("v" if raw_version.__len__() > 0 and raw_version[
    0].isdigit() else "") + raw_version) if raw_version is not None and raw_version.__len__() > 0 else "latest"
branch = (("v" if raw_version.__len__() > 0 and raw_version[
    0].isdigit() else "") + raw_version) if raw_version is not None and raw_version.__len__() > 0 else "main"


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
        Os.linux, Arch.riscv64,
        True, True,
        False, False
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


def load_release_manifest() -> dict:
    filename = pos.getenv('RELEASE_MANIFEST_FILE')
    if filename is None or filename.__len__() == 0:
        return fallback_release_manifest()

    with open(filename, 'r', encoding='utf-8') as source:
        manifest = json.load(source)
    if manifest.get('schemaVersion') != 1:
        raise Exception(f"unsupported release manifest schema in {filename}")
    if manifest.get('project') != repo:
        raise Exception(f"release manifest project does not match {repo}")
    if release != 'latest' and manifest.get('version') != release:
        raise Exception(f"release manifest version {manifest.get('version')} does not match {release}")

    assets = manifest.get('assets')
    variants = manifest.get('variants')
    if not isinstance(assets, list) or not isinstance(variants, list):
        raise Exception("release manifest has no asset or variant inventory")
    for key in ('manifestAsset', 'checksumAsset'):
        name = manifest.get(key)
        if not isinstance(name, str) or path.basename(name) != name:
            raise Exception(f"release manifest has invalid {key}")
    asset_names = set()
    for asset in assets:
        name = asset.get('name')
        if not isinstance(name, str) or path.basename(name) != name or name in asset_names:
            raise Exception(f"invalid or duplicate release asset name {name}")
        asset_names.add(name)

    referenced = set()
    for variant in variants:
        for key in ('archive', 'notice'):
            if variant.get(key):
                referenced.add(variant[key])
        for subject in variant.get('sboms', {}).values():
            for name in subject.values():
                if name:
                    referenced.add(name)
    missing_inventory = referenced - asset_names
    if missing_inventory:
        raise Exception(f"release manifest references unknown assets: {sorted(missing_inventory)}")

    expected_variants = set()
    expected_images = set()
    for o, by_os in support_matrix.entries.items():
        for arch, by_arch in by_os.items():
            for kind, edition in by_arch.items():
                if edition.binary_supported:
                    key = (o.value, arch.value, kind.value)
                    expected_variants.add(key)
                    if edition.image_supported:
                        expected_images.add(key)
    actual_variants = set()
    actual_images = set()
    for variant in variants:
        key = (variant.get('os'), variant.get('architecture'), variant.get('edition'))
        if key in actual_variants:
            raise Exception(f"duplicate release variant {key}")
        actual_variants.add(key)
        if not variant.get('archive') or not variant.get('notice'):
            raise Exception(f"release variant {key} has no archive or notice")
        archive_sboms = variant.get('sboms', {}).get('archive', {})
        if not archive_sboms.get('spdx') or not archive_sboms.get('cycloneDx'):
            raise Exception(f"release variant {key} has incomplete archive SBOMs")
        if variant.get('image') is not None:
            actual_images.add(key)
            image_sboms = variant.get('sboms', {}).get('image', {})
            if not image_sboms.get('spdx') or not image_sboms.get('cycloneDx'):
                raise Exception(f"release variant {key} has incomplete image SBOMs")
    if actual_variants != expected_variants:
        raise Exception("release variants do not match the documented support matrix")
    if actual_images != expected_images:
        raise Exception("release image variants do not match the documented support matrix")

    inventory_filename = pos.getenv('RELEASE_ASSETS_FILE')
    if inventory_filename is not None and inventory_filename.__len__() > 0:
        with open(inventory_filename, 'r', encoding='utf-8') as source:
            published = {line.strip() for line in source if line.strip().__len__() > 0}
        expected = asset_names | {manifest['manifestAsset'], manifest['checksumAsset']}
        missing_release_assets = expected - published
        if missing_release_assets:
            raise Exception(f"release is missing assets: {sorted(missing_release_assets)}")
        unexpected_release_assets = published - expected
        if unexpected_release_assets:
            raise Exception(f"release has unexpected assets: {sorted(unexpected_release_assets)}")

    return manifest


def fallback_release_manifest() -> dict:
    variants = []
    version = raw_version[1:] if raw_version is not None and raw_version.startswith('v') else raw_version
    for o, by_os in support_matrix.entries.items():
        for arch, by_arch in by_os.items():
            for kind, edition in by_arch.items():
                if not edition.binary_supported:
                    continue
                prefix = f"bifroest-{o.value}-{arch.value}-{kind.value}"
                archive = prefix + ('.zip' if o == Os.windows else '.tgz')
                variant = {
                    'os': o.value,
                    'architecture': arch.value,
                    'edition': kind.value,
                    'archive': archive,
                    'notice': prefix + '.third-party-notices.txt',
                    'sboms': {
                        'archive': {
                            'spdx': archive + '.spdx.json',
                            'cycloneDx': archive + '.cdx.json',
                        }
                    },
                }
                if edition.image_supported:
                    image_name = f"bifroest-image-{o.value}-{arch.value}-{kind.value}"
                    tag = kind.value if version is None or version.__len__() == 0 else f"{kind.value}-{version}"
                    variant['sboms']['image'] = {
                        'spdx': image_name + '.spdx.json',
                        'cycloneDx': image_name + '.cdx.json',
                    }
                    variant['image'] = {'tag': f"{repo_container_uri}:{tag}"}
                variants.append(variant)
    return {
        'schemaVersion': 1,
        'project': repo,
        'version': release,
        'manifestAsset': 'bifroest-release-manifest.json',
        'checksumAsset': 'bifroest-checksums.txt',
        'assets': [],
        'variants': variants,
    }


def resolve_container_image_reference(image: dict, registry: str) -> tuple[str, str | None]:
    raw_tag = image.get('tag')
    if raw_tag is not None and not isinstance(raw_tag, str):
        raise Exception("release manifest has an invalid image tag")

    target_tag = None
    tagged_reference = None
    embedded_digest = None
    if raw_tag:
        parsed = urlparse(raw_tag)
        if parsed.scheme in ('http', 'https'):
            tags = parse_qs(parsed.query).get('tag', [])
            if tags:
                target_tag = tags[0]
        else:
            tagged_reference, _, embedded_digest = raw_tag.partition('@')
            last_slash = tagged_reference.rfind('/')
            last_colon = tagged_reference.rfind(':')
            if last_colon > last_slash:
                target_tag = tagged_reference[last_colon + 1:]

    if target_tag is not None and re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', target_tag) is None:
        raise Exception(f"release manifest has an invalid image tag {target_tag}")

    digest = image.get('platformDigest') or image.get('indexDigest') or embedded_digest or None
    digest_reference = image.get('platformReference') if image.get('platformDigest') else image.get('indexReference')
    if digest is not None:
        if not isinstance(digest, str) or re.fullmatch(r'sha256:[0-9a-f]{64}', digest) is None:
            raise Exception(f"release manifest has an invalid image digest {digest}")

    repository = registry
    if digest_reference:
        if not isinstance(digest_reference, str):
            raise Exception("release manifest has an invalid image reference")
        repository = digest_reference.partition('@')[0]
    elif tagged_reference:
        last_slash = tagged_reference.rfind('/')
        last_colon = tagged_reference.rfind(':')
        repository = tagged_reference[:last_colon] if last_colon > last_slash else tagged_reference

    if not repository:
        raise Exception("release manifest has no image registry")
    reference = f"{repository}:{target_tag}" if target_tag else (tagged_reference or repository)
    if digest:
        reference = f"{reference.partition('@')[0]}@{digest}"
    return reference, target_tag


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
            ref: str | None,
            *args: TypeRefT | None,
    ):
        def filter_out_nones(candidate: TypeRefT | None) -> bool:
            return candidate is not None

        self.title = title
        self.ref = ref
        self.args = list(filter(filter_out_nones, args))

    @property
    def markdown(self) -> str:
        array = self.title == "Array" and self.ref is None and len(self.args) == 1
        if array:
            result = '<span data-hint-type="array">[]</span>'
        else:
            result = self.title
            if isinstance(self.ref, str):
                result = f"[{result}]({self.ref})"

        if len(self.args) > 0:
            if not array:
                result += "&lt;"
            first = True
            for arg in self.args:
                if first:
                    first = False
                else:
                    result += ","
                result += arg.markdown
            if not array:
                result += "&gt;"

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
            template_context: TypeRefT | TypeRef | None = None,
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

        if template_context is not None:
            templating: File = env.variables.files.get_file_from_path("reference/templating/index.md")
            templating_ref = PurePath(
                path.relpath(templating.src_path, path.dirname(env.page.file.src_path))).as_posix()
            result += f" [:material-file-replace-outline:{{ title=\"Templated with {template_context.title}\" data-hint-type=\"templated\" }}]({templating_ref}) {template_context.markdown}"

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
            default_str = default_str.replace("`", "\\`")
            if len(default_str) > 30:
                result += f""" = :material-keyboard-return:\n///\n
```{{.json .property-description-default-block linenums=0}}
{default_str}
```
"""
            else:
                result += f" = <code>{html.escape(default_str)}</code>" + "\n///"
        else:
            result += "\n///"
        return result

    @env.macro
    def ref(
            title: str | None = None,
            ref: str | None = None,
            *args: TypeRef | TypeRefT | None,
    ) -> TypeRef | TypeRefT | None:
        if ref is not None:
            if title is None:
                if ref == "bool" or ref == "string" and ref == "number" and ref == "uint" and ref == "integer" and ref == "float":
                    title = ref
                else:
                    file: File = env.variables.files.get_file_from_path(
                        path.normpath(path.dirname(env.page.file.src_path) + "/" + ref))
                    if file is None:
                        title = path.basename(ref)
                    else:
                        title = file.page.title

            return TypeRef(title, ref, *args)

        if title is not None:
            return TypeRef(title, None, *args)

        return None

    @env.macro
    def array_ref(
            title: str | None = None,
            ref_n: str | None = None,
            *args: TypeRef | TypeRefT | None,
    ) -> TypeRef | TypeRefT | None:
        return ref("Array", None, ref(title, ref_n, *args))

    @env.macro
    def property(
            name: str,
            data_type: str | TypeRef | TypeRefT,
            data_type_reference: str | None = None,
            default=None,
            required: bool = False,
            id_prefix: str | None = "",
            heading: int = 3,
            requirement: bool = False,
            optional: bool = False,
            template_context_title: str | None = None,
            template_context: str | None = None,
    ):
        if isinstance(data_type, str):
            data_type = TypeRef(data_type, data_type_reference)

        return property_extended(
            name=name,
            data_type=data_type,
            default=default,
            required=required,
            id_prefix=id_prefix,
            heading=heading,
            requirement=requirement,
            optional=optional,
            template_context=ref(template_context_title, template_context)
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
            data_type: str | TypeRef | TypeRefT | None = None,
            data_type_reference: str | None = None,
            default=None,
            required: bool = False,
            id_prefix: str | None = "",
            heading: int = 3,
            aliases: Sequence[str] | None = None
    ):
        if isinstance(data_type, str):
            data_type = TypeRef(data_type, data_type_reference)

        return flag_extended(
            name=name,
            data_type=data_type,
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
    def container_packages_url(tag: str | None = None) -> str:
        result = f"{repo_http_url}/pkgs/container/bifroest"
        return result if tag is None else f"{result}?tag={quote(tag, safe='')}"

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
        if target == "latest":
            return f"{repo_http_url}/releases/latest/download/{quote(asset)}"
        return f"{repo_http_url}/releases/download/{quote(target, safe='')}/{quote(asset)}"

    @env.macro
    def compliance_matrix() -> str:
        manifest = load_release_manifest()

        result = '<table markdown="1" data-kind="compliance_matrix"><thead markdown="1">'
        result += ('<tr markdown="1">'
                   '<th rowspan="2">Variant</th>'
                   '<th rowspan="2" class="vertical">Notice</th>'
                   '<th colspan="3">Archive</th>'
                   '<th colspan="3">OCI</th>'
                   '</tr>'
                   )
        result += ('<tr markdown="1">'
                   '<th class="vertical">Download</th>'
                   '<th class="vertical">SPDX</th>'
                   '<th class="vertical">CycloneDX</th>'
                   '<th class="vertical">Reference</th>'
                   '<th class="vertical">SPDX</th>'
                   '<th class="vertical">CycloneDX</th>'
                   '</tr>'
                   )
        result += '</thead><tbody markdown="1">'

        def asset(name: str | None, label: str) -> str:
            if name is None or name.__len__() == 0:
                return "-"
            return f"[:octicons-download-24:{{. title='{f"{label}"}'}}]({release_asset_url(name)})"

        for variant in manifest['variants']:
            platform = f"`{variant['os']}/{variant['architecture']}/{variant['edition']}`"
            sboms = variant.get('sboms', {})
            archive_sboms = sboms.get('archive', {})
            image_sboms = sboms.get('image', {})
            image = variant.get('image')
            image_cell = "-"
            if image is not None:
                full_reference, target_tag = resolve_container_image_reference(
                    image, manifest.get('registry', repo_container_uri))
                escaped_reference = html.escape(full_reference, quote=True)
                target_url = html.escape(container_packages_url(target_tag), quote=True)
                image_cell = (
                    f'<a href="{target_url}" data-reference="{escaped_reference}" title="{escaped_reference}" '
                    'onclick="if (!navigator.clipboard || !window.isSecureContext) return true; '
                    'event.preventDefault(); try { navigator.clipboard.writeText(this.dataset.reference)'
                    '.catch(function () { window.location.assign(this.href); }.bind(this)); } '
                    'catch (_) { window.location.assign(this.href); } return false;">'
                    ':octicons-copy-24:</a>'
                )

            result += ('<tr markdown="1">'
                       f'<td markdown="1">{platform}</td>'
                       f'<td markdown="1">{asset(variant.get('notice'), 'Notice')}</td>'
                       f'<td markdown="1">{asset(variant.get('archive'), 'Archive')}</td>'
                       f'<td markdown="1">{asset(archive_sboms.get('spdx'), 'SPDX')}</td>'
                       f'<td markdown="1">{asset(archive_sboms.get('cycloneDx'), 'CycloneDX')}</td>'
                       f'<td markdown="1">{image_cell}</td>'
                       f'<td markdown="1">{asset(image_sboms.get('spdx'), 'SPDX')}</td>'
                       f'<td markdown="1">{asset(image_sboms.get('cycloneDx'), 'CycloneDX')}</td>'
                       '</tr>')

        result += "</tbody></table>"
        return result

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

        result = '<table markdown="1" data-kind="compatibility_matrix"><thead markdown="1">'
        result += f'<tr markdown="1"><th{' rowspan="2"' if packaging is None else ''}>Architecture</th>'
        if os is not None:
            result += f'<th{' colspan="2"' if packaging is None else ''} markdown="span">{dist(os)}</th>'
        else:
            for osv in Os:
                result += f'<th{' colspan="2"' if packaging is None else ''} markdown="span">{dist(osv)}</th>'
        result += "</tr>"

        if packaging is None:
            result += '<tr>'
            if os is not None:
                result += '<th>Binary</th><th>Image</th>'
            else:
                for _ in Os:
                    result += '<th>Binary</th><th>Image</th>'
            result += '</tr>'

        result += '</thead><tbody markdown="1">'

        for arch in Arch:

            if os is not None:
                generic = support_matrix.lookup(os, arch, EditionKind.generic)
                extended = support_matrix.lookup(os, arch, EditionKind.extended)

                if (generic and (generic.binary_supported or generic.image_supported)) or (extended and (extended.binary_supported or extended.image_supported)):
                    result += f'<tr markdown="1"><td markdown="span">`{arch.name}`</td>'

                    if packaging == Packaging.archive or packaging is None:
                        result += f'<td markdown="span">{compatibility_editions(True if generic and generic.binary_supported else None, True if extended and extended.binary_supported else None, os)}</td>'
                    if packaging == Packaging.image or packaging is None:
                        result += f'<td markdown="span">{compatibility_editions(True if generic and generic.image_supported else None, True if extended and extended.image_supported else None, os)}</td>'

                    result += '</tr>'

            else:
                result += f'<tr markdown="1"><td markdown="span">`{arch.name}`</td>'

                for osv in Os:
                    generic = support_matrix.lookup(osv, arch, EditionKind.generic)
                    extended = support_matrix.lookup(osv, arch, EditionKind.extended)
                    if packaging == Packaging.archive or packaging is None:
                        result += f'<td markdown="span">{compatibility_editions(True if generic and generic.binary_supported else None, True if extended and extended.binary_supported else None, osv)}</td>'
                    if packaging == Packaging.image or packaging is None:
                        result += f'<td markdown="span">{compatibility_editions(True if generic and generic.image_supported else None, True if extended and extended.image_supported else None, osv)}</td>'

                result += '</tr>'

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
