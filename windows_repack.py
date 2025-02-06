import contextlib
import ctypes.wintypes
import itertools
import logging
import os
import re
import subprocess
import sys
import time
import types
from typing import Annotated
from typing import cast
from typing import Literal
from typing import override
from typing import TYPE_CHECKING
from typing import TypedDict

import bs4
import platformdirs
import pooch  # pyright: ignore[reportMissingTypeStubs]
import pydantic
import pydantic_settings
import requests
import rich.logging
import rich_argparse

_W = r'[a-zA-Z0-9]'


def main():
    if len(sys.argv) == 1:
        sys.argv.append('--help')
    pydantic_settings.CliApp.run(
        _Main,
        cli_settings_source=pydantic_settings.CliSettingsSource(
            _Main,
            formatter_class=rich_argparse.RawDescriptionRichHelpFormatter,
        ),
    )


class _AppxInfo(TypedDict):
    url: str
    known_hash: str
    fname: str


class _AppxSettings(pydantic.BaseModel):
    include: list[Annotated[
        str,
        pydantic.StringConstraints(
            min_length=17,
            pattern=fr'^[A-Z]{_W}*\.[A-Z]{_W}*(\.{_W}+)*_[a-z0-9]{{13}}$',
            strict=True,
            strip_whitespace=True,
        ),
    ]] = []
    exclude: list[Annotated[
        str,
        pydantic.StringConstraints(
            min_length=3,
            pattern=fr'^[A-Z]{_W}*\.[A-Z]{_W}*(\.{_W}+)*$',
            strict=True,
            strip_whitespace=True,
        ),
    ]] = []


@contextlib.contextmanager
def _requests_session(method: str = 'get'):
    mod = types.ModuleType('requests')
    with requests.Session() as session:
        mod.get = getattr(session, method)  # pyright: ignore[reportAttributeAccessIssue]
        sys.modules['requests'] = mod
        try:
            yield
        finally:
            sys.modules['requests'] = requests


@_requests_session('post')
def _appx_info(settings: _AppxSettings) -> list[_AppxInfo]:
    info: list[_AppxInfo] = []
    pattern = re.compile(r'^.+?_.+?_(neutral|x64|x86)_.+?\.(app|msi)x')
    for family_name in settings.include:
        appname, appauthor = family_name.split('_')
        if family_name == 'Mozilla.MozillaFirefox_jag0gd4e3s9p2':
            raise NotImplementedError()
        pup = pooch.create(  # pyright: ignore[reportUnknownMemberType]
            path=platformdirs.user_cache_dir(appname, appauthor),
            base_url='https://store.rg-adguard.net/api/',
            version=time.strftime('%Y.%m.%d.%H'),
            registry={'GetFiles': None},
        )
        downloader = pooch.HTTPDownloader(data={
            'type': 'PackageFamilyName',
            'url': family_name,
            'ring': 'Retail',
            'lang': 'en-US',
        })
        for _ in range(5):
            response = _pooch_fetch(pup, 'GetFiles', downloader)
            with open(response, encoding='utf-8') as f:
                soup = bs4.BeautifulSoup(f, 'html.parser')
            found: list[_AppxInfo] = []
            for row in soup.find_all('tr'):
                assert isinstance(row, bs4.Tag)
                match row.find('a', string=pattern):
                    case None:
                        continue
                    case bs4.Tag(attrs={'href': str(url)}, string=str(fname)):
                        pass
                    case _:
                        assert False, 'unreachable'
                match row.find_all('td'):
                    case [_, _, bs4.Tag(string=str(known_hash)), _]:
                        found.append({
                            'url': url,
                            'known_hash': 'sha1:' + known_hash,
                            'fname': fname,
                        })
                    case _:
                        assert False, 'unreachable'
            if found:
                info += found
                break
            os.unlink(response)
        else:
            if TYPE_CHECKING:
                soup = bs4.BeautifulSoup()
            raise RuntimeError(soup.prettify())
    return info


def _appx_key(x: _AppxInfo):
    name, version, platform, _ = x['fname'].split('_', 3)
    version_info = list(map(int, version.split('.')))
    if name == 'Microsoft.ZuneMusic' and version_info[0] < 2000:
        version_info[0] += 10000
    return version_info, platform != 'x86'


@_requests_session()
def _appx_latest(settings: _AppxSettings, info: list[_AppxInfo]):
    appx = _fullfile(__file__, '../data/appx')
    info.sort(key=lambda x: x['fname'])
    for name, group in itertools.groupby(
        info,
        key=lambda x: x['fname'].split('_', 1)[0],
    ):
        if name not in settings.exclude:
            latest = max(group, key=_appx_key)
            _pooch_retrieve(**latest, path=appx)


def _fullfile(*args: str):
    return os.path.abspath(os.path.join(*args))


class _Main(pydantic_settings.BaseSettings):
    path: Annotated[
        pydantic_settings.CliPositionalArg[
            pydantic.DirectoryPath | pydantic.NewPath
        ],
        pydantic.Field(description='Path to operate on'),
    ]

    input_file: Annotated[
        pydantic.FilePath | None,
        pydantic.Field(alias='i', description='Input image file'),
    ] = None
    index: Annotated[
        pydantic.PositiveInt,
        pydantic.Field(description='The index number in the input image file'),
    ] = 1

    output_file: Annotated[
        pydantic.NewPath | None,
        pydantic.Field(alias='o', description='Output image file'),
    ] = None
    compression: Annotated[
        Literal['max', 'fast', 'none'],
        pydantic.Field(
            alias='c',
            description='Compression level for the output image file',
        ),
    ] = 'fast'
    name: Annotated[
        str,
        pydantic.Field(
            alias='n',
            description='Internal name of the output image file',
        ),
    ] = 'Windows'

    model_config = pydantic_settings.SettingsConfigDict(
        nested_model_default_partial_update=True,
        case_sensitive=True,
        cli_hide_none_type=True,
        cli_avoid_json=True,
        cli_enforce_required=True,
        cli_implicit_flags=True,
        cli_kebab_case=True,
        cli_prog_name=__package__,
    )

    def cli_cmd(self):
        settings = _Settings()
        _setup_logging()
        nsudo = _nsudo()
        pwsh = _pwsh()
        info = _appx_info(settings.appx)
        _appx_latest(settings.appx, info)
        args = subprocess.list2cmdline([
            '-nop',
            '-f', _fullfile(__file__, '../scripts/repack.ps1'),
            nsudo,
            self._path(),
            self.input_file or 'nul',
            str(self.index),
            self.output_file or 'nul',
            self.compression,
            self.name,
        ])

        # https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutew
        ShellExecuteW = ctypes.WINFUNCTYPE(
            ctypes.wintypes.HINSTANCE,  # return
            ctypes.wintypes.HWND,  # hwnd
            ctypes.wintypes.LPCWSTR,  # lpOperation
            ctypes.wintypes.LPCWSTR,  # lpFile
            ctypes.wintypes.LPCWSTR,  # lpParameters
            ctypes.wintypes.LPCWSTR,  # lpDirectory
            ctypes.wintypes.INT,  # nShowCmd
        )(('ShellExecuteW', ctypes.windll.shell32))
        if ShellExecuteW(None, 'runas', pwsh, args, None, 3) <= 32:
            winerror = ctypes.GetLastError()
            raise OSError(None, ctypes.FormatError(winerror), None, winerror)

    def _path(self):
        p = os.path.abspath(self.path)
        if p == 'C:\\' or (
            self.input_file
            and len(p) > 3
            and os.path.exists(p)
            and os.listdir(p)
        ):
            raise ValueError(p)
        return p


@_requests_session()
def _nsudo():
    fe = _fullfile(__file__, '../data/NSudoDM.dll')
    if not os.path.exists(fe):
        downloader = pooch.HTTPDownloader(headers={
            'Accept': 'application/vnd.github.raw+json',
            'X-Github-Api-Version': '2022-11-28',
        })
        src = _fullfile(__file__, '../src')
        mint = os.path.join(src, 'MINT.h')
        if not os.path.exists(mint):
            os.makedirs(src, exist_ok=True)
            fname = _pooch_retrieve(
                'https://api.github.com/repos/M2TeamArchived/NSudo/contents/Source/Native/MINT/MINT.h',
                known_hash='26e200aace4d4e7458c756ea13d21f9941551aaacea841692649760f1cb0f7f4',
                downloader=downloader,
            )
            with open(fname, 'rb') as f, open(mint, 'wb') as g:
                for t in (
                    b'FILE_STAT_INFORMATION',
                    b'FILE_STAT_LX_INFORMATION',
                    b'FILE_CASE_SENSITIVE_INFORMATION',
                ):
                    prefix = b'typedef struct _%b' % t
                    for line in f:
                        if line.startswith(prefix):
                            break
                        g.write(line)
                    prefix = b'} %b, *P%b;' % (t, t)
                    for line in f:
                        if line.startswith(prefix):
                            break
                g.writelines(f)
        pup = pooch.create(  # pyright: ignore[reportUnknownMemberType]
            path=src,
            base_url='https://api.github.com/repos/M2TeamArchived/NSudo/contents/Source/Native/NSudoDevilMode',
            registry={
                'NSudoDevilMode.cpp': '14a68144cc50d4fddeac3c2b03483b4f4db2d351fdfd635bd454436d539e7171',
                'detours.cpp': '643dc84fd7051fa57942ce434439237624e52e895e1e54021dd099e55497d0e9',
                'detours.h': '9ca6a623888008ff69982c4e2e61d8666d72433426325047cf8c926f4feedb77',
                'disasm.cpp': 'fb150f5a4b00b0f8355fc63ae650a95f26dbc8b18715b8a86342b665120fda27',
            },
        )
        _pooch_fetch(pup, 'detours.h', downloader)
        subprocess.run(
            [
                'cl',
                f'/Fe{fe}',
                '/GL',
                '/I.',
                '/LD',
                '/MD',
                '/O2',
                _pooch_fetch(pup, 'NSudoDevilMode.cpp', downloader),
                _pooch_fetch(pup, 'detours.cpp', downloader),
                _pooch_fetch(pup, 'disasm.cpp', downloader),
                'kernel32.lib',
                'ntdll.lib',
                _fullfile(
                    os.environ['CONDA_PREFIX'],
                    'Library/x86_64-w64-mingw32/sysroot/usr/lib/libntoskrnl.a',
                ),
            ],
            check=True,
            cwd=src,
        )
    return fe


def _pooch_fetch(
    pup: pooch.Pooch,
    fname: str,
    downloader: pooch.HTTPDownloader | None = None,
):
    fname = pup.fetch(fname, downloader=downloader)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    assert isinstance(fname, str)
    return fname


def _pooch_retrieve(
    url: str,
    known_hash: str | None = None,
    fname: str | None = None,
    path: str | None = None,
    *,
    downloader: pooch.HTTPDownloader | None = None,
):
    fname = pooch.retrieve(url, known_hash, fname, path, None, downloader)  # pyright: ignore[reportUnknownMemberType]
    assert isinstance(fname, str)
    return fname


@_requests_session()
def _pwsh():
    hashes = _pooch_retrieve(
        'https://mirrors.cernet.edu.cn/PowerShell/LatestRelease/hashes.sha256',
    )
    with open(hashes, encoding='ascii') as f:
        for line in f:
            if '-win-x64.zip' in line:
                break
        else:
            assert False, 'unreachable'
    fname = line[66:].strip()
    files = pooch.retrieve(  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        f'https://mirrors.cernet.edu.cn/PowerShell/LatestRelease/{fname}',
        known_hash=line[:64],
        processor=pooch.Unzip(),
    )
    assert isinstance(files, list)
    for fname in cast('list[str]', files):
        if os.path.basename(fname) == 'pwsh.exe':
            return fname
    assert False, 'unreachable'


class _Settings(pydantic_settings.BaseSettings):
    appx: _AppxSettings = _AppxSettings()

    @classmethod
    @override
    def settings_customise_sources(
        cls,
        settings_cls: type[pydantic_settings.BaseSettings],
        init_settings: pydantic_settings.PydanticBaseSettingsSource,
        env_settings: pydantic_settings.PydanticBaseSettingsSource,
        dotenv_settings: pydantic_settings.PydanticBaseSettingsSource,
        file_secret_settings: pydantic_settings.PydanticBaseSettingsSource,
    ):
        return (
            pydantic_settings.PyprojectTomlConfigSettingsSource(settings_cls),
        )


def _setup_logging():
    pooch.utils.LOGGER = logger = logging.getLogger('pooch')
    logger.addHandler(rich.logging.RichHandler())
    logger.setLevel(logging.INFO)


if __name__ == '__main__':
    main()
