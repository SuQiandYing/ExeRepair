"""Small, format-neutral records shared by the application layers.

The binary reader owns offsets and byte layouts.  The rest of the program
works with the records in this module, which keeps the format boundary narrow
and makes the public API independent of the parser implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, IntFlag


class ContainerFlags(IntFlag):
    UseCommandLineShortPath = 0x00000001
    UseDefaultDisplaySetting = 0x00000002
    AutoVerify = 0x00000004
    UseExecutableFileNameArgument = 0x00000008
    AllowMultiProcess = 0x00000010
    UCScidChargeDialog = 0x00000020
    ExecutableFileNotPack = 0x00000040
    ShowSoftDCDialog = 0x00000080
    UseTempPath = 0x00000100
    UseLockFile = 0x00000200
    UCDialogVersion3 = 0x00000400

    USE_COMMAND_LINE_SHORT_PATH = UseCommandLineShortPath
    USE_DEFAULT_DISPLAY_SETTING = UseDefaultDisplaySetting
    AUTO_VERIFY = AutoVerify
    USE_EXECUTABLE_FILE_NAME_ARGUMENT = UseExecutableFileNameArgument
    ALLOW_MULTI_PROCESS = AllowMultiProcess
    UC_SCID_CHARGE_DIALOG = UCScidChargeDialog
    EXECUTABLE_FILE_NOT_PACK = ExecutableFileNotPack
    SHOW_SOFT_DC_DIALOG = ShowSoftDCDialog
    USE_TEMP_PATH = UseTempPath
    USE_LOCK_FILE = UseLockFile
    UC_DIALOG_VERSION_3 = UCDialogVersion3

    def __str__(self) -> str:
        return format_container_flags(self)


_FLAG_ORDER: tuple[ContainerFlags, ...] = (
    ContainerFlags.UseCommandLineShortPath,
    ContainerFlags.UseDefaultDisplaySetting,
    ContainerFlags.AutoVerify,
    ContainerFlags.UseExecutableFileNameArgument,
    ContainerFlags.AllowMultiProcess,
    ContainerFlags.UCScidChargeDialog,
    ContainerFlags.ExecutableFileNotPack,
    ContainerFlags.ShowSoftDCDialog,
    ContainerFlags.UseTempPath,
    ContainerFlags.UseLockFile,
    ContainerFlags.UCDialogVersion3,
)
_KNOWN_FLAGS = sum(int(flag) for flag in _FLAG_ORDER)


def format_container_flags(value: ContainerFlags | int) -> str:
    """Render flags in their stable display order.

    Unknown bits remain visible as a number instead of being silently
    discarded.  This keeps inspection output useful when a newer container
    version is opened by an older build of the tool.
    """

    numeric = int(value)
    if numeric == 0 or numeric & ~_KNOWN_FLAGS:
        return str(numeric)
    return ", ".join(flag.name for flag in _FLAG_ORDER if numeric & int(flag))


class PatchMode(IntEnum):
    None_ = 0
    ExecutableOnly = 1
    File = 2
    Memory = 3

    NONE = None_
    EXECUTABLE_ONLY = ExecutableOnly
    FILE = File
    MEMORY = Memory

    def __str__(self) -> str:
        return "None" if self is self.None_ else self.name


class ContainerVersion(IntEnum):
    V1 = 0
    V2 = 1
    V3 = 2
    V4 = 3
    V5 = 4
    V6 = 5
    V7 = 6

    def __str__(self) -> str:
        return self.name


class ContainerParseResult(IntEnum):
    Successed = 0
    StubInvalid = 0xC0000000
    StubUnknowVersion = 0xC0000001
    StubHashInvalid = 0xC0000002

    SUCCEEDED = Successed
    STUB_INVALID = StubInvalid
    STUB_UNKNOWN_VERSION = StubUnknowVersion
    STUB_HASH_INVALID = StubHashInvalid

    @property
    def succeeded(self) -> bool:
        return self is self.Successed

    @property
    def error_message(self) -> str:
        return {
            self.StubInvalid: "Stub数据无效",
            self.StubUnknowVersion: "Stub版本未知",
            self.StubHashInvalid: "Stub数据校验失败",
        }.get(self, "")

    def Successed_(self) -> bool:
        """Keep the historical callable spelling for integrations."""

        return self.succeeded


@dataclass(frozen=True, slots=True)
class ContainerHeader:
    version: int
    hash: int
    key: int
    reserve1: int = 0

    @property
    def Version(self) -> int:
        return self.version

    @property
    def Hash(self) -> int:
        return self.hash

    @property
    def Key(self) -> int:
        return self.key


@dataclass(frozen=True, slots=True)
class ContainerConfig:
    mode: ContainerFlags

    @property
    def Mode(self) -> ContainerFlags:
        return self.mode


@dataclass(slots=True)
class PatchRecord:
    file_name: str = ""
    position: int = 0
    length: int = 0
    signature1: int = 0
    signature2: int = 0
    reserve1: int = 0
    mode: PatchMode = PatchMode.None_

    @property
    def FileName(self) -> str:
        return self.file_name

    @property
    def Position(self) -> int:
        return self.position

    @property
    def Length(self) -> int:
        return self.length

    @property
    def Signature1(self) -> int:
        return self.signature1

    @property
    def Signature2(self) -> int:
        return self.signature2

    @property
    def Reserve1(self) -> int:
        return self.reserve1

    @property
    def Mode(self) -> PatchMode:
        return self.mode
