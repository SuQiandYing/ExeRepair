"""Static extraction of Enigma's encrypted Virtual Box container."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct
from typing import Iterable

from .enigma import EnigmaFormatError, PEImage
from .enigma_common import MAX_EXPANDED, expanded_size, lz_decompress


@dataclass(frozen=True, slots=True)
class EVBFile:
    path: Path
    data: bytes


@dataclass(frozen=True, slots=True)
class _Node:
    path: Path
    size: int
    offset: int
    stored: int


@dataclass(frozen=True, slots=True)
class _Located:
    table: int
    base: int
    length: int
    version: int


class _Cursor:
    __slots__ = ("data", "at")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.at = 0

    def read(self, size: int) -> bytes:
        if size < 0 or self.at + size > len(self.data):
            raise EnigmaFormatError("truncated EVB record")
        value = self.data[self.at : self.at + size]
        self.at += size
        return value

    def byte(self) -> int:
        return self.read(1)[0]

    def dword(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def qword(self) -> int:
        return struct.unpack("<Q", self.read(8))[0]

    def name(self) -> str:
        words = []
        while True:
            word = struct.unpack("<H", self.read(2))[0]
            if word == 0:
                return bytes().join(value.to_bytes(2, "little") for value in words).decode(
                    "utf-16-le"
                )
            words.append(word)


def _decipher(data: bytes, initial: bytes) -> bytes:
    if len(initial) != 256:
        raise ValueError("EVB state tables must contain 256 bytes")
    state = list(initial)
    i = 0
    j = 0
    output = bytearray()
    for value in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output.append(value ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(output)


def _safe_path(parent: Path, name: str) -> Path:
    if not name or name == "%DEFAULT FOLDER%":
        return parent
    if name.startswith(("/", "\\")):
        raise EnigmaFormatError(f"absolute EVB path: {name}")
    result = parent
    for part in name.replace("\\", "/").split("/"):
        stem = part.split(".", 1)[0].upper()
        device = stem in {"CON", "PRN", "AUX", "NUL"} or (
            len(stem) == 4 and stem[:3] in {"COM", "LPT"} and "1" <= stem[3] <= "9"
        )
        if (
            not part
            or part in {".", ".."}
            or any(ord(char) < 0x20 or char in '<>:"|?*' for char in part)
            or device
            or part.endswith((".", " "))
            or (part.startswith("%") and part.endswith("%"))
        ):
            raise EnigmaFormatError(f"unsupported EVB path component: {part}")
        result /= part
    return result


def _directory(tree: bytes) -> tuple[_Node, ...]:
    cursor = _Cursor(tree)
    pending: list[tuple[Path, int]] = [(Path(), 1)]
    files: list[_Node] = []
    while pending:
        parent, remaining = pending.pop()
        if remaining == 0:
            continue
        pending.append((parent, remaining - 1))
        cursor.dword()
        cursor.dword()
        children = cursor.dword()
        if children > len(tree) // 15:
            raise EnigmaFormatError("invalid EVB child count")
        name = cursor.name()
        kind = cursor.byte()
        item = _safe_path(parent, name)
        if kind in (0, 1):
            pass
        elif kind == 3:
            cursor.read(30)
        elif kind == 2:
            if str(item) in ("", ".") or children != 0:
                raise EnigmaFormatError("invalid EVB file node")
            cursor.read(2)
            size = cursor.qword()
            if size > MAX_EXPANDED:
                raise EnigmaFormatError("EVB file exceeds expansion limit")
            cursor.read(29)
            cursor.name()
            cursor.byte()
            offset = cursor.qword()
            stored = cursor.qword()
            files.append(_Node(item, size, offset, stored))
        else:
            raise EnigmaFormatError(f"unknown EVB node kind {kind}")
        if children:
            pending.append((item, children))
    if cursor.at != len(tree):
        raise EnigmaFormatError("unparsed EVB directory bytes")
    return tuple(files)


def _interleaved_directory(container: bytes, state: bytes) -> tuple[_Node, ...]:
    at = 120
    pending: list[tuple[Path, int]] = [(Path(), 1)]
    files: list[_Node] = []
    while pending:
        parent, remaining = pending.pop()
        if remaining == 0:
            continue
        pending.append((parent, remaining - 1))
        if at + 4 > len(container):
            raise EnigmaFormatError("truncated EVB record length")
        size = struct.unpack("<I", _decipher(container[at : at + 4], state))[0]
        at += 4
        record = _decipher(container[at : at + size], state)
        if len(record) != size:
            raise EnigmaFormatError("truncated EVB interleaved record")
        at += size
        cursor = _Cursor(record)
        cursor.dword()
        cursor.dword()
        children = cursor.dword()
        if children > len(container) // 15:
            raise EnigmaFormatError("invalid EVB child count")
        label = cursor.name()
        kind = cursor.byte()
        item = _safe_path(parent, label)
        if kind in (0, 1, 3):
            pass
        elif kind == 2:
            if str(item) in ("", ".") or children != 0:
                raise EnigmaFormatError("invalid EVB file node")
            cursor.read(2)
            size = cursor.qword()
            if size > MAX_EXPANDED:
                raise EnigmaFormatError("EVB file exceeds expansion limit")
            cursor.read(29)
            cursor.name()
            stored = cursor.qword()
            if cursor.at != len(record):
                raise EnigmaFormatError("unparsed interleaved EVB file record")
            if at + stored > len(container):
                raise EnigmaFormatError("EVB file data exceeds container")
            files.append(_Node(item, size, at, stored))
            at += stored
        else:
            raise EnigmaFormatError(f"unknown EVB node kind {kind}")
        if children:
            pending.append((item, children))
        if len(files) > 0x100000:
            raise EnigmaFormatError("too many EVB files")
    if at != len(container):
        raise EnigmaFormatError("unparsed interleaved EVB container bytes")
    return tuple(files)


def _file_data(stored: bytes, size: int, compressed: bool, state: bytes) -> bytes:
    if compressed:
        count = (size + 65535) // 65536
        if count * 12 > len(stored):
            raise EnigmaFormatError("truncated EVB compression index")
        output = bytearray()
        end = count * 12
        for index in range(count):
            record = _decipher(stored[index * 12 : index * 12 + 12], state)
            offset = struct.unpack_from("<Q", record, 0)[0]
            packed = struct.unpack_from("<I", record, 8)[0]
            if offset != end or packed == 0 or offset + packed > len(stored):
                raise EnigmaFormatError("invalid EVB block extent")
            clear = _decipher(stored[offset : offset + packed], state)
            expected = min(65536, size - len(output))
            output.extend(lz_decompress(clear, expected, strict=False))
            end = offset + packed
        if end != len(stored):
            raise EnigmaFormatError("unparsed compressed EVB file bytes")
        return bytes(output)
    if len(stored) != size:
        raise EnigmaFormatError("plain EVB stored size mismatch")
    output = bytearray()
    for offset in range(0, len(stored), 8192):
        output.extend(_decipher(stored[offset : offset + 8192], state))
    return bytes(output)


def _locate(data: bytes, pe: PEImage, context: bytes) -> _Located | None:
    found: set[_Located] = set()
    for table in range(len(context)):
        length_at = (table + 0x400 + 3) & ~3
        if length_at + 8 > len(context):
            continue
        length, bias = struct.unpack_from("<II", context, length_at)
        if length < 120:
            continue
        for section in pe.sections:
            if bias + length > section.raw_size:
                continue
            base = section.raw_offset + bias
            header_at = base + 56
            if header_at + 64 > len(data):
                continue
            metadata = context[table : table + 256]
            if len(metadata) != 256:
                continue
            header = _decipher(data[header_at : header_at + 64], metadata)
            if (
                struct.unpack_from("<I", header, 4)[0] != 64
                or struct.unpack_from("<Q", header, 48)[0] != length
                or struct.unpack_from("<Q", header, 24)[0] != 120
                or struct.unpack_from("<Q", header, 32)[0] + 120 != length
            ):
                continue
            version = struct.unpack_from("<I", header, 20)[0]
            if version not in (1, 3):
                raise EnigmaFormatError(f"unsupported EVB directory version {version}")
            found.add(_Located(table, base, length, version))
    if len(found) > 1:
        raise EnigmaFormatError(f"expected one embedded EVB container, found {len(found)}")
    return next(iter(found), None)


def _decode_files(nodes: Iterable[_Node], data: bytes, state: bytes, compressed: bool) -> tuple[EVBFile, ...]:
    result = []
    for node in nodes:
        end = node.offset + node.stored
        if node.offset < 0 or end > len(data):
            raise EnigmaFormatError(f"EVB file {node.path} exceeds container data")
        try:
            decoded = _file_data(data[node.offset:end], node.size, compressed, state)
        except EnigmaFormatError as error:
            raise EnigmaFormatError(f"EVB file {node.path}: {error}") from error
        result.append(EVBFile(node.path, decoded))
    return tuple(result)


def _stored_files(nodes: tuple[_Node, ...], data: bytes, state: bytes) -> tuple[EVBFile, ...]:
    plain = all(node.stored == node.size for node in nodes)
    if plain and all(node.size == 0 for node in nodes):
        return _decode_files(nodes, data, state, False)
    try:
        compressed = _decode_files(nodes, data, state, True)
    except EnigmaFormatError as compressed_error:
        if plain:
            return _decode_files(nodes, data, state, False)
        raise EnigmaFormatError(f"invalid compressed EVB storage: {compressed_error}") from compressed_error
    if plain:
        raise EnigmaFormatError("ambiguous EVB storage: both plain and compressed layouts are valid")
    return compressed


def extract_evb(
    data: bytes | bytearray | memoryview,
    pe: PEImage,
    context: bytes,
) -> tuple[EVBFile, ...]:
    """Recover EVB files from a validated Loader context."""

    raw = bytes(data)
    located = _locate(raw, pe, bytes(context))
    if located is None:
        return ()
    metadata = bytes(context[located.table : located.table + 256])
    content = bytes(context[located.table + 0x100 : located.table + 0x200])
    container = raw[located.base : located.base + located.length]
    if len(container) != located.length:
        raise EnigmaFormatError("EVB container exceeds the input")
    if located.version == 1:
        nodes = _interleaved_directory(container, metadata)
        storage = container
    else:
        if len(container) < 128:
            raise EnigmaFormatError("EVB container header is truncated")
        packed = struct.unpack("<I", _decipher(container[120:124], metadata))[0]
        expected = expanded_size(struct.unpack("<I", _decipher(container[124:128], metadata))[0])
        directory = _decipher(container[128 : 128 + packed], metadata)
        tree = lz_decompress(directory, expected, strict=True)
        nodes = _directory(tree)
        storage = container[128 + packed :]
    paths = set()
    for node in nodes:
        normalized = str(node.path).casefold()
        if normalized in paths:
            raise EnigmaFormatError("duplicate EVB output path")
        paths.add(normalized)
    return _stored_files(nodes, storage, content)


__all__ = ["EVBFile", "extract_evb"]
