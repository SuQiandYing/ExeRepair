"""Application service for static Enigma section and EVB recovery."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from ..formats.enigma import PEImage
from ..formats.enigma_unpack import (
    Configuration,
    EnigmaLayout,
    Recovered,
    StoredSection,
    parse_configuration,
    recover_sections,
    stored_sections,
)
from ..formats.evb import EVBFile, extract_evb

Progress = Callable[[str], None]


@dataclass(frozen=True, slots=True)
class EnigmaInspection:
    source_path: Path
    bitness: int
    image_base: int
    entry_rva: int
    section_count: int
    metadata_rva: int | None
    configuration: Configuration | None


@dataclass(frozen=True, slots=True)
class EnigmaRecoveryResult:
    source_path: Path
    salt: int | None
    stored_sections: tuple[StoredSection, ...]
    recovered_sections: tuple[Recovered, ...]
    evb_files: tuple[EVBFile, ...]
    output_directory: Path | None


class EnigmaService:
    """Static Enigma recovery facade independent of runtime capture."""

    def inspect(
        self,
        target: str | Path,
        *,
        metadata_rva: int | None = None,
        loader: bytes | None = None,
        layout: EnigmaLayout | object | Sequence[tuple[int, int]] | None = None,
    ) -> EnigmaInspection:
        source = Path(target).expanduser().resolve(strict=True)
        data = source.read_bytes()
        pe = PEImage.parse(data)
        configuration = (
            None
            if metadata_rva is None
            else parse_configuration(data, pe, metadata_rva, loader=loader, layout=layout)
        )
        return EnigmaInspection(
            source_path=source,
            bitness=pe.bitness,
            image_base=pe.image_base,
            entry_rva=pe.entry_rva,
            section_count=len(pe.sections),
            metadata_rva=metadata_rva,
            configuration=configuration,
        )

    def recover(
        self,
        target: str | Path,
        *,
        metadata_rva: int,
        salt: int | None = None,
        backend: str = "auto",
        search_start: int = 0,
        search_count: int = 1 << 32,
        loader: bytes | None = None,
        layout: EnigmaLayout | object | Sequence[tuple[int, int]] | None = None,
        output_directory: str | Path | None = None,
        progress: Progress | None = None,
    ) -> EnigmaRecoveryResult:
        report = progress or (lambda _message: None)
        if salt is not None and not 0 <= salt < 1 << 32:
            raise ValueError("section salt must be a 32-bit unsigned value")
        source = Path(target).expanduser().resolve(strict=True)
        data = source.read_bytes()
        pe = PEImage.parse(data)
        configuration = parse_configuration(
            data, pe, metadata_rva, loader=loader, layout=layout
        )
        sections = stored_sections(data, pe, configuration)
        report(f"已解析 Enigma 配置：{len(configuration.descriptors)} 个描述符")
        if salt is None:
            report("正在校验未加盐状态或搜索 32 位 section salt")
            from ..adapters.enigma_search import search_salt

            salt = search_salt(
                sections,
                start=search_start,
                count=search_count,
                backend=backend,
                progress=lambda checked, total, engine: report(
                    f"{engine} 已检查 {checked:,}/{total:,} 个盐候选"
                ),
            )
        recovered = recover_sections(sections, salt)
        files = (
            extract_evb(data, pe, configuration.context)
            if configuration.context is not None
            else ()
        )
        destination = None
        if output_directory is not None:
            destination = Path(output_directory).expanduser().resolve()
            if destination.exists():
                raise FileExistsError(f"Enigma output directory already exists: {destination}")
            destination.mkdir(parents=True)
            section_dir = destination / "sections"
            section_dir.mkdir()
            for index, item in enumerate(recovered):
                (section_dir / f"section-{index:03d}-{item.rva:08x}.bin").write_bytes(item.bytes)
            for item in files:
                path = destination / item.path
                path.parent.mkdir(parents=True, exist_ok=True)
                if path.exists():
                    raise ValueError(f"duplicate EVB output path: {item.path}")
                path.write_bytes(item.data)
            report(f"已写出 {len(recovered)} 个恢复节和 {len(files)} 个 EVB 文件")
        return EnigmaRecoveryResult(source, salt, sections, recovered, files, destination)


__all__ = ["EnigmaInspection", "EnigmaRecoveryResult", "EnigmaService"]
