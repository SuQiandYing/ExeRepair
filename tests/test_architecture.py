from __future__ import annotations

import ast
from pathlib import Path


PACKAGE = Path(__file__).parents[1] / "exerepair"


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
    return imports


def test_domain_and_security_do_not_depend_on_outer_layers() -> None:
    forbidden = {"application", "adapters", "presentation"}
    for directory in (PACKAGE / "domain", PACKAGE / "security"):
        for path in directory.glob("*.py"):
            assert not any(
                part in forbidden
                for imported in _imports(path)
                for part in imported.split(".")
            ), path


def test_formats_never_depend_on_application_or_presentation() -> None:
    for path in (PACKAGE / "formats").glob("*.py"):
        imports = _imports(path)
        assert not any("application" in value for value in imports), path
        assert not any("presentation" in value for value in imports), path


def test_application_has_no_tk_dependency() -> None:
    for path in (PACKAGE / "application").glob("*.py"):
        assert not any(value.startswith("tkinter") for value in _imports(path)), path
