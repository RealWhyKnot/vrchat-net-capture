from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Protocol, cast


class Postprocessor(Protocol):
    def main(self) -> int: ...


def main() -> int:
    package_dir = Path(__file__).resolve().parent / "vrchat_net_capture"
    spec = importlib.util.spec_from_file_location(
        "vrchat_net_capture", package_dir / "__init__.py", submodule_search_locations=[str(package_dir)]
    )
    if spec is None or spec.loader is None:
        message = "No module named 'vrchat_net_capture'"
        raise ModuleNotFoundError(message)
    package = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = package
    spec.loader.exec_module(package)
    postprocessor = cast("Postprocessor", importlib.import_module("vrchat_net_capture.postprocess_raw_udp"))
    return postprocessor.main()


if __name__ == "__main__":
    raise SystemExit(main())
