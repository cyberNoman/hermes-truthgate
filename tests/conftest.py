"""Load the plugin package from the repository root for isolated tests."""

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if "truthgate" not in sys.modules:
    spec = importlib.util.spec_from_file_location(
        "truthgate", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)]
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
