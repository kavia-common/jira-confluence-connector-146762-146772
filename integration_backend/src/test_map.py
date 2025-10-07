import builtins
import types

import pytest

# Ensure the module imports without side effects or name shadowing issues
def test_import_map_module():
    mod = __import__("src.map".replace("/", "."), fromlist=["*"])
    assert isinstance(mod, types.ModuleType)

def test_apply_map_basic():
    from src.map import apply_map

    assert apply_map(lambda x: x * 2, [1, 2, 3]) == [2, 4, 6]

def test_iter_map_basic():
    from src.map import iter_map

    assert list(iter_map(lambda x: x + 1, (0, 1, 2))) == [1, 2, 3]

def test_builtin_map_wrapper():
    from src.map import builtin_map

    # Confirm we still reference the actual built-in map
    assert builtins.map is map  # noqa: F821 - checking runtime binding

    it = builtin_map(lambda s: s.upper(), ["a", "b"])
    assert list(it) == ["A", "B"]

def test_type_errors():
    from src.map import apply_map, iter_map, builtin_map

    with pytest.raises(TypeError):
        apply_map(123, [1, 2])  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        list(iter_map(None, [1]))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        list(builtin_map(None, [1]))  # type: ignore[arg-type]
