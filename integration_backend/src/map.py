"""Utility mapping functions.

This module intentionally avoids shadowing the Python built-in `map` by
exposing safe wrappers. It is created to satisfy references to `map.py`
and to provide simple, well-documented helpers for functional-style mapping.

Design notes:
- We avoid defining top-level names called `map` to prevent confusion with
  the built-in function.
- Public interfaces are clearly documented and preceded by PUBLIC_INTERFACE.

No runtime side effects occur on import.
"""

from typing import Callable, Iterable, Iterator, TypeVar
import builtins

T = TypeVar("T")
U = TypeVar("U")


# PUBLIC_INTERFACE
def apply_map(func: Callable[[T], U], items: Iterable[T]) -> list[U]:
    """Apply a function over an iterable and return a list of results.

    Args:
        func: A single-argument callable to transform each item.
        items: An iterable of input items.

    Returns:
        A list of transformed results.

    Raises:
        TypeError: If func is not callable or items is not iterable.

    Example:
        >>> apply_map(lambda x: x * 2, [1, 2, 3])
        [2, 4, 6]
    """
    if not callable(func):
        raise TypeError("func must be callable")
    # Use list(..) to realize results eagerly and keep interface simple
    return [func(x) for x in items]


# PUBLIC_INTERFACE
def iter_map(func: Callable[[T], U], items: Iterable[T]) -> Iterator[U]:
    """Yield transformed items by mapping a function over an iterable.

    Args:
        func: A single-argument callable to transform each item.
        items: An iterable of input items.

    Returns:
        An iterator producing transformed results.

    Example:
        >>> list(iter_map(lambda x: x + 1, (0, 1)))
        [1, 2]
    """
    if not callable(func):
        raise TypeError("func must be callable")
    for x in items:
        yield func(x)


# PUBLIC_INTERFACE
def builtin_map(func: Callable[[T], U], items: Iterable[T]) -> Iterator[U]:
    """Expose Python's built-in map as an iterator without shadowing.

    This calls builtins.map directly to avoid any confusion if a local
    variable named 'map' exists elsewhere.

    Args:
        func: A single-argument callable to transform each item.
        items: An iterable of input items.

    Returns:
        An iterator produced by builtins.map.

    Example:
        >>> it = builtin_map(lambda x: x.upper(), ["a", "b"])
        >>> list(it)
        ["A", "B"]
    """
    if not callable(func):
        raise TypeError("func must be callable")
    return builtins.map(func, items)
