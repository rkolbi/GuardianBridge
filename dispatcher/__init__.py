"""GuardianBridge dispatcher package."""

__all__ = ["Dispatcher", "main"]


def __getattr__(name):
    if name in __all__:
        from .core import Dispatcher, main
        return {"Dispatcher": Dispatcher, "main": main}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
