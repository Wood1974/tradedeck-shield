"""One file per feature. `include_all` adds every module here that defines `router`.

Adding a feature means adding a file in this folder; nothing else in the app has to change, so two features
no longer edit the same lines of main.py. A module whose name starts with an underscore is a helper, not a feature.
"""
from __future__ import annotations

import importlib
import pkgutil

from fastapi import APIRouter, FastAPI


def feature_routers() -> list[tuple[str, APIRouter]]:
    found = []
    for module in sorted(pkgutil.iter_modules(__path__), key=lambda m: m.name):
        if module.name.startswith("_"):
            continue
        router = getattr(importlib.import_module(f"{__name__}.{module.name}"), "router", None)
        if not isinstance(router, APIRouter):
            raise RuntimeError(f"app/routes/{module.name}.py defines no `router`")
        found.append((module.name, router))
    return found


def include_all(app: FastAPI) -> None:
    for _, router in feature_routers():
        app.include_router(router)
