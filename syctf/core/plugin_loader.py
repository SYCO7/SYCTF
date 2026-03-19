"""Dynamic plugin discovery and loading for SYCTF modules."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Iterable

from syctf.core.types import ModulePlugin


class PluginLoader:
    """Load command modules from the modules directory at runtime."""

    def __init__(self, modules_roots: Iterable[Path], logger) -> None:
        self.modules_roots = [Path(root).resolve() for root in modules_roots]
        self.logger = logger

    def discover(self, category: str) -> dict[str, ModulePlugin]:
        """Discover all plugins under a category directory."""

        plugins: dict[str, ModulePlugin] = {}
        for root in self.modules_roots:
            category_path = (root / category).resolve()
            if not self._is_safe_path(category_path):
                self.logger.warning("Blocked unsafe category path: %s", category_path)
                continue
            if not category_path.exists() or not category_path.is_dir():
                continue

            for file_path in sorted(category_path.glob("*.py")):
                if file_path.name.startswith("__"):
                    continue
                safe_file = file_path.resolve()
                if not self._is_safe_path(safe_file):
                    self.logger.warning("Blocked unsafe plugin path: %s", safe_file)
                    continue
                plugin = self._load_plugin_from_path(safe_file)
                if plugin:
                    plugins[plugin.name] = plugin
        return plugins

    def _is_safe_path(self, path: Path) -> bool:
        """Check that a path stays within one of allowed module roots."""

        resolved = path.resolve()
        for root in self.modules_roots:
            if resolved == root or root in resolved.parents:
                return True
        return False

    def _load_plugin_from_path(self, path: Path) -> ModulePlugin | None:
        """Load one plugin module and validate the required interface."""

        module_name = f"syctf.dynamic.{path.parent.name}.{path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            self.logger.warning("Failed to build import spec for %s", path)
            return None

        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:  # noqa: BLE001
            self.logger.exception("Failed to import plugin %s: %s", path, exc)
            return None

        plugin = self._extract_plugin(module, path)
        return plugin

    def _extract_plugin(self, module: ModuleType, path: Path) -> ModulePlugin | None:
        """Extract and validate plugin object from an imported module."""

        plugin = getattr(module, "plugin", None)
        if plugin is None:
            self.logger.warning("Plugin file missing 'plugin' object: %s", path)
            return None

        if not hasattr(plugin, "name") or not hasattr(plugin, "description"):
            self.logger.warning("Plugin missing metadata fields: %s", path)
            return None
        if not callable(getattr(plugin, "add_arguments", None)):
            self.logger.warning("Plugin missing add_arguments(parser): %s", path)
            return None
        if not callable(getattr(plugin, "run", None)):
            self.logger.warning("Plugin missing run(args, context): %s", path)
            return None

        return plugin
