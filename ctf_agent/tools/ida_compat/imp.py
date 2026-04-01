"""
Minimal compatibility shim for the removed stdlib ``imp`` module.

IDA 8.3 still imports ``imp`` from its bundled ``ida_idaapi.py``. When IDA is
switched to Python 3.12, that import fails before plugins can start. This shim
implements the tiny subset IDA still uses: ``find_module`` and ``load_module``.
"""

import importlib
import importlib.util
import os
import sys
import types


PY_SOURCE = 1
PY_COMPILED = 2
C_EXTENSION = 3
PKG_DIRECTORY = 5
C_BUILTIN = 6
PY_FROZEN = 7


def new_module(name):
    return types.ModuleType(name)


def find_module(name, path=None):
    search_paths = list(path or sys.path)
    module_name = str(name or "").strip()
    if not module_name:
        raise ImportError("empty module name")

    for base in search_paths:
        if not base:
            continue
        package_dir = os.path.join(base, module_name)
        package_init = os.path.join(package_dir, "__init__.py")
        if os.path.isdir(package_dir) and os.path.exists(package_init):
            return (None, package_dir, ("", "", PKG_DIRECTORY))

        source_path = os.path.join(base, module_name + ".py")
        if os.path.exists(source_path):
            return (open(source_path, "rb"), source_path, (".py", "rb", PY_SOURCE))

        compiled_path = os.path.join(base, module_name + ".pyc")
        if os.path.exists(compiled_path):
            return (open(compiled_path, "rb"), compiled_path, (".pyc", "rb", PY_COMPILED))

        for suffix in importlib.machinery.EXTENSION_SUFFIXES:
            extension_path = os.path.join(base, module_name + suffix)
            if os.path.exists(extension_path):
                return (None, extension_path, (suffix, "rb", C_EXTENSION))

    raise ImportError("No module named '{0}'".format(module_name))


def load_module(name, file_obj, pathname, description):
    suffix, _mode, module_type = description

    if module_type == PKG_DIRECTORY:
        init_path = os.path.join(pathname, "__init__.py")
        spec = importlib.util.spec_from_file_location(name, init_path, submodule_search_locations=[pathname])
    elif module_type in (PY_SOURCE, PY_COMPILED, C_EXTENSION):
        spec = importlib.util.spec_from_file_location(name, pathname)
    elif module_type in (C_BUILTIN, PY_FROZEN):
        return importlib.import_module(name)
    else:
        raise ImportError("unsupported imp module type: {0}".format(module_type))

    if spec is None or spec.loader is None:
        raise ImportError("unable to build module spec for '{0}'".format(name))

    module = importlib.util.module_from_spec(spec)
    module.__file__ = pathname
    if module_type == PKG_DIRECTORY:
        module.__path__ = [pathname]
        module.__package__ = name
    else:
        parent = name.rpartition(".")[0]
        module.__package__ = parent

    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
