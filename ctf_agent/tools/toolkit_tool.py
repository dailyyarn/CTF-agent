import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


class ToolkitTool(object):
    TOOL_SPECS = {
        "strings": {
            "lane": "fast",
            "category": "binary_tools",
            "description": "Low-cost printable string extraction for binaries and mixed blobs.",
            "candidates": [("libdll", "strings.exe"), ("strings.exe",)],
        },
        "exiftool": {
            "lane": "fast",
            "category": "stego_tools",
            "description": "Metadata extraction for images, documents, and media.",
            "candidates": [("libdll", "exiftool_v12.5.6.exe"), ("libdll", "exiftool.exe"), ("exiftool_v12.5.6.exe",)],
        },
        "snow": {
            "lane": "fast",
            "category": "misc_tools",
            "description": "Classic whitespace stego helper.",
            "candidates": [("libdll", "SNOW.EXE"), ("SNOW.EXE",)],
        },
        "stegsolve": {
            "lane": "fast",
            "category": "stego_tools",
            "description": "Interactive image stego inspection helper.",
            "candidates": [("libdll", "stegsolve.exe"), ("stegsolve.exe",), ("StegSolve.jar",), ("stegsolveV7改.exe",)],
        },
        "f5": {
            "lane": "bounded-heavy",
            "category": "stego_tools",
            "description": "JPEG stego utility wrapper.",
            "candidates": [("libdll", "f5.jar"), ("f5.jar",)],
        },
        "sqlmap": {
            "lane": "bounded-heavy",
            "category": "web_tools",
            "description": "Bounded SQLi automation helper.",
            "candidates": [("libdll", "sqlmap", "sqlmap.py"), ("libdll", "sqlmapXplus", "sqlmap.py")],
        },
        "ida64": {
            "lane": "sidecar",
            "category": "sidecar_tools",
            "description": "IDA GUI binary analysis frontend.",
            "candidates": [("libdll", "ida8.3", "ida64.exe")],
        },
        "idat64": {
            "lane": "sidecar",
            "category": "sidecar_tools",
            "description": "IDA headless analysis frontend.",
            "candidates": [("libdll", "ida8.3", "idat64.exe")],
        },
        "idapyswitch": {
            "lane": "sidecar",
            "category": "sidecar_tools",
            "description": "IDA Python runtime switch helper.",
            "candidates": [("libdll", "ida8.3", "idapyswitch.exe")],
        },
        "x64dbg": {
            "lane": "sidecar",
            "category": "debug_tools",
            "description": "Windows GUI debugger for manual or scripted assistance.",
            "candidates": [("libdll", "snapshot_2024-07-21_20-36", "release", "x64", "x64dbg.exe")],
        },
        "x32dbg": {
            "lane": "sidecar",
            "category": "debug_tools",
            "description": "32-bit Windows GUI debugger for manual or scripted assistance.",
            "candidates": [("libdll", "snapshot_2024-07-21_20-36", "release", "x32", "x32dbg.exe")],
        },
        "radare2": {
            "lane": "bounded-heavy",
            "category": "binary_tools",
            "description": "CLI reverse engineering helper for quick disassembly and analysis.",
            "candidates": [("libdll", "r2", "bin", "radare2.exe")],
        },
        "7z": {
            "lane": "fast",
            "category": "forensics_tools",
            "description": "Archive extraction helper for nested bundles and quick previews.",
            "candidates": [("libdll", "misc", "7-Zip", "7z.exe"), ("libdll", "misc", "7-Zip-Zstandard", "7z.exe")],
        },
        "steghide": {
            "lane": "bounded-heavy",
            "category": "stego_tools",
            "description": "CLI stego extraction helper for common image/audio containers.",
            "candidates": [("libdll", "misc", "steghide", "steghide.exe")],
        },
        "foremost": {
            "lane": "bounded-heavy",
            "category": "forensics_tools",
            "description": "File carving helper for disk and blob recovery.",
            "candidates": [("libdll", "formost", "foremost.exe"), ("libdll", "ECCTOOL", "main.dist", "foremostlrb", "foremost.exe")],
        },
        "memprocfs": {
            "lane": "sidecar",
            "category": "forensics_tools",
            "description": "Memory image exploration helper with filesystem projection.",
            "candidates": [("libdll", "MemProcFS_files_and_binaries_v5.10.1-win_x64-20240721", "MemProcFS.exe")],
        },
        "openssl": {
            "lane": "fast",
            "category": "crypto_tools",
            "description": "General-purpose crypto and encoding CLI helper.",
            "candidates": [("libdll", "openssl", "openssl.exe"), ("libdll", "john", "bin", "openssl.exe")],
        },
        "pngdebugger": {
            "lane": "fast",
            "category": "stego_tools",
            "description": "PNG chunk inspection helper for metadata and hidden object hints.",
            "candidates": [("libdll", "PNGDebugger.exe")],
        },
        "tcpview": {
            "lane": "fast",
            "category": "debug_tools",
            "description": "Socket/process visibility helper for local network behavior inspection.",
            "candidates": [("libdll", "TCPView.exe")],
        },
        "imhex": {
            "lane": "fast",
            "category": "forensics_tools",
            "description": "Hex inspection helper for binary blobs.",
            "candidates": [
                ("libdll", "imhex", "imhex.exe"),
                ("libdll", "imhex-1.35.3-Windows-Portable-x86_64", "imhex.exe"),
            ],
        },
        "pcapfix": {
            "lane": "fast",
            "category": "forensics_tools",
            "description": "Low-cost PCAP repair helper.",
            "candidates": [("libdll", "pcapfix.exe"), ("pcapfix.exe",)],
        },
        "volatility2": {
            "lane": "bounded-heavy",
            "category": "forensics_tools",
            "description": "Memory forensics helper.",
            "candidates": [("libdll", "volatility_2.6_win64_standalone.exe"), ("volatility_2.6_win64_standalone.exe",)],
        },
        "wireshark": {
            "lane": "fast",
            "category": "forensics_tools",
            "description": "Packet inspection GUI helper.",
            "candidates": [("libdll", "Wireshark", "Wireshark.exe"), ("libdll", "misc", "App", "Wireshark", "Wireshark.exe"), ("libdll", "ECCTOOL", "main.dist", "Wireshark", "Wireshark.exe")],
        },
        "tshark": {
            "lane": "fast",
            "category": "forensics_tools",
            "description": "CLI packet inspection helper for PCAP summaries and field extraction.",
            "candidates": [("libdll", "misc", "App", "Wireshark", "tshark.exe"), ("libdll", "ECCTOOL", "main.dist", "Wireshark", "tshark.exe")],
        },
        "capinfos": {
            "lane": "fast",
            "category": "forensics_tools",
            "description": "CLI PCAP metadata summary helper.",
            "candidates": [("libdll", "misc", "App", "Wireshark", "capinfos.exe"), ("libdll", "ECCTOOL", "main.dist", "Wireshark", "capinfos.exe")],
        },
        "editcap": {
            "lane": "bounded-heavy",
            "category": "forensics_tools",
            "description": "PCAP trimming and repair helper.",
            "candidates": [("libdll", "misc", "App", "Wireshark", "editcap.exe"), ("libdll", "ECCTOOL", "main.dist", "Wireshark", "editcap.exe")],
        },
        "mergecap": {
            "lane": "bounded-heavy",
            "category": "forensics_tools",
            "description": "PCAP merge helper.",
            "candidates": [("libdll", "misc", "App", "Wireshark", "mergecap.exe"), ("libdll", "ECCTOOL", "main.dist", "Wireshark", "mergecap.exe")],
        },
        "dumpcap": {
            "lane": "bounded-heavy",
            "category": "forensics_tools",
            "description": "Packet capture helper.",
            "candidates": [("libdll", "misc", "App", "Wireshark", "dumpcap.exe"), ("libdll", "ECCTOOL", "main.dist", "Wireshark", "dumpcap.exe")],
        },
        "sage": {
            "lane": "bounded-heavy",
            "category": "crypto_tools",
            "description": "Math-heavy cryptanalysis runtime entrypoint.",
            "candidates": [("libdll", "sage.bat"), ("sage.bat",)],
        },
        "yafu": {
            "lane": "bounded-heavy",
            "category": "crypto_tools",
            "description": "Integer factorization helper.",
            "candidates": [("libdll", "yafu", "yafu-x64.exe"), ("libdll", "yafu", "yafu.exe")],
        },
        "hashcat": {
            "lane": "bounded-heavy",
            "category": "crypto_tools",
            "description": "Password/hash cracking helper.",
            "candidates": [("libdll", "hashcat", "hashcat.exe")],
        },
        "john": {
            "lane": "bounded-heavy",
            "category": "crypto_tools",
            "description": "Password/hash cracking helper.",
            "candidates": [("libdll", "john", "run", "john.exe"), ("libdll", "john", "bin", "john.exe")],
        },
        "binwalk": {
            "lane": "bounded-heavy",
            "category": "forensics_tools",
            "description": "Embedded object and firmware carving helper.",
            "candidates": [("libdll", "binwalk提取文件路径", "binwalk.exe")],
        },
        "pngcheck": {
            "lane": "fast",
            "category": "stego_tools",
            "description": "CLI PNG structural validation and chunk summary helper.",
            "candidates": [("libdll", "misc", "IDAT", "pngcheck.exe")],
        },
        "sox": {
            "lane": "fast",
            "category": "misc_tools",
            "description": "CLI audio metadata and signal helper.",
            "candidates": [("libdll", "up3", "sox", "sox.exe")],
        },
        "ffmpeg": {
            "lane": "bounded-heavy",
            "category": "misc_tools",
            "description": "CLI media conversion and probing helper.",
            "candidates": [("libdll", "newUP", "ffmpeg", "ffmpeg.exe")],
        },
    }

    LIBRARY_SPECS = {
        "gmpy2": {"lane": "bounded-heavy", "category": "crypto_runtime", "markers": [("gmpy2",), ("gmpy2.libs",), ("libdll", "up3", "yinjia", "Lib", "site-packages", "gmpy2"), ("libdll", "up3", "yinjia", "Lib", "site-packages", "gmpy2.libs")], "description": "Big integer helper for RSA-style bounded attacks."},
        "z3": {"lane": "bounded-heavy", "category": "crypto_runtime", "markers": [("z3",), ("libdll", "up3", "yinjia", "Lib", "site-packages", "z3")], "description": "Constraint solver runtime."},
        "pycryptodome": {"lane": "bounded-heavy", "category": "crypto_runtime", "markers": [("Cryptodome",), ("Crypto",), ("libdll", "up3", "yinjia", "Lib", "site-packages", "Cryptodome"), ("libdll", "up3", "yinjia", "Lib", "site-packages", "Crypto")], "description": "Python cryptography runtime."},
        "sympy": {"lane": "bounded-heavy", "category": "crypto_runtime", "markers": [("sympy",), ("sympy-1.13.3.dist-info",), ("libdll", "up3", "yinjia", "Lib", "site-packages", "sympy"), ("libdll", "up3", "yinjia", "Lib", "site-packages", "sympy-1.13.1.dist-info"), ("libdll", "up3", "yinjia", "Lib", "site-packages", "sympy-1.13.3.dist-info")], "description": "Symbolic algebra runtime for bounded factoring and number theory."},
        "libnum": {"lane": "bounded-heavy", "category": "crypto_runtime", "markers": [("libnum",), ("libnum-1.7.1.dist-info",), ("libdll", "up3", "yinjia", "Lib", "site-packages", "libnum"), ("libdll", "up3", "yinjia", "Lib", "site-packages", "libnum-1.7.1.dist-info")], "description": "Small helper library for CTF-style number theory utilities."},
        "numpy": {"lane": "bounded-heavy", "category": "science_runtime", "markers": [("numpy",), ("numpy.libs",)], "description": "Array/math runtime."},
        "scipy": {"lane": "bounded-heavy", "category": "science_runtime", "markers": [("scipy",), ("scipy.libs",)], "description": "Scientific computing runtime."},
        "opencv": {"lane": "bounded-heavy", "category": "image_runtime", "markers": [("cv2",)], "description": "Image and video processing runtime."},
        "pillow": {"lane": "bounded-heavy", "category": "image_runtime", "markers": [("PIL",)], "description": "Image processing runtime."},
        "pyside6": {"lane": "sidecar", "category": "gui_runtime", "markers": [("PySide6",), ("shiboken6",)], "description": "Qt runtime for GUI-heavy helpers."},
        "matplotlib": {"lane": "bounded-heavy", "category": "science_runtime", "markers": [("matplotlib",), ("matplotlib.libs",)], "description": "Plotting runtime."},
        "pandas": {"lane": "bounded-heavy", "category": "science_runtime", "markers": [("pandas",), ("pandas.libs",)], "description": "Tabular data runtime."},
    }

    RUNTIME_SPECS = {
        "toolkit_python311": {
            "lane": "sidecar",
            "category": "sidecar_runtime",
            "description": "Toolkit embedded Python 3.11 runtime files.",
            "markers": [("python311.dll",), ("python3.dll",)],
        },
        "ida_python38": {
            "lane": "sidecar",
            "category": "sidecar_runtime",
            "description": "IDA bundled Python runtime.",
            "markers": [("libdll", "ida8.3", "python38", "python.exe")],
        },
    }

    CATEGORY_RECOMMENDATIONS = {
        "crypto": ["strings", "openssl", "gmpy2", "z3", "pycryptodome", "sage", "yafu", "john", "hashcat"],
        "osint": ["browser-use", "sqlmap", "tshark", "capinfos", "wireshark"],
        "misc": ["strings", "7z", "exiftool", "pngdebugger", "pngcheck", "stegsolve", "steghide", "snow", "pcapfix", "sox", "ffmpeg"],
        "forensics": ["strings", "7z", "exiftool", "pcapfix", "capinfos", "tshark", "wireshark", "imhex", "volatility2", "binwalk", "foremost", "memprocfs"],
        "pwn": ["strings", "ida64", "idat64", "x64dbg", "x32dbg", "radare2", "imhex"],
        "re": ["strings", "ida64", "idat64", "x64dbg", "x32dbg", "radare2", "imhex"],
        "reverse": ["strings", "ida64", "idat64", "x64dbg", "x32dbg", "radare2", "imhex"],
        "web": ["sqlmap", "browser-use"],
    }

    SUBTYPE_RECOMMENDATIONS = {
        "stego": ["exiftool", "strings", "pngcheck", "stegsolve", "steghide", "pngdebugger", "7z"],
        "rf": ["sox", "ffmpeg", "wireshark", "imhex"],
        "dns": ["tshark", "capinfos", "wireshark", "pcapfix", "tcpview"],
        "encoding": ["openssl", "gmpy2", "z3", "pycryptodome"],
        "jail": ["python"],
        "vm-or-esolang": ["python", "imhex", "radare2"],
        "rsa": ["openssl", "gmpy2", "z3", "sage", "yafu"],
        "network": ["capinfos", "tshark", "wireshark", "pcapfix", "tcpview"],
        "memory-or-disk": ["7z", "imhex", "volatility2", "memprocfs", "binwalk", "foremost"],
    }
    CATEGORY_LANE_DEFAULTS = {
        "web": ["fast"],
        "crypto": ["fast", "bounded-heavy"],
        "misc": ["fast", "bounded-heavy"],
        "osint": ["fast", "sidecar"],
        "forensics": ["fast", "bounded-heavy"],
        "pwn": ["fast", "sidecar"],
        "re": ["fast", "sidecar"],
        "reverse": ["fast", "sidecar"],
        "malware": ["fast", "bounded-heavy"],
    }
    SUBTYPE_LANE_OVERRIDES = {
        "rsa": ["fast", "bounded-heavy"],
        "stego": ["fast", "bounded-heavy"],
        "rf": ["fast", "bounded-heavy"],
        "network": ["fast", "bounded-heavy"],
        "memory-or-disk": ["fast", "bounded-heavy"],
        "vm-or-esolang": ["fast", "bounded-heavy"],
        "jail": ["fast"],
    }

    TOOL_REASON_HINTS = {
        "strings": "Low-cost string extraction for fast surface triage.",
        "radare2": "Quick CLI disassembly and symbol probe before heavier reverse workflows.",
        "7z": "Archive listing and extraction for nested bundles and container triage.",
        "steghide": "CLI stego probe for common image and audio carriers.",
        "openssl": "Low-cost crypto and encoding CLI fallback.",
        "ida64": "Interactive reverse engineering sidecar for deep code inspection.",
        "idat64": "Headless IDA runner for repeatable static analysis templates.",
        "x64dbg": "64-bit Windows debugger for live trace capture and manual exploit assistance.",
        "x32dbg": "32-bit Windows debugger for PE32 samples and WOW64-era challenges.",
        "imhex": "Hex-level structure inspection for binary and container artifacts.",
        "exiftool": "Metadata extraction for media and document artifacts.",
        "pngdebugger": "PNG chunk visibility for low-cost stego hints.",
        "wireshark": "Packet inspection helper for network artifacts and protocol clues.",
        "tshark": "CLI packet summary and field extraction for bounded PCAP inspection.",
        "capinfos": "CLI capture metadata summary for quick PCAP profiling.",
        "pcapfix": "Repair helper for damaged packet captures.",
        "foremost": "File carving helper for blobs and disk-style recovery.",
        "memprocfs": "Memory-image sidecar with projected filesystem access.",
        "pngcheck": "PNG structural validation and chunk-level inspection helper.",
        "sox": "Audio metadata and sample format probe for RF and misc media paths.",
        "ffmpeg": "Media probe fallback for bounded container and codec inspection.",
    }
    LIBRARY_REASON_HINTS = {
        "gmpy2": "Big integer arithmetic for bounded RSA and number-theory attacks.",
        "z3": "Constraint solving for bounded algebraic or logic-heavy paths.",
        "pycryptodome": "General cryptography runtime for fast symmetric and block helpers.",
        "sympy": "Symbolic algebra and bounded factoring helpers for medium-size RSA paths.",
        "libnum": "CTF-focused number theory helpers for integer-to-text and RSA plumbing.",
        "numpy": "Array-heavy helpers for signal, image, and numeric transforms.",
        "scipy": "Scientific routines for bounded decode and analysis paths.",
        "opencv": "Image and video transforms for stego and misc visual paths.",
        "pillow": "Low-cost image object inspection and channel extraction.",
        "pyside6": "GUI runtime for heavier toolkit helpers.",
    }
    SIDECAR_REASON_HINTS = {
        "browser-use": "Browser sidecar for dynamic pages or JS-driven workflows.",
        "ida64": "IDA GUI sidecar for interactive reverse analysis.",
        "idat64": "IDA headless sidecar for repeatable template analysis.",
        "x64dbg": "x64 debugger sidecar for live execution tracing.",
        "x32dbg": "x86 debugger sidecar for 32-bit Windows samples.",
    }

    def __init__(self, toolkit_root, shell_tool):
        self.toolkit_root = Path(toolkit_root) if toolkit_root else None
        self.shell_tool = shell_tool
        self._cache = None
        self._library_cache = None
        self._runtime_cache = None
        self._digest_cache = None
        self._runtime_import_cache = None
        self._tool_health_cache = None

    def is_configured(self):
        return bool(self.toolkit_root and self.toolkit_root.exists())

    def discover_tools(self):
        if self._cache is not None:
            return dict(self._cache)

        discovered = {}
        if not self.is_configured():
            self._cache = discovered
            return discovered

        for name, spec in self.TOOL_SPECS.items():
            for candidate in spec.get("candidates", []):
                tool_path = self.toolkit_root.joinpath(*candidate)
                if tool_path.exists():
                    discovered[name] = {
                        "name": name,
                        "path": tool_path,
                        "lane": spec.get("lane", "fast"),
                        "category": spec.get("category", "misc_tools"),
                        "description": spec.get("description", ""),
                    }
                    break
            if name == "binwalk" and name not in discovered:
                tool_path = self.toolkit_root.joinpath("libdll", "misc", "binwalk", "binwalk.exe")
                if tool_path.exists():
                    discovered[name] = {
                        "name": name,
                        "path": tool_path,
                        "lane": spec.get("lane", "fast"),
                        "category": spec.get("category", "misc_tools"),
                        "description": spec.get("description", ""),
                    }
        self._cache = discovered
        return dict(discovered)

    def discover_libraries(self):
        if self._library_cache is not None:
            return list(self._library_cache)

        discovered = []
        if not self.is_configured():
            self._library_cache = discovered
            return discovered

        runtime_imports = self._probe_runtime_library_status(list(self.LIBRARY_SPECS.keys()))
        runtime_path = self.detect_toolkit_python_executable()
        for name, spec in self.LIBRARY_SPECS.items():
            path = self._first_existing_marker(spec.get("markers", []))
            if not path and runtime_imports.get(name) == "ok" and runtime_path:
                path = Path(runtime_path)
            if not path:
                continue
            discovered.append(
                {
                    "name": name,
                    "path": str(path),
                    "lane": spec.get("lane", "bounded-heavy"),
                    "category": spec.get("category", "crypto_runtime"),
                    "description": spec.get("description", ""),
                }
            )
        self._library_cache = discovered
        return list(discovered)

    def discover_runtimes(self):
        if self._runtime_cache is not None:
            return list(self._runtime_cache)

        discovered = []
        if not self.is_configured():
            self._runtime_cache = discovered
            return discovered

        for name, spec in self.RUNTIME_SPECS.items():
            path = self._first_existing_marker(spec.get("markers", []))
            if not path:
                continue
            discovered.append(
                {
                    "name": name,
                    "path": str(path),
                    "lane": spec.get("lane", "sidecar"),
                    "category": spec.get("category", "sidecar_runtime"),
                    "description": spec.get("description", ""),
                }
            )
        self._runtime_cache = discovered
        return list(discovered)

    def capability_digest(self):
        if self._digest_cache is not None:
            return dict(self._digest_cache)

        tools = self.describe_tools()
        libraries = self.discover_libraries()
        runtimes = self.discover_runtimes()
        lane_keys = {"fast": "fast_lane", "bounded-heavy": "bounded_heavy_lane", "sidecar": "sidecar_lane"}
        layers = {"fast_lane": [], "bounded_heavy_lane": [], "sidecar_lane": []}
        categories = {}

        for item in tools + libraries + runtimes:
            lane_name = lane_keys.get(item.get("lane", "fast"), "fast_lane")
            layers[lane_name].append(item.get("name", ""))
            category = str(item.get("category", "misc_tools"))
            categories.setdefault(category, []).append(item.get("name", ""))

        for key in list(layers.keys()):
            layers[key] = sorted({item for item in layers[key] if item})
        for key in list(categories.keys()):
            categories[key] = sorted({item for item in categories[key] if item})
        sidecar_tools = []
        for key in ["sidecar_tools", "debug_tools", "sidecar_runtime"]:
            sidecar_tools.extend(list(categories.get(key, [])))
        if sidecar_tools:
            categories["sidecar_tools"] = sorted({item for item in sidecar_tools if item})

        ida_info = {
            "ida64": self._stringify_path(self.get_tool_path("ida64")),
            "idat64": self._stringify_path(self.get_tool_path("idat64")),
            "idapyswitch": self._stringify_path(self.get_tool_path("idapyswitch")),
            "plugin_path": self._detect_ida_plugin_path(),
            "bootstrap_script": self._detect_ida_bootstrap_script(),
            "compat_dir": self._stringify_path(self._detect_ida_compat_dir()),
            "compat_shim": self._stringify_path(self._detect_ida_compat_shim()),
        }
        x64_path = self.get_tool_path("x64dbg")
        x32_path = self.get_tool_path("x32dbg")
        plugins_x64 = x64_path.parent / "plugins" if x64_path else None
        plugins_x32 = x32_path.parent / "plugins" if x32_path else None
        x64dbg_info = {
            "x64dbg": self._stringify_path(x64_path),
            "x32dbg": self._stringify_path(x32_path),
            "plugins_x64": self._stringify_path(plugins_x64 if plugins_x64 and plugins_x64.exists() else ""),
            "plugins_x32": self._stringify_path(plugins_x32 if plugins_x32 and plugins_x32.exists() else ""),
            "automate_plugin_x64": self._stringify_path((plugins_x64 / "x64dbg-automate.dp64") if plugins_x64 and (plugins_x64 / "x64dbg-automate.dp64").exists() else ""),
            "automate_plugin_x32": self._stringify_path((plugins_x32 / "x64dbg-automate.dp32") if plugins_x32 and (plugins_x32 / "x64dbg-automate.dp32").exists() else ""),
            "libzmq_x64": self._stringify_path((x64_path.parent / "libzmq-mt-4_3_5.dll") if x64_path and (x64_path.parent / "libzmq-mt-4_3_5.dll").exists() else ""),
            "libzmq_x32": self._stringify_path((x32_path.parent / "libzmq-mt-4_3_5.dll") if x32_path and (x32_path.parent / "libzmq-mt-4_3_5.dll").exists() else ""),
        }
        tool_health = {
            "sage": {
                "available": self.has_tool("sage"),
                "healthy": self.is_tool_healthy("sage") if self.has_tool("sage") else False,
            },
            "yafu": {
                "available": self.has_tool("yafu"),
                "healthy": self.is_tool_healthy("yafu") if self.has_tool("yafu") else False,
            },
        }
        digest = {
            "configured": self.is_configured(),
            "toolkit_root": str(self.toolkit_root) if self.toolkit_root else "",
            "tool_count": len(tools),
            "library_count": len(libraries),
            "runtime_count": len(runtimes),
            "layers": layers,
            "categories": categories,
            "tools": tools,
            "libraries": libraries,
            "runtimes": runtimes,
            "ida": ida_info,
            "x64dbg": x64dbg_info,
            "tool_health": tool_health,
        }
        self._digest_cache = digest
        return dict(digest)

    def capability_plan(self, category="", subtype=""):
        category = str(category or "").strip().lower()
        subtype = str(subtype or "").strip().lower()
        digest = self.capability_digest()
        layers = dict(digest.get("layers") or {})
        categories = dict(digest.get("categories") or {})
        tool_health = dict(digest.get("tool_health") or {})

        selected_lanes = list(self.SUBTYPE_LANE_OVERRIDES.get(subtype) or self.CATEGORY_LANE_DEFAULTS.get(category) or ["fast"])
        recommended_tools = self.recommend_tools(category, subtype)
        recommended_libraries = []
        if category in {"crypto", "misc"} or subtype in {"encoding", "rsa"}:
            for name in ["gmpy2", "z3", "pycryptodome", "sympy", "libnum", "numpy", "scipy"]:
                if self.has_library(name):
                    recommended_libraries.append(name)
        if category in {"misc", "forensics"} or subtype in {"stego", "rf", "network", "memory-or-disk"}:
            for name in ["opencv", "pillow"]:
                if self.has_library(name):
                    recommended_libraries.append(name)

        recommended_sidecars = []
        if category in {"pwn", "re", "reverse"}:
            for name in ["ida64", "idat64", "x64dbg", "x32dbg"]:
                if self.has_tool(name):
                    recommended_sidecars.append(name)
        if category == "osint":
            recommended_sidecars.append("browser-use")

        triggers = []
        if "sidecar" in selected_lanes and recommended_sidecars:
            triggers.append("category:{0}".format(category or "unknown"))
        if "bounded-heavy" in selected_lanes and recommended_libraries:
            triggers.append("subtype:{0}".format(subtype or category or "general"))
        if category == "osint":
            triggers.append("public-source-budgeted-expansion")

        recommended_tool_reasons = self.describe_recommendations(recommended_tools, category, subtype, kind="tool")
        recommended_library_reasons = self.describe_recommendations(recommended_libraries, category, subtype, kind="library")
        recommended_sidecar_reasons = self.describe_recommendations(recommended_sidecars, category, subtype, kind="sidecar")
        recommended_tool_health = []
        for name in self._unique(recommended_tools):
            health = tool_health.get(name)
            if health is not None:
                recommended_tool_health.append(
                    {
                        "name": name,
                        "available": bool(health.get("available", False)),
                        "healthy": bool(health.get("healthy", False)),
                    }
                )
        unhealthy_tools = [item.get("name", "") for item in recommended_tool_health if not item.get("healthy", True)]
        if unhealthy_tools:
            triggers.append("health:{0}".format(",".join(self._unique(unhealthy_tools)[:4])))

        return {
            "category": category,
            "subtype": subtype,
            "selected_lanes": selected_lanes,
            "fast_lane_tools": list(layers.get("fast_lane", [])),
            "bounded_heavy_lane_tools": list(layers.get("bounded_heavy_lane", [])),
            "sidecar_lane_tools": list(layers.get("sidecar_lane", [])),
            "recommended_tools": recommended_tools,
            "recommended_libraries": self._unique(recommended_libraries),
            "recommended_sidecars": self._unique(recommended_sidecars),
            "binary_tools": list(categories.get("binary_tools", [])),
            "crypto_runtime": list(categories.get("crypto_runtime", [])),
            "forensics_tools": list(categories.get("forensics_tools", [])),
            "stego_tools": list(categories.get("stego_tools", [])),
            "sidecar_tools": list(categories.get("sidecar_tools", [])),
            "triggers": triggers,
            "recommended_tool_reasons": recommended_tool_reasons,
            "recommended_library_reasons": recommended_library_reasons,
            "recommended_sidecar_reasons": recommended_sidecar_reasons,
            "recommended_tool_health": recommended_tool_health,
            "tool_health": tool_health,
        }

    def get_tool_path(self, name):
        entry = self.discover_tools().get(name)
        return entry["path"] if entry else None

    def has_tool(self, name):
        return self.get_tool_path(name) is not None

    def has_library(self, name):
        for item in self.discover_libraries():
            if item.get("name") == name:
                return True
        return False

    def detect_toolkit_python_executable(self):
        if not self.is_configured():
            return ""
        candidates = [
            ("libdll", "up3", "yinjia", "python.exe"),
            ("libdll", "up4", "volatility3", "python.exe"),
            ("libdll", "MemProcFS_files_and_binaries_v5.10.1-win_x64-20240721", "python", "python.exe"),
        ]
        for candidate in candidates:
            path = self.toolkit_root.joinpath(*candidate)
            if path.exists():
                return str(path)
        return ""

    def run_toolkit_python_inline(self, code, stdin_text="", pythonpath_entries=None, path_entries=None, timeout=60):
        runtime = self.detect_toolkit_python_executable()
        if not runtime:
            return {"status": "missing", "tool": "toolkit-python311", "message": "no toolkit python runtime is available"}
        env = os.environ.copy()
        pythonpaths = [str(item) for item in list(pythonpath_entries or []) if item]
        pathdirs = [str(item) for item in list(path_entries or []) if item]
        if pythonpaths:
            current_pythonpath = str(env.get("PYTHONPATH", "") or "")
            env["PYTHONPATH"] = os.pathsep.join(pythonpaths + ([current_pythonpath] if current_pythonpath else []))
        if pathdirs:
            env["PATH"] = os.pathsep.join(pathdirs + [str(env.get("PATH", "") or "")])
        command = [runtime, "-c", str(code)]
        try:
            completed = subprocess.run(
                command,
                input=str(stdin_text or ""),
                text=True,
                capture_output=True,
                cwd=str(self.toolkit_root),
                timeout=timeout,
                env=env,
            )
            return {
                "status": "ok" if completed.returncode == 0 else "error",
                "tool": "toolkit-python311",
                "command": self.command_preview(command),
                "runtime_path": str(runtime),
                "returncode": int(completed.returncode),
                "stdout": str(completed.stdout or ""),
                "stderr": str(completed.stderr or ""),
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "status": "timeout",
                "tool": "toolkit-python311",
                "command": self.command_preview(command),
                "runtime_path": str(runtime),
                "stdout": str(exc.stdout or ""),
                "stderr": str(exc.stderr or ""),
                "message": "toolkit python timed out",
            }

    def run_crypto_runtime_probe(self, params, timeout=45):
        payload = json.dumps(dict(params or {}), ensure_ascii=False)
        pythonpaths = [
            str(self.toolkit_root / "libdll" / "yafu"),
            str(self.toolkit_root),
        ]
        path_entries = [str(self.toolkit_root / "libdll" / "yafu")]
        code = r"""
import json, math, sys
payload = json.loads(sys.stdin.read() or "{}")
result = {"imports": {}, "attacks": []}
mods = {}
for name in ["gmpy2", "z3", "Crypto", "sympy", "libnum"]:
    try:
        mods[name] = __import__(name)
        result["imports"][name] = "ok"
    except Exception as exc:
        result["imports"][name] = str(exc)

def int_to_text(value):
    try:
        if value is None:
            return ""
        value = int(value)
        if value < 0:
            return ""
        hex_text = format(value, "x")
        if len(hex_text) % 2:
            hex_text = "0" + hex_text
        decoded = bytes.fromhex(hex_text).decode("utf-8", errors="ignore")
        if decoded:
            return decoded
        if result["imports"].get("libnum") == "ok":
            try:
                raw = mods["libnum"].n2s(value)
                if isinstance(raw, bytes):
                    return raw.decode("utf-8", errors="ignore")
                return str(raw or "")
            except Exception:
                pass
        return decoded
    except Exception:
        return ""

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def mod_pow_signed(base, exp, mod):
    base = int(base); exp = int(exp); mod = int(mod)
    if exp >= 0:
        return pow(base, exp, mod)
    inv = pow(base, -1, mod)
    return pow(inv, -exp, mod)

n = payload.get("n")
e = payload.get("e")
c = payload.get("c")
d = payload.get("d")
phi = payload.get("phi")
n1 = payload.get("n1")
n2 = payload.get("n2")
e1 = payload.get("e1")
e2 = payload.get("e2")
c1 = payload.get("c1")
c2 = payload.get("c2")

if n and d and c:
    try:
        text = int_to_text(pow(int(c), int(d), int(n)))
        if text:
            result["attacks"].append({"name": "rsa-private-exponent-toolkit", "plaintext": text[:240], "details": "d supplied"})
    except Exception:
        pass

if n and e and c and phi:
    try:
        derived_d = pow(int(e), -1, int(phi))
        text = int_to_text(pow(int(c), derived_d, int(n)))
        if text:
            result["attacks"].append({"name": "rsa-phi-supplied-toolkit", "plaintext": text[:240], "details": "phi supplied"})
    except Exception:
        pass

if result["imports"].get("gmpy2") == "ok" and e and c and int(e) <= 7:
    try:
        root, exact = mods["gmpy2"].iroot(int(c), int(e))
        if exact:
            text = int_to_text(root)
            if text:
                result["attacks"].append({"name": "rsa-low-exponent-root-gmpy2", "plaintext": text[:240], "details": "exact-root"})
    except Exception:
        pass

if result["imports"].get("sympy") == "ok" and e and c and int(e) <= 7:
    try:
        root, exact = mods["sympy"].integer_nthroot(int(c), int(e))
        if exact:
            text = int_to_text(root)
            if text:
                result["attacks"].append({"name": "rsa-low-exponent-root-sympy", "plaintext": text[:240], "details": "integer_nthroot"})
    except Exception:
        pass

if result["imports"].get("sympy") == "ok" and n and e and c:
    try:
        digits = len(str(int(n)))
        if digits <= 30:
            factors_map = mods["sympy"].factorint(int(n), limit=200000)
            expanded = []
            for prime, exponent in dict(factors_map).items():
                expanded.extend([int(prime)] * int(exponent))
            if len(expanded) == 2:
                fp, fq = expanded
                phi = (fp - 1) * (fq - 1)
                d = pow(int(e), -1, phi)
                text = int_to_text(pow(int(c), d, int(n)))
                if text:
                    result["attacks"].append({"name": "rsa-small-factor-sympy", "plaintext": text[:240], "details": "factorint"})
    except Exception:
        pass

if result["imports"].get("gmpy2") == "ok" and n1 and n2 and c1 and c2:
    try:
        shared = int(mods["gmpy2"].gcd(int(n1), int(n2)))
        if shared not in {0, 1, int(n1), int(n2)}:
            left_q = int(n1) // shared
            right_q = int(n2) // shared
            left_e = int(e1 or e or 65537)
            right_e = int(e2 or e or 65537)
            left_d = pow(left_e, -1, (shared - 1) * (left_q - 1))
            right_d = pow(right_e, -1, (shared - 1) * (right_q - 1))
            left_plain = int_to_text(pow(int(c1), left_d, int(n1)))
            right_plain = int_to_text(pow(int(c2), right_d, int(n2)))
            if left_plain:
                result["attacks"].append({"name": "rsa-shared-prime-gmpy2", "plaintext": left_plain[:240], "details": "n1 shared prime"})
            if right_plain:
                result["attacks"].append({"name": "rsa-shared-prime-gmpy2", "plaintext": right_plain[:240], "details": "n2 shared prime"})
    except Exception:
        pass

if n and e1 and e2 and c1 and c2 and math.gcd(int(e1), int(e2)) == 1:
    try:
        g, a, b = egcd(int(e1), int(e2))
        if g == 1:
            msg = (mod_pow_signed(int(c1), a, int(n)) * mod_pow_signed(int(c2), b, int(n))) % int(n)
            text = int_to_text(msg)
            if text:
                result["attacks"].append({"name": "rsa-common-modulus-toolkit", "plaintext": text[:240], "details": "common modulus"})
    except Exception:
        pass

print(json.dumps(result))
"""
        result = self.run_toolkit_python_inline(
            code,
            stdin_text=payload,
            pythonpath_entries=pythonpaths,
            path_entries=path_entries,
            timeout=timeout,
        )
        stdout = str(result.get("stdout", "") or "").strip()
        try:
            parsed = json.loads(stdout) if stdout else {}
        except Exception:
            parsed = {}
        result["probe"] = parsed if isinstance(parsed, dict) else {}
        return result

    def available_tools(self):
        return sorted(self.discover_tools().keys())

    def available_libraries(self):
        return sorted(item.get("name", "") for item in self.discover_libraries())

    def describe_tools(self):
        payload = []
        for name, entry in sorted(self.discover_tools().items()):
            payload.append(
                {
                    "name": name,
                    "path": str(entry["path"]),
                    "lane": entry.get("lane", "fast"),
                    "category": entry.get("category", "misc_tools"),
                    "description": entry.get("description", ""),
                }
            )
        return payload

    def recommend_tools(self, category="", subtype=""):
        category = str(category or "").strip().lower()
        subtype = str(subtype or "").strip().lower()
        recommendations = []
        recommendations.extend(self.CATEGORY_RECOMMENDATIONS.get(category, []))
        recommendations.extend(self.SUBTYPE_RECOMMENDATIONS.get(subtype, []))
        realized = []
        for name in recommendations:
            if name == "python":
                realized.append(name)
                continue
            if name == "browser-use":
                realized.append(name)
                continue
            if name in {"sage", "yafu"} and not self.is_tool_healthy(name):
                continue
            if self.has_tool(name) or self.has_library(name):
                realized.append(name)
        return self._unique(realized)

    def describe_recommendations(self, names, category="", subtype="", kind="tool"):
        payload = []
        for name in self._unique(names):
            healthy = None
            available = None
            if kind == "tool" and self.has_tool(name):
                available = True
                healthy = self.is_tool_healthy(name)
            payload.append(
                {
                    "name": name,
                    "reason": self._reason_for_name(name, category=category, subtype=subtype, kind=kind),
                    "available": available,
                    "healthy": healthy,
                }
            )
        return payload

    def run_named_tool(self, name, args=None, cwd=None, timeout=120):
        tool_path = self.get_tool_path(name)
        if not tool_path:
            return {
                "status": "missing",
                "tool": name,
                "message": "tool is not available in the configured toolkit root",
            }

        command = [str(tool_path)]
        if args:
            command.extend([str(item) for item in args])
        result = self.shell_tool.run(command, cwd=cwd, timeout=timeout)
        result["status"] = "ok" if result["returncode"] == 0 else "error"
        result["tool"] = name
        result["command"] = self.command_preview(command)
        result["lane"] = self.discover_tools().get(name, {}).get("lane", "fast")
        result["category"] = self.discover_tools().get(name, {}).get("category", "misc_tools")
        return result

    def detect_binary_bitness(self, binary_path):
        binary_path = Path(binary_path)
        if not binary_path.exists():
            return ""
        with binary_path.open("rb") as handle:
            header = handle.read(4096)
        if len(header) >= 6 and header.startswith(b"\x7fELF"):
            elf_class = header[4]
            if elf_class == 1:
                return "32"
            if elf_class == 2:
                return "64"
        if len(header) >= 0x40 and header.startswith(b"MZ"):
            pe_offset = int.from_bytes(header[0x3C:0x40], byteorder="little", signed=False)
            if 0 <= pe_offset <= len(header) - 0x18 and header[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                machine = int.from_bytes(header[pe_offset + 4:pe_offset + 6], byteorder="little", signed=False)
                opt_magic = int.from_bytes(header[pe_offset + 24:pe_offset + 26], byteorder="little", signed=False)
                if opt_magic == 0x10B or machine in {0x014C, 0x01C0, 0x01C4}:
                    return "32"
                if opt_magic == 0x20B or machine in {0x8664, 0x0200, 0xAA64}:
                    return "64"
        return ""

    def select_windows_debugger(self, binary_path):
        binary_path = Path(binary_path)
        bits = self.detect_binary_bitness(binary_path)
        if bits == "32" and self.has_tool("x32dbg"):
            return {
                "debugger_name": "x32dbg",
                "debugger_path": str(self.get_tool_path("x32dbg")),
                "bits": bits,
                "reason": "PE32 sample detected; prefer x32dbg to match target bitness.",
            }
        debugger_name = "x64dbg" if self.has_tool("x64dbg") else ("x32dbg" if self.has_tool("x32dbg") else "")
        debugger_path = self.get_tool_path(debugger_name) if debugger_name else None
        if not debugger_path:
            return {"debugger_name": "", "debugger_path": "", "bits": bits, "reason": "no Windows debugger is available"}
        reason = "Defaulting to x64dbg for PE32+/unknown Windows samples." if debugger_name == "x64dbg" else "Only x32dbg is available in the toolkit."
        if bits == "64" and debugger_name == "x64dbg":
            reason = "PE32+ sample detected; prefer x64dbg to match target bitness."
        return {
            "debugger_name": debugger_name,
            "debugger_path": str(debugger_path),
            "bits": bits,
            "reason": reason,
        }

    def run_radare2_probe(self, binary_path, timeout=20):
        binary_path = Path(binary_path)
        if not self.has_tool("radare2"):
            return {"status": "missing", "tool": "radare2", "message": "radare2 is not available in the configured toolkit root"}
        if not binary_path.exists():
            return {"status": "missing", "tool": "radare2", "message": "binary does not exist", "binary_path": str(binary_path)}
        script = "aa;iI;ii;izz~flag;izz~win;izz~check;izz~main;afl~main;afl~win;afl~check;afl~flag"
        result = self.run_named_tool("radare2", ["-2", "-q", "-c", script, str(binary_path)], cwd=str(binary_path.parent), timeout=timeout)
        stdout = str(result.get("stdout", "") or "")
        stderr = str(result.get("stderr", "") or "")
        interesting_lines = []
        for line in stdout.splitlines():
            cleaned = line.strip()
            if not cleaned:
                continue
            lowered = cleaned.lower()
            if any(token in lowered for token in ["flag", "win", "main", "check", "sym.", "entry"]):
                interesting_lines.append(cleaned[:240])
        result["interesting_lines"] = interesting_lines[:40]
        result["binary_path"] = str(binary_path)
        return result

    def list_archive_with_7z(self, archive_path, timeout=20):
        archive_path = Path(archive_path)
        if not self.has_tool("7z"):
            return {"status": "missing", "tool": "7z", "message": "7z is not available in the configured toolkit root"}
        if not archive_path.exists():
            return {"status": "missing", "tool": "7z", "message": "archive does not exist", "archive_path": str(archive_path)}
        result = self.run_named_tool("7z", ["l", "-slt", str(archive_path)], cwd=str(archive_path.parent), timeout=timeout)
        lines = [line.strip() for line in str(result.get("stdout", "") or "").splitlines() if line.strip()]
        entries = [line for line in lines if line.startswith("Path = ") or line.startswith("Size = ")]
        result["archive_path"] = str(archive_path)
        result["entries_preview"] = entries[:80]
        return result

    def extract_archive_with_7z(self, archive_path, output_dir, timeout=60):
        archive_path = Path(archive_path)
        output_dir = Path(output_dir)
        if not self.has_tool("7z"):
            return {"status": "missing", "tool": "7z", "message": "7z is not available in the configured toolkit root"}
        if not archive_path.exists():
            return {"status": "missing", "tool": "7z", "message": "archive does not exist", "archive_path": str(archive_path)}
        try:
            if output_dir.exists():
                shutil.rmtree(output_dir, ignore_errors=True)
            output_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        result = self.run_named_tool(
            "7z",
            ["x", "-y", "-o{0}".format(output_dir), str(archive_path)],
            cwd=str(archive_path.parent),
            timeout=timeout,
        )
        extracted_files = []
        if output_dir.exists():
            for item in sorted(path for path in output_dir.rglob("*") if path.is_file()):
                extracted_files.append(str(item))
        result["archive_path"] = str(archive_path)
        result["output_dir"] = str(output_dir)
        result["extracted_files"] = extracted_files[:60]
        return result

    def run_steghide_info(self, file_path, timeout=20):
        file_path = Path(file_path)
        if not self.has_tool("steghide"):
            return {"status": "missing", "tool": "steghide", "message": "steghide is not available in the configured toolkit root"}
        if not file_path.exists():
            return {"status": "missing", "tool": "steghide", "message": "file does not exist", "file_path": str(file_path)}
        result = self.run_named_tool("steghide", ["info", str(file_path), "-p", ""], cwd=str(file_path.parent), timeout=timeout)
        result["file_path"] = str(file_path)
        return result

    def run_steghide_extract(self, file_path, output_path, timeout=30):
        file_path = Path(file_path)
        output_path = Path(output_path)
        if not self.has_tool("steghide"):
            return {"status": "missing", "tool": "steghide", "message": "steghide is not available in the configured toolkit root"}
        if not file_path.exists():
            return {"status": "missing", "tool": "steghide", "message": "file does not exist", "file_path": str(file_path)}
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.exists():
            try:
                output_path.unlink()
            except OSError:
                pass
        result = self.run_named_tool(
            "steghide",
            ["extract", "-sf", str(file_path), "-xf", str(output_path), "-p", "", "-f"],
            cwd=str(file_path.parent),
            timeout=timeout,
        )
        result["file_path"] = str(file_path)
        result["output_path"] = str(output_path)
        result["output_exists"] = output_path.exists()
        if output_path.exists():
            result["output_size"] = output_path.stat().st_size
        return result

    def run_binwalk_scan(self, target_path, timeout=30):
        target_path = Path(target_path)
        if not self.has_tool("binwalk"):
            return {"status": "missing", "tool": "binwalk", "message": "binwalk is not available in the configured toolkit root"}
        if not target_path.exists():
            return {"status": "missing", "tool": "binwalk", "message": "target does not exist", "target_path": str(target_path)}
        result = self.run_named_tool("binwalk", [str(target_path)], cwd=str(target_path.parent), timeout=timeout)
        result["target_path"] = str(target_path)
        return result

    def run_binwalk_extract(self, target_path, output_dir, timeout=45):
        target_path = Path(target_path)
        output_dir = Path(output_dir)
        if not self.has_tool("binwalk"):
            return {"status": "missing", "tool": "binwalk", "message": "binwalk is not available in the configured toolkit root"}
        if not target_path.exists():
            return {"status": "missing", "tool": "binwalk", "message": "target does not exist", "target_path": str(target_path)}
        output_dir.mkdir(parents=True, exist_ok=True)
        result = self.run_named_tool(
            "binwalk",
            ["--extract", "--directory", str(output_dir), str(target_path)],
            cwd=str(target_path.parent),
            timeout=timeout,
        )
        extracted_files = []
        if output_dir.exists():
            for item in sorted(path for path in output_dir.rglob("*") if path.is_file()):
                extracted_files.append(str(item))
        result["target_path"] = str(target_path)
        result["output_dir"] = str(output_dir)
        result["extracted_files"] = extracted_files[:80]
        return result

    def run_openssl_base64_decode(self, token, timeout=20):
        raw_token = str(token or "").strip()
        if not self.has_tool("openssl"):
            return {"status": "missing", "tool": "openssl", "message": "openssl is not available in the configured toolkit root"}
        if not raw_token:
            return {"status": "missing", "tool": "openssl", "message": "token is empty"}

        input_handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".b64", delete=False)
        input_path = Path(input_handle.name)
        output_path = input_path.with_suffix(".out")
        input_handle.write(raw_token)
        input_handle.close()
        try:
            result = self.run_named_tool(
                "openssl",
                ["base64", "-d", "-A", "-in", str(input_path), "-out", str(output_path)],
                cwd=str(input_path.parent),
                timeout=timeout,
            )
            decoded_bytes = b""
            decoded_text = ""
            if output_path.exists():
                decoded_bytes = output_path.read_bytes()
                decoded_text = decoded_bytes.decode("utf-8", errors="replace")
            result["token"] = raw_token[:120]
            result["decoded_text"] = decoded_text[:4000]
            result["decoded_size"] = len(decoded_bytes)
            return result
        finally:
            try:
                if input_path.exists():
                    input_path.unlink()
            except Exception:
                pass
            try:
                if output_path.exists():
                    output_path.unlink()
            except Exception:
                pass

    def run_yafu_factor(self, integer_value, timeout=45):
        raw_value = str(integer_value or "").strip()
        if not self.has_tool("yafu"):
            return {"status": "missing", "tool": "yafu", "message": "yafu is not available in the configured toolkit root"}
        if not raw_value or not raw_value.isdigit():
            return {"status": "missing", "tool": "yafu", "message": "integer value is missing or invalid", "integer": raw_value}
        result = self.run_named_tool("yafu", ["factor({0})".format(raw_value)], cwd=str(self.toolkit_root), timeout=timeout)
        stdout = str(result.get("stdout", "") or "")
        factors = []
        for line in stdout.splitlines():
            match = re.search(r"\bP\d+\s*=\s*(\d+)\b", line)
            if match:
                factors.append(int(match.group(1)))
        result["integer"] = raw_value
        result["factors"] = factors
        return result

    def run_pcapfix_probe(self, target_path, timeout=30):
        target_path = Path(target_path)
        if not self.has_tool("pcapfix"):
            return {"status": "missing", "tool": "pcapfix", "message": "pcapfix is not available in the configured toolkit root"}
        if not target_path.exists():
            return {"status": "missing", "tool": "pcapfix", "message": "target does not exist", "target_path": str(target_path)}
        result = self.run_named_tool("pcapfix", [str(target_path), "-d"], cwd=str(target_path.parent), timeout=timeout)
        result["target_path"] = str(target_path)
        return result

    def run_capinfos_probe(self, target_path, timeout=30):
        target_path = Path(target_path)
        if not self.has_tool("capinfos"):
            return {"status": "missing", "tool": "capinfos", "message": "capinfos is not available in the configured toolkit root"}
        if not target_path.exists():
            return {"status": "missing", "tool": "capinfos", "message": "target does not exist", "target_path": str(target_path)}
        result = self.run_named_tool("capinfos", [str(target_path)], cwd=str(target_path.parent), timeout=timeout)
        result["target_path"] = str(target_path)
        return result

    def run_tshark_probe(self, target_path, timeout=45):
        target_path = Path(target_path)
        if not self.has_tool("tshark"):
            return {"status": "missing", "tool": "tshark", "message": "tshark is not available in the configured toolkit root"}
        if not target_path.exists():
            return {"status": "missing", "tool": "tshark", "message": "target does not exist", "target_path": str(target_path)}
        args = [
            "-r",
            str(target_path),
            "-Y",
            "http or dns",
            "-T",
            "fields",
            "-E",
            "separator=|",
            "-e",
            "http.host",
            "-e",
            "http.request.uri",
            "-e",
            "http.response.code",
            "-e",
            "dns.qry.name",
        ]
        result = self.run_named_tool("tshark", args, cwd=str(target_path.parent), timeout=timeout)
        result["target_path"] = str(target_path)
        return result

    def run_pngcheck_probe(self, target_path, timeout=30):
        target_path = Path(target_path)
        if not self.has_tool("pngcheck"):
            return {"status": "missing", "tool": "pngcheck", "message": "pngcheck is not available in the configured toolkit root"}
        if not target_path.exists():
            return {"status": "missing", "tool": "pngcheck", "message": "target does not exist", "target_path": str(target_path)}
        result = self.run_named_tool("pngcheck", ["-vt", str(target_path)], cwd=str(target_path.parent), timeout=timeout)
        result["target_path"] = str(target_path)
        return result

    def run_sox_probe(self, target_path, timeout=30):
        target_path = Path(target_path)
        if not self.has_tool("sox"):
            return {"status": "missing", "tool": "sox", "message": "sox is not available in the configured toolkit root"}
        if not target_path.exists():
            return {"status": "missing", "tool": "sox", "message": "target does not exist", "target_path": str(target_path)}
        result = self.run_named_tool("sox", ["--i", str(target_path)], cwd=str(target_path.parent), timeout=timeout)
        result["target_path"] = str(target_path)
        return result

    def run_ffmpeg_probe(self, target_path, timeout=30):
        target_path = Path(target_path)
        if not self.has_tool("ffmpeg"):
            return {"status": "missing", "tool": "ffmpeg", "message": "ffmpeg is not available in the configured toolkit root"}
        if not target_path.exists():
            return {"status": "missing", "tool": "ffmpeg", "message": "target does not exist", "target_path": str(target_path)}
        result = self.run_named_tool("ffmpeg", ["-hide_banner", "-i", str(target_path)], cwd=str(target_path.parent), timeout=timeout)
        result["target_path"] = str(target_path)
        return result

    def run_ffmpeg_decode_audio(self, target_path, output_path, timeout=60):
        target_path = Path(target_path)
        output_path = Path(output_path)
        if not self.has_tool("ffmpeg"):
            return {"status": "missing", "tool": "ffmpeg", "message": "ffmpeg is not available in the configured toolkit root"}
        if not target_path.exists():
            return {"status": "missing", "tool": "ffmpeg", "message": "target does not exist", "target_path": str(target_path)}
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        result = self.run_named_tool(
            "ffmpeg",
            ["-y", "-hide_banner", "-loglevel", "error", "-i", str(target_path), str(output_path)],
            cwd=str(target_path.parent),
            timeout=timeout,
        )
        result["target_path"] = str(target_path)
        result["output_path"] = str(output_path)
        result["output_exists"] = bool(output_path.exists())
        if output_path.exists():
            try:
                result["output_size"] = int(output_path.stat().st_size)
            except Exception:
                result["output_size"] = 0
        return result

    def run_foremost_scan(self, target_path, output_dir, timeout=90):
        target_path = Path(target_path)
        output_dir = Path(output_dir)
        if not self.has_tool("foremost"):
            return {"status": "missing", "tool": "foremost", "message": "foremost is not available in the configured toolkit root"}
        if not target_path.exists():
            return {"status": "missing", "tool": "foremost", "message": "target does not exist", "target_path": str(target_path)}
        try:
            if output_dir.exists():
                shutil.rmtree(output_dir, ignore_errors=True)
            output_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        result = self.run_named_tool(
            "foremost",
            ["-q", "-i", str(target_path), "-o", str(output_dir)],
            cwd=str(target_path.parent),
            timeout=timeout,
        )
        audit_path = output_dir / "audit.txt"
        recovered_files = []
        if output_dir.exists():
            for item in sorted(path for path in output_dir.rglob("*") if path.is_file()):
                if item.name.lower() == "audit.txt":
                    continue
                recovered_files.append(str(item))
        result["target_path"] = str(target_path)
        result["output_dir"] = str(output_dir)
        result["audit_path"] = str(audit_path) if audit_path.exists() else ""
        result["recovered_files"] = recovered_files[:40]
        return result

    def run_tool_path(self, path, args=None, cwd=None, timeout=120):
        if not path:
            return {"status": "missing", "message": "tool path is empty"}
        tool_path = Path(path)
        if not tool_path.exists():
            return {"status": "missing", "message": "tool path does not exist", "path": str(tool_path)}
        command = [str(tool_path)]
        if args:
            command.extend([str(item) for item in args])
        result = self.shell_tool.run(command, cwd=cwd, timeout=timeout)
        result["status"] = "ok" if result["returncode"] == 0 else "error"
        result["command"] = self.command_preview(command)
        result["path"] = str(tool_path)
        return result

    def build_sqlmap_command(self, target_url, data=None, method="GET", extra_args=None):
        sqlmap_path = self.get_tool_path("sqlmap")
        if not sqlmap_path:
            return None

        command = [sys.executable, str(sqlmap_path), "-u", str(target_url), "--batch"]
        if method and method.upper() != "GET":
            command.extend(["--method", method.upper()])
        if data:
            if isinstance(data, dict):
                pairs = []
                for key, value in data.items():
                    pairs.append("{0}={1}".format(key, value))
                data = "&".join(pairs)
            command.extend(["--data", str(data)])
        if extra_args:
            command.extend([str(item) for item in extra_args])
        return command

    def render_x64dbg_runner(self, binary_path, initial_breakpoints=None):
        debugger = self.select_windows_debugger(binary_path)
        debugger_name = str(debugger.get("debugger_name", "") or "")
        debugger_path = debugger.get("debugger_path", "")
        if not debugger_name or not debugger_path:
            return {
                "status": "missing",
                "message": "no Windows debugger is available in the configured toolkit root",
            }

        binary_path = Path(binary_path)
        breakpoints = [str(item).strip() for item in list(initial_breakpoints or []) if str(item).strip()]
        launcher_name = "{0}_{1}_runner.cmd".format(binary_path.stem, debugger_name)
        notes_name = "{0}_{1}_notes.txt".format(binary_path.stem, debugger_name)
        launcher = [
            "@echo off",
            "setlocal",
            'set "XDBG={0}"'.format(debugger_path),
            'set "TARGET={0}"'.format(binary_path),
            'if not exist "%XDBG%" (',
            '  echo debugger not found: %XDBG%',
            "  exit /b 1",
            ")",
            'if not exist "%TARGET%" (',
            '  echo target not found: %TARGET%',
            "  exit /b 1",
            ")",
            'start "" "%XDBG%" "%TARGET%"',
        ]
        notes = [
            "{0} runner".format(debugger_name),
            "target={0}".format(binary_path),
            "launcher={0}".format(launcher_name),
            "detected_bits={0}".format(debugger.get("bits", "") or "unknown"),
            "selection_reason={0}".format(debugger.get("reason", "")),
            "suggested breakpoints:",
        ]
        if breakpoints:
            for item in breakpoints[:8]:
                notes.append("- {0}".format(item))
        else:
            notes.append("- entry")
            notes.append("- main")
            notes.append("- win / flag / check function")
        notes.extend(
            [
                "",
                "manual follow-up:",
                "- run the launcher",
                "- set breakpoints on candidate validation paths",
                "- capture stack/input traces into the workspace artifacts if dynamic inspection is needed",
            ]
        )
        return {
            "status": "ok",
            "launcher_name": launcher_name,
            "launcher_content": "\n".join(launcher) + "\n",
            "notes_name": notes_name,
            "notes_content": "\n".join(notes) + "\n",
            "command_preview": self.command_preview([str(debugger_path), str(binary_path)]),
            "debugger_name": debugger_name,
            "debugger_path": str(debugger_path),
            "detected_bits": debugger.get("bits", ""),
            "selection_reason": debugger.get("reason", ""),
        }

    def render_ida_runner(self, binary_path, headless=True):
        launcher_name = "idat64" if headless else "ida64"
        launcher_path = self.get_tool_path(launcher_name)
        bootstrap_script = self._detect_ida_bootstrap_script()
        compat_dir = self._detect_ida_compat_dir()
        compat_shim = self._detect_ida_compat_shim()
        binary_path = Path(binary_path)

        if not launcher_path:
            return {"status": "missing", "message": "{0} is not available in the configured toolkit root".format(launcher_name)}
        if not bootstrap_script or not Path(bootstrap_script).exists():
            return {"status": "missing", "message": "IDA bootstrap script is not available"}
        if not compat_dir or not Path(compat_dir).exists() or not compat_shim or not Path(compat_shim).exists():
            return {"status": "missing", "message": "IDA compatibility shim is not available"}
        if not binary_path.exists():
            return {"status": "missing", "message": "binary does not exist", "binary_path": str(binary_path)}

        mode_label = "headless" if headless else "gui"
        launcher_file = "{0}_ida_{1}_runner.cmd".format(binary_path.stem, mode_label)
        notes_file = "{0}_ida_{1}_notes.txt".format(binary_path.stem, mode_label)
        command = self._build_ida_command(binary_path, headless=headless)
        command_preview = self.command_preview(command)
        launcher_lines = [
            "@echo off",
            "setlocal",
            'set "IDA_LAUNCHER={0}"'.format(launcher_path),
            'set "IDA_BOOTSTRAP={0}"'.format(bootstrap_script),
            'set "IDA_COMPAT_DIR={0}"'.format(compat_dir),
            'set "TARGET={0}"'.format(binary_path),
            'if not exist "%IDA_LAUNCHER%" (',
            '  echo ida launcher not found: %IDA_LAUNCHER%',
            "  exit /b 1",
            ")",
            'if not exist "%IDA_BOOTSTRAP%" (',
            '  echo ida bootstrap missing: %IDA_BOOTSTRAP%',
            "  exit /b 1",
            ")",
            'if not exist "%IDA_COMPAT_DIR%\\imp.py" (',
            '  echo ida compat shim missing: %IDA_COMPAT_DIR%\\imp.py',
            "  exit /b 1",
            ")",
            'if not exist "%TARGET%" (',
            '  echo target not found: %TARGET%',
            "  exit /b 1",
            ")",
            'set "PYTHONPATH=%IDA_COMPAT_DIR%;%PYTHONPATH%"',
        ]
        launch_line = 'start "" "%IDA_LAUNCHER%"'
        if headless:
            launch_line += " -A"
        launch_line += ' "-S%IDA_BOOTSTRAP%" "%TARGET%"'
        launcher_lines.append(launch_line)
        notes_lines = [
            "ida {0} runner".format(mode_label),
            "target={0}".format(binary_path),
            "launcher={0}".format(launcher_file),
            "mode={0}".format(mode_label),
            "bootstrap={0}".format(bootstrap_script),
            "compat_dir={0}".format(compat_dir),
            "command={0}".format(command_preview),
            "",
            "manual follow-up:",
            "- run the launcher from the workspace artifact directory",
            "- wait for ida-pro-mcp check_connection to report connected",
            "- keep this launch path for both GUI and headless sessions so the compat shim stays active",
        ]
        return {
            "status": "ok",
            "mode": mode_label,
            "launcher_name": launcher_file,
            "launcher_content": "\n".join(launcher_lines) + "\n",
            "notes_name": notes_file,
            "notes_content": "\n".join(notes_lines) + "\n",
            "command_preview": command_preview,
            "bootstrap_script": str(bootstrap_script),
            "compat_dir": str(compat_dir),
        }

    def launch_ida_live(self, binary_path, headless=True):
        launcher_name = "idat64" if headless else "ida64"
        launcher_path = self.get_tool_path(launcher_name)
        bootstrap_script = self._detect_ida_bootstrap_script()
        compat_dir = self._detect_ida_compat_dir()
        compat_shim = self._detect_ida_compat_shim()
        binary_path = Path(binary_path)

        if not launcher_path:
            return {"status": "missing", "message": "{0} is not available in the configured toolkit root".format(launcher_name)}
        if not bootstrap_script or not Path(bootstrap_script).exists():
            return {"status": "missing", "message": "IDA bootstrap script is not available"}
        if not compat_dir or not Path(compat_dir).exists() or not compat_shim or not Path(compat_shim).exists():
            return {"status": "missing", "message": "IDA compatibility shim is not available"}
        if not binary_path.exists():
            return {"status": "missing", "message": "binary does not exist", "binary_path": str(binary_path)}

        command = self._build_ida_command(binary_path, headless=headless)
        env = self._build_ida_env()
        compat_text = str(compat_dir)

        creationflags = 0
        for name in ["CREATE_NEW_PROCESS_GROUP", "DETACHED_PROCESS", "CREATE_NO_WINDOW"]:
            creationflags |= int(getattr(subprocess, name, 0))

        try:
            process = subprocess.Popen(
                command,
                cwd=str(binary_path.parent),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
            )
        except Exception as exc:
            return {
                "status": "error",
                "message": "failed to launch IDA live sidecar",
                "error": str(exc),
                "command_preview": self.command_preview(command),
            }

        return {
            "status": "ok",
            "mode": "headless" if headless else "gui",
            "pid": int(process.pid),
            "binary_path": str(binary_path),
            "bootstrap_script": str(bootstrap_script),
            "compat_dir": compat_text,
            "command_preview": self.command_preview(command),
        }

    def _build_ida_command(self, binary_path, headless=True):
        launcher_name = "idat64" if headless else "ida64"
        launcher_path = self.get_tool_path(launcher_name)
        bootstrap_script = self._detect_ida_bootstrap_script()
        binary_path = Path(binary_path)
        command = [str(launcher_path)]
        if headless:
            command.append("-A")
        command.append("-S{0}".format(bootstrap_script))
        command.append(str(binary_path))
        return command

    def _build_ida_env(self):
        env = os.environ.copy()
        compat_dir = self._detect_ida_compat_dir()
        compat_text = str(compat_dir)
        current_pythonpath = str(env.get("PYTHONPATH", "") or "")
        env["PYTHONPATH"] = compat_text if not current_pythonpath else compat_text + os.pathsep + current_pythonpath
        return env

    def command_preview(self, command):
        return " ".join(self._quote_piece(item) for item in command)

    def _quote_piece(self, value):
        value = str(value)
        if " " in value:
            return '"{0}"'.format(value)
        return value

    def _first_existing_marker(self, markers):
        for candidate in list(markers or []):
            path = self.toolkit_root.joinpath(*candidate)
            if path.exists():
                return path
        return None

    def _probe_runtime_library_status(self, names):
        if self._runtime_import_cache is not None:
            return dict(self._runtime_import_cache)
        runtime = self.detect_toolkit_python_executable()
        if not runtime:
            self._runtime_import_cache = {}
            return {}
        code = r"""
import importlib
import json
import sys

payload = json.loads(sys.stdin.read() or "[]")
result = {}
for item in list(payload or []):
    name = str(item or "").strip()
    if not name:
        continue
    try:
        if name == "pycryptodome":
            importlib.import_module("Crypto")
        else:
            importlib.import_module(name)
        result[name] = "ok"
    except Exception as exc:
        result[name] = str(exc)
print(json.dumps(result, ensure_ascii=False))
"""
        result = self.run_toolkit_python_inline(
            code,
            stdin_text=json.dumps(list(names or []), ensure_ascii=False),
            timeout=30,
        )
        if result.get("status") != "ok":
            self._runtime_import_cache = {}
            return {}
        try:
            payload = json.loads(str(result.get("stdout", "") or "").strip() or "{}")
        except Exception:
            payload = {}
        self._runtime_import_cache = dict(payload)
        return dict(payload)

    def is_tool_healthy(self, name):
        name = str(name or "").strip().lower()
        if not name:
            return False
        if self._tool_health_cache is None:
            self._tool_health_cache = {}
        if name in self._tool_health_cache:
            return bool(self._tool_health_cache.get(name))
        healthy = True
        if name == "sage":
            healthy = self._probe_sage_health()
        elif name == "yafu":
            healthy = self._probe_yafu_health()
        self._tool_health_cache[name] = bool(healthy)
        return bool(healthy)

    def _probe_sage_health(self):
        if not self.has_tool("sage"):
            return False
        result = self.run_named_tool("sage", ["-c", "print(2+2)"], cwd=str(self.toolkit_root), timeout=45)
        stdout = str(result.get("stdout", "") or "").strip()
        return result.get("status") == "ok" and stdout.endswith("4")

    def _probe_yafu_health(self):
        if not self.has_tool("yafu"):
            return False
        result = self.run_yafu_factor(15, timeout=30)
        factors = sorted(int(item) for item in list(result.get("factors", [])) if str(item).isdigit())
        return result.get("status") == "ok" and factors[:2] == [3, 5]

    def _detect_ida_plugin_path(self):
        base = Path.home() / "AppData" / "Roaming" / "Hex-Rays" / "IDA Pro" / "plugins" / "mcp-plugin.py"
        return str(base) if base.exists() else ""

    def _detect_ida_bootstrap_script(self):
        candidate = Path(__file__).resolve().with_name("ida_mcp_bootstrap.py")
        return str(candidate) if candidate.exists() else ""

    def _detect_ida_compat_dir(self):
        candidate = Path(__file__).resolve().with_name("ida_compat")
        return str(candidate) if candidate.exists() else ""

    def _detect_ida_compat_shim(self):
        compat_dir = self._detect_ida_compat_dir()
        if not compat_dir:
            return ""
        candidate = Path(compat_dir) / "imp.py"
        return str(candidate) if candidate.exists() else ""

    def _stringify_path(self, value):
        return str(value) if value else ""

    def _unique(self, items):
        seen = set()
        result = []
        for item in list(items or []):
            key = str(item or "").strip()
            if not key or key in seen:
                continue
            seen.add(key)
            result.append(key)
        return result

    def _reason_for_name(self, name, category="", subtype="", kind="tool"):
        name = str(name or "").strip()
        category = str(category or "").strip().lower()
        subtype = str(subtype or "").strip().lower()
        if kind == "library":
            reason = self.LIBRARY_REASON_HINTS.get(name)
        elif kind == "sidecar":
            reason = self.SIDECAR_REASON_HINTS.get(name) or self.TOOL_REASON_HINTS.get(name)
        else:
            reason = self.TOOL_REASON_HINTS.get(name)
        if reason:
            if category == "crypto" and name in {"gmpy2", "z3", "sage", "yafu", "openssl"}:
                return "{0} Triggered by bounded number-theory or encoding paths.".format(reason)
            if category == "osint" and name in {"browser-use", "wireshark", "tshark", "capinfos"}:
                return "{0} Triggered when public-source expansion or dynamic pages need heavier visibility.".format(reason)
            if category == "misc" and subtype == "stego" and name in {"steghide", "pngdebugger", "pngcheck", "exiftool", "binwalk"}:
                return "{0} Triggered by stego-specific artifact hints.".format(reason)
            if category == "misc" and subtype == "rf" and name in {"sox", "ffmpeg", "wireshark"}:
                return "{0} Triggered by media or signal container hints.".format(reason)
            if category == "misc" and subtype == "dns" and name in {"tshark", "capinfos", "pcapfix", "wireshark", "tcpview"}:
                return "{0} Triggered by DNS, PCAP, or network-artifact hints.".format(reason)
            if category == "forensics" and name in {"wireshark", "tshark", "capinfos", "pcapfix", "foremost", "7z"}:
                return "{0} Triggered by container, carving, or PCAP recovery requirements.".format(reason)
            if category in {"pwn", "re", "reverse"} and name in {"radare2", "ida64", "idat64", "x64dbg", "x32dbg"}:
                return "{0} Triggered by binary analysis or live-debug requirements.".format(reason)
            return reason
        if category and subtype:
            return "Recommended for {0}:{1} based on the current capability plan.".format(category, subtype)
        if category:
            return "Recommended for {0} based on the current capability plan.".format(category)
        return "Recommended by the current capability plan."
