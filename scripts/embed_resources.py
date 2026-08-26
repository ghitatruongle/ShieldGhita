import ctypes
import struct
import sys
from pathlib import Path

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

k32.BeginUpdateResourceW.restype = ctypes.c_void_p
k32.BeginUpdateResourceW.argtypes = [ctypes.c_wchar_p, ctypes.c_bool]
k32.UpdateResourceW.restype = ctypes.c_bool
k32.UpdateResourceW.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_ushort,
    ctypes.c_char_p,
    ctypes.c_uint32,
]
k32.EndUpdateResourceW.restype = ctypes.c_bool
k32.EndUpdateResourceW.argtypes = [ctypes.c_void_p, ctypes.c_bool]

RT_ICON = 3
RT_GROUP_ICON = 14
RT_VERSION = 16
RT_MANIFEST = 24
LANG_ID = 0x0409


def make_int_resource(i):
    return ctypes.c_void_p(i)


def begin_update(path):
    h = k32.BeginUpdateResourceW(str(path), False)
    if not h:
        raise OSError(f"BeginUpdateResourceW failed err={ctypes.get_last_error()}")
    return h


def update_res(h, rtype, rid, data, lang=LANG_ID):
    buf = ctypes.create_string_buffer(data, len(data))
    ok = k32.UpdateResourceW(h, make_int_resource(rtype), make_int_resource(rid), lang, buf, len(data))
    if not ok:
        raise OSError(f"UpdateResourceW type={rtype} id={rid} failed err={ctypes.get_last_error()}")


def end_update(h):
    if not k32.EndUpdateResourceW(h, False):
        raise OSError(f"EndUpdateResourceW failed err={ctypes.get_last_error()}")


def read_ico_icons(ico_path):
    raw = Path(ico_path).read_bytes()
    _, _, count = struct.unpack("<HHH", raw[:6])
    icons = []
    for i in range(count):
        off = 6 + 16 * i
        _w, _h, _c, _r, planes, bpp, size, doff = struct.unpack("<BBBBHHII", raw[off : off + 16])
        icons.append(
            {
                "width": _w or 256,
                "height": _h or 256,
                "planes": planes,
                "bpp": bpp,
                "data": raw[doff : doff + size],
            }
        )
    return icons


def group_icon_blob(icons):
    out = struct.pack("<HHH", 0, 1, len(icons))
    for idx, icon in enumerate(icons, start=1):
        dim = 0 if icon["width"] >= 256 else icon["width"]
        out += struct.pack(
            "<BBBBHHIH",
            dim,
            dim,
            0,
            0,
            icon["planes"] or 1,
            icon["bpp"] or 32,
            len(icon["data"]),
            idx,
        )
    return out


def align4(buf):
    return buf + b"\x00" * ((4 - len(buf) % 4) % 4)


def ustr(s):
    return s.encode("utf-16-le") + b"\x00\x00"


APP_VERSION = "0.1.0-beta1"


def pad4(buf):
    return buf + b"\x00" * ((4 - len(buf) % 4) % 4)


def version_numeric_fields(version_str):
    """Map '0.1.0-beta1' -> MS/LS dword pair (non-numeric tail becomes 0)."""
    nums = []
    for part in version_str.split(".")[:4]:
        digits = ""
        for ch in part:
            if ch.isdigit():
                digits += ch
            elif digits:
                break
        nums.append(int(digits) if digits else 0)
    while len(nums) < 4:
        nums.append(0)
    major, minor, patch, revision = nums[:4]
    ms = (major << 16) | minor
    ls = (patch << 16) | revision
    return ms, ls


def make_string_entry(key, value):
    key_b = ustr(key)
    val_b = ustr(value)
    key_part = pad4(struct.pack("<HHH", 0, len(val_b), 1) + key_b)
    entry = key_part + val_b
    entry = pad4(entry)
    total = len(entry)
    return struct.pack("<HHH", total, len(val_b), 1) + entry[6:]


def make_string_table(lang_id, entries):
    key_b = ustr(lang_id)
    body = pad4(struct.pack("<HHH", 0, 0, 1) + key_b)
    for key, value in entries:
        body += make_string_entry(key, value)
    return struct.pack("<HHH", len(body), 0, 1) + body[6:]


def make_string_file_info(tables):
    key_b = ustr("StringFileInfo")
    body = pad4(struct.pack("<HHH", 0, 0, 1) + key_b)
    for table in tables:
        body += table
    return struct.pack("<HHH", len(body), 0, 1) + body[6:]


def make_var_file_info():
    key_b = ustr("VarFileInfo")
    val = struct.pack("<HH", 0x0409, 1200)
    body = pad4(struct.pack("<HHH", 0, len(val), 0) + key_b) + val
    body = pad4(body)
    return struct.pack("<HHH", len(body), len(val), 0) + body[6:]


def build_version_info(version_str):
    ms, ls = version_numeric_fields(version_str)
    ffi = struct.pack(
        "<13I",
        0xFEEF04BD,      # dwSignature
        0x00010000,      # dwStrucVersion
        ms, ls,          # dwFileVersion
        ms, ls,          # dwProductVersion
        0x0000003F,      # dwFileFlagsMask
        0x00000000,      # dwFileFlags
        0x00040004,      # dwFileOS: VOS_NT_WINDOWS32
        0x00000001,      # dwFileType: VFT_APP
        0x00000000,      # dwFileSubtype
        0x00000000,      # dwFileDateMS
        0x00000000,      # dwFileDateLS
    )

    entries = [
        ("CompanyName", "ShieldGhita"),
        ("FileDescription", "Shield Ghita - Master Internet Controller & Ad Blocker"),
        ("FileVersion", version_str),
        ("InternalName", "shield_ghita"),
        ("LegalCopyright", "Copyright (C) 2026 ShieldGhita"),
        ("OriginalFilename", "shield_ghita.exe"),
        ("ProductName", "Shield Ghita"),
        ("ProductVersion", version_str),
    ]
    sfi_block = make_string_file_info([make_string_table("040904b0", entries)])
    vfi_block = make_var_file_info()

    key_b = ustr("VS_VERSION_INFO")
    core = pad4(struct.pack("<HHH", 0, 52, 0) + key_b) + ffi + sfi_block + vfi_block
    return struct.pack("<HHH", len(core), 52, 0) + core[6:]


def main():
    exe = Path(sys.argv[1])
    root = Path(__file__).resolve().parent.parent
    icons = read_ico_icons(root / "assets" / "app_icon.ico")
    manifest = (root / "app.manifest").read_bytes()
    version = build_version_info(APP_VERSION)

    h = begin_update(exe)
    try:
        for idx, icon in enumerate(icons, start=1):
            update_res(h, RT_ICON, idx, icon["data"])
        update_res(h, RT_GROUP_ICON, 1, group_icon_blob(icons))
        update_res(h, RT_MANIFEST, 1, manifest)
        update_res(h, RT_VERSION, 1, version)
        end_update(h)
    except Exception:
        k32.EndUpdateResourceW(h, True)
        raise

    print(f"Embedded {len(icons)} icons + manifest + versioninfo into {exe}")


if __name__ == "__main__":
    main()
