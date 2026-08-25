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


def pack_str_hdr(total_len):
    return struct.pack("<HHH", total_len, 0, 1)


def build_version_string(key, value):
    key_b = ustr(key)
    val_b = ustr(value)
    str_len = 6 + len(key_b) + len(val_b)
    entry = struct.pack("<HHH", str_len, len(val_b), 1) + key_b
    entry = align4(entry)
    entry += val_b
    entry = align4(entry)
    return entry


def build_version_info():
    ffi = struct.pack(
        "<14I",
        0xFEEF04BD,
        0x00010000,
        0x00000000,
        0x00000005,
        0x00000000,
        0x00000005,
        0x0000003F,
        0x00000000,
        0x00040004,
        0x00000001,
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000,
    )

    table_body = pack_str_hdr(6 + len(ustr("000004b0"))) + ustr("000004b0")
    table_body = align4(table_body)
    for key, value in [
        ("CompanyName", "ShieldGhita"),
        ("FileDescription", "Shield Ghita - Master Internet Controller & Ad Blocker"),
        ("FileVersion", "0.1.0-demo"),
        ("InternalName", "shield_ghita"),
        ("LegalCopyright", "Copyright (C) 2026 ShieldGhita"),
        ("OriginalFilename", "shield_ghita.exe"),
        ("ProductName", "Shield Ghita"),
        ("ProductVersion", "0.1.0-demo"),
    ]:
        table_body += build_version_string(key, value)

    sfi_head = align4(pack_str_hdr(6 + len(ustr("StringFileInfo"))) + ustr("StringFileInfo")[: len(ustr("StringFileInfo"))])
    sfi_head = struct.pack("<HHH", 6 + len(ustr("StringFileInfo")), 0, 1) + ustr("StringFileInfo")
    sfi_head = align4(sfi_head)
    sfi_block = struct.pack("<HHH", len(sfi_head) + len(table_body), 0, 1) + sfi_head[6:] + table_body

    vfi_key = ustr("Translation")
    vfi_data = struct.pack("<HH", 0x04B0, 1200)
    vfi_child_len = 6 + len(vfi_key) + len(vfi_data)
    vfi_child = struct.pack("<HHH", vfi_child_len, 4, 0) + vfi_key
    vfi_child = align4(vfi_child)
    vfi_child += vfi_data
    vfi_head = align4(struct.pack("<HHH", 6 + len(ustr("VarFileInfo")), 0, 1) + ustr("VarFileInfo"))
    vfi_block = struct.pack("<HHH", len(vfi_head) + len(vfi_child), 0, 1) + vfi_head[6:] + vfi_child

    top_key = ustr("VS_VERSION_INFO")
    top_head = align4(struct.pack("<HHH", 0, 52, 0) + top_key)
    total = len(top_head) + 52 + len(sfi_block) + len(vfi_block)
    top = struct.pack("<HHH", total, 52, 0) + top_key
    top = align4(top)
    return top + ffi + sfi_block + vfi_block


def main():
    exe = Path(sys.argv[1])
    root = Path(__file__).resolve().parent.parent
    icons = read_ico_icons(root / "assets" / "app_icon.ico")
    manifest = (root / "app.manifest").read_bytes()
    version = build_version_info()

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
