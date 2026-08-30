#!/usr/bin/env python3
"""Build an iOS Unscroll IPA with a minimal client-side Reels limiter."""

from __future__ import annotations

import argparse
import shutil
import struct
import tempfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile, ZipInfo


EXECUTABLE = "Payload/Instagram.app/Instagram"
RUNTIME_FIX_NAME = "UnscrollRuntimeFix.dylib"
RUNTIME_FIX_ARCHIVE_PATH = f"Payload/Instagram.app/Frameworks/{RUNTIME_FIX_NAME}"
RUNTIME_FIX_INSTALL_NAME = f"@executable_path/Frameworks/{RUNTIME_FIX_NAME}"
EXTENSION_PREFIXES = (
    "Payload/Instagram.app/Extensions/",
    "Payload/Instagram.app/PlugIns/",
)
LC_LOAD_DYLIB = 0xC
LC_SEGMENT_64 = 0x19
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build an iOS Instagram IPA with a single-item Reels viewer."
    )
    parser.add_argument("input", type=Path, help="decrypted Instagram IPA")
    parser.add_argument("output", type=Path, help="output Unscroll IPA")
    parser.add_argument(
        "--runtime-fix",
        type=Path,
        required=True,
        help="inject UnscrollRuntimeFix.dylib for sideload compatibility",
    )
    parser.add_argument(
        "--keep-extensions",
        action="store_true",
        help="retain app extensions (not recommended for SideStore)",
    )
    return parser.parse_args()


def encryption_id(binary: Path) -> int:
    with binary.open("rb") as stream:
        header = stream.read(32)
        if len(header) != 32:
            raise ValueError("Instagram executable is too small to be a Mach-O file")
        magic, _, _, _, command_count, _, _, _ = struct.unpack("<IiiIIIII", header)
        if magic != 0xFEEDFACF:
            raise ValueError(f"unsupported Mach-O magic 0x{magic:08x}; expected ARM64")

        for _ in range(command_count):
            command_header = stream.read(8)
            if len(command_header) != 8:
                raise ValueError("truncated Mach-O load commands")
            command, command_size = struct.unpack("<II", command_header)
            if command_size < 8:
                raise ValueError("invalid Mach-O load command size")
            payload = stream.read(command_size - 8)
            if len(payload) != command_size - 8:
                raise ValueError("truncated Mach-O load command")
            if command in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
                _, _, crypt_id = struct.unpack("<III", payload[:12])
                return crypt_id
    raise ValueError("Mach-O has no encryption information load command")


def inject_dylib(binary_path: Path, install_name: str) -> None:
    encoded_name = install_name.encode() + b"\0"
    command_size = (24 + len(encoded_name) + 7) & ~7
    dylib_command = (
        struct.pack("<IIIIII", LC_LOAD_DYLIB, command_size, 24, 0, 0, 0)
        + encoded_name
    ).ljust(command_size, b"\0")

    with binary_path.open("r+b") as stream:
        header = stream.read(32)
        if len(header) != 32:
            raise ValueError("Instagram executable has a truncated Mach-O header")
        (
            magic,
            cpu_type,
            _,
            _,
            command_count,
            commands_size,
            _,
            _,
        ) = struct.unpack("<IiiIIIII", header)
        if magic != 0xFEEDFACF or cpu_type != 0x0100000C:
            raise ValueError("dylib injection requires a 64-bit ARM Mach-O")

        command_area = stream.read(commands_size)
        if len(command_area) != commands_size:
            raise ValueError("Instagram executable has truncated load commands")
        if encoded_name[:-1] in command_area:
            raise ValueError(f"dylib is already injected: {install_name}")

        minimum_section_offset = binary_path.stat().st_size
        cursor = 0
        for _ in range(command_count):
            command, size = struct.unpack_from("<II", command_area, cursor)
            if size < 8 or cursor + size > len(command_area):
                raise ValueError("invalid Mach-O load command while injecting dylib")
            if command == LC_SEGMENT_64:
                if size < 72:
                    raise ValueError("invalid 64-bit Mach-O segment command")
                section_count = struct.unpack_from("<I", command_area, cursor + 64)[0]
                if 72 + section_count * 80 > size:
                    raise ValueError("invalid Mach-O section table")
                for section_index in range(section_count):
                    section = cursor + 72 + section_index * 80
                    section_offset = struct.unpack_from(
                        "<I", command_area, section + 48
                    )[0]
                    if section_offset:
                        minimum_section_offset = min(
                            minimum_section_offset, section_offset
                        )
            cursor += size

        command_end = 32 + commands_size
        new_command_end = command_end + command_size
        if new_command_end > minimum_section_offset:
            raise ValueError("Mach-O has insufficient header padding for dylib injection")
        stream.seek(command_end)
        if any(stream.read(command_size)):
            raise ValueError("Mach-O load command padding is not empty")

        stream.seek(command_end)
        stream.write(dylib_command)
        stream.seek(16)
        stream.write(struct.pack("<II", command_count + 1, commands_size + command_size))


def validate_runtime_fix(dylib_path: Path) -> None:
    with dylib_path.open("rb") as stream:
        header = stream.read(32)
    if len(header) != 32:
        raise ValueError("runtime fix dylib is truncated")
    magic, cpu_type, _, file_type, _, _, _, _ = struct.unpack(
        "<IiiIIIII", header
    )
    if magic != 0xFEEDFACF or cpu_type != 0x0100000C or file_type != 6:
        raise ValueError("runtime fix must be an ARM64 Mach-O dylib")


def validate_binary(binary_path: Path) -> None:
    crypt_id = encryption_id(binary_path)
    if crypt_id != 0:
        raise ValueError(
            f"Instagram executable is encrypted (cryptid={crypt_id}); "
            "use a decrypted IPA"
        )


def copy_zip_entry(source: ZipFile, target: ZipFile, info) -> None:
    if info.is_dir():
        target.writestr(info, b"")
        return
    with source.open(info, "r") as reader, target.open(info, "w") as writer:
        shutil.copyfileobj(reader, writer, length=1024 * 1024)


def add_runtime_fix(target: ZipFile, dylib_path: Path) -> None:
    info = ZipInfo(RUNTIME_FIX_ARCHIVE_PATH)
    info.create_system = 3
    info.compress_type = ZIP_DEFLATED
    info.external_attr = 0o100755 << 16
    with dylib_path.open("rb") as reader, target.open(info, "w") as writer:
        shutil.copyfileobj(reader, writer)


def build_ipa(
    source_path: Path,
    output_path: Path,
    keep_extensions: bool,
    runtime_fix: Path,
) -> None:
    source_path = source_path.resolve()
    output_path = output_path.resolve()
    runtime_fix = runtime_fix.resolve()
    validate_runtime_fix(runtime_fix)
    if source_path == output_path:
        raise ValueError("input and output IPA paths must differ")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix=".unscroll-", dir=output_path.parent
    ) as temporary_dir:
        temporary = Path(temporary_dir)
        binary_path = temporary / "Instagram"
        staged_output = temporary / output_path.name

        try:
            with ZipFile(source_path, "r") as source:
                names = set(source.namelist())
                if EXECUTABLE not in names:
                    raise ValueError(f"IPA does not contain {EXECUTABLE}")
                with source.open(EXECUTABLE) as reader, binary_path.open("wb") as writer:
                    shutil.copyfileobj(reader, writer, length=1024 * 1024)

                validate_binary(binary_path)
                inject_dylib(binary_path, RUNTIME_FIX_INSTALL_NAME)

                removed_entries = 0
                with ZipFile(staged_output, "w", allowZip64=True) as target:
                    for info in source.infolist():
                        if info.filename == RUNTIME_FIX_ARCHIVE_PATH:
                            continue
                        if not keep_extensions and info.filename.startswith(
                            EXTENSION_PREFIXES
                        ):
                            removed_entries += 1
                            continue
                        if info.filename == EXECUTABLE:
                            with binary_path.open("rb") as reader, target.open(
                                info, "w"
                            ) as writer:
                                shutil.copyfileobj(reader, writer, length=1024 * 1024)
                        else:
                            copy_zip_entry(source, target, info)
                    add_runtime_fix(target, runtime_fix)
        except BadZipFile as error:
            raise ValueError(f"invalid IPA/ZIP archive: {error}") from error

        with ZipFile(staged_output, "r") as verification:
            bad_entry = verification.testzip()
            if bad_entry:
                raise ValueError(f"rebuilt IPA failed CRC validation at {bad_entry}")
            if not keep_extensions and any(
                name.startswith(EXTENSION_PREFIXES)
                for name in verification.namelist()
            ):
                raise ValueError("an app extension remains in the rebuilt IPA")
            if RUNTIME_FIX_ARCHIVE_PATH not in verification.namelist():
                raise ValueError("runtime fix is missing from the rebuilt IPA")

        staged_output.replace(output_path)

    if not keep_extensions:
        print(f"Removed extension entries: {removed_entries}")
    print(f"Injected client-side Reels limiter: {RUNTIME_FIX_NAME}")
    print(f"Created: {output_path}")


def main() -> None:
    args = parse_args()
    try:
        build_ipa(
            args.input,
            args.output,
            args.keep_extensions,
            args.runtime_fix,
        )
    except (OSError, ValueError) as error:
        raise SystemExit(f"error: {error}") from error


if __name__ == "__main__":
    main()
