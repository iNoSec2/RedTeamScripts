#!/usr/bin/env python3
"""Parse uncompressed OAB v4 Full Details files (udetails.oab) per MS-OXOAB."""

from __future__ import annotations

import argparse
import binascii
import csv
import io
import json
import sys
import time
import uuid
from struct import unpack
from typing import Any, Callable, Iterator, Optional

OAB_V4_VERSION = 0x20

BANNER = r"""
      __...--~~~~~-._   _.-~~~~~--...__
    //               `V'               \\
   //     OFFLINE     |   ADDRESSBOOK   \\
  //__...--~~~~~~-._  |  _.-~~~~~~--...__\\
 //__.....----~~~~._\ | /_.~~~~----.....__\\
====================\|//====================
                    `---`
              oabparser -- Python 3 -- MS-OXOAB v4 parser
"""


def print_banner(stream=sys.stderr) -> None:
    try:
        stream.write(BANNER)
        stream.write("\n")
        stream.flush()
    except Exception:
        pass

PTYP_INTEGER32 = "PtypInteger32"
PTYP_BOOLEAN = "PtypBoolean"
PTYP_STRING = "PtypString"
PTYP_STRING8 = "PtypString8"
PTYP_BINARY = "PtypBinary"
PTYP_MULTIPLE_INTEGER32 = "PtypMultipleInteger32"
PTYP_MULTIPLE_STRING = "PtypMultipleString"
PTYP_MULTIPLE_STRING8 = "PtypMultipleString8"
PTYP_MULTIPLE_BINARY = "PtypMultipleBinary"
PTYP_OBJECT = "PtypObject"
PTYP_EMBEDDED_TABLE = "PtypEmbeddedTable"

TYPE_CODE_TO_NAME = {
    0x0003: PTYP_INTEGER32,
    0x000B: PTYP_BOOLEAN,
    0x001E: PTYP_STRING8,
    0x001F: PTYP_STRING,
    0x0102: PTYP_BINARY,
    0x1003: PTYP_MULTIPLE_INTEGER32,
    0x101E: PTYP_MULTIPLE_STRING8,
    0x101F: PTYP_MULTIPLE_STRING,
    0x1102: PTYP_MULTIPLE_BINARY,
    0x000D: PTYP_OBJECT,
}

# Seeded from antimatter15/boa schema.py (verified against real OABs) and
# extended with additional address-book PropIDs from MS-OXPROPS. Unknown PropIDs
# at runtime fall back to type-inference from the low 16 bits of the tag.
PID_TAG_SCHEMA: dict[str, tuple[str, str]] = {
    "3003001E": ("EmailAddress", PTYP_STRING8),
    "39FE001F": ("SmtpAddress", PTYP_STRING),
    "3001001F": ("DisplayName", PTYP_STRING),
    "8C92001F": ("AddressBookPhoneticDisplayName", PTYP_STRING),
    "3A00001F": ("Account", PTYP_STRING),
    "3A11001F": ("Surname", PTYP_STRING),
    "8C8F001F": ("AddressBookPhoneticSurname", PTYP_STRING),
    "3A06001F": ("GivenName", PTYP_STRING),
    "8C8E001F": ("AddressBookPhoneticGivenName", PTYP_STRING),
    "800F101F": ("AddressBookProxyAddresses", PTYP_MULTIPLE_STRING),
    "3A19001F": ("OfficeLocation", PTYP_STRING),
    "39000003": ("DisplayType", PTYP_INTEGER32),
    "0FFE0003": ("ObjectType", PTYP_INTEGER32),
    "3A40000B": ("SendRichInfo", PTYP_BOOLEAN),
    "3A08001F": ("BusinessTelephoneNumber", PTYP_STRING),
    "3A0A001F": ("Initials", PTYP_STRING),
    "3A29001F": ("StreetAddress", PTYP_STRING),
    "3A27001F": ("Locality", PTYP_STRING),
    "3A28001F": ("StateOrProvince", PTYP_STRING),
    "3A2A001F": ("PostalCode", PTYP_STRING),
    "3A26001F": ("Country", PTYP_STRING),
    "3A17001F": ("Title", PTYP_STRING),
    "3A16001F": ("CompanyName", PTYP_STRING),
    "8C91001F": ("AddressBookPhoneticCompanyName", PTYP_STRING),
    "3A30001F": ("Assistant", PTYP_STRING),
    "3A18001F": ("DepartmentName", PTYP_STRING),
    "8C90001F": ("AddressBookPhoneticDepartmentName", PTYP_STRING),
    "8011001F": ("AddressBookTargetAddress", PTYP_STRING),
    "3A09001F": ("HomeTelephoneNumber", PTYP_STRING),
    "3A1B101F": ("Business2TelephoneNumbers", PTYP_MULTIPLE_STRING),
    "3A2F101F": ("Home2TelephoneNumbers", PTYP_MULTIPLE_STRING),
    "3A23001F": ("PrimaryFaxNumber", PTYP_STRING),
    "3A1C001F": ("MobileTelephoneNumber", PTYP_STRING),
    "3A2E001F": ("AssistantTelephoneNumber", PTYP_STRING),
    "3A21001F": ("PagerTelephoneNumber", PTYP_STRING),
    "3004001F": ("Comment", PTYP_STRING),
    "3A220102": ("UserCertificate", PTYP_BINARY),
    "3A701102": ("UserX509Certificate", PTYP_MULTIPLE_BINARY),
    "8C6A1102": ("AddressBookX509Certificate", PTYP_MULTIPLE_BINARY),
    "8006001E": ("AddressBookHomeMessageDatabase", PTYP_STRING8),
    "39FF001E": ("AddressBookDisplayNamePrintable", PTYP_STRING8),
    "39050003": ("DisplayTypeEx", PTYP_INTEGER32),
    "8CA00003": ("AddressBookSeniorityIndex", PTYP_INTEGER32),
    "8CDD000B": ("AddressBookHierarchicalIsHierarchicalGroup", PTYP_BOOLEAN),
    "8C6D0102": ("AddressBookObjectGuid", PTYP_BINARY),
    "8CAC101F": ("AddressBookSenderHintTranslations", PTYP_MULTIPLE_STRING),
    "806A0003": ("AddressBookDeliveryContentLength", PTYP_INTEGER32),
    "8CB5000B": ("AddressBookModerationEnabled", PTYP_BOOLEAN),
    "8CE20003": ("AddressBookDistributionListMemberCount", PTYP_INTEGER32),
    "8CE30003": ("AddressBookDistributionListExternalMemberCount", PTYP_INTEGER32),
    "8009101E": ("AddressBookMember", PTYP_EMBEDDED_TABLE),
    "8008101E": ("AddressBookIsMemberOfDistributionList", PTYP_EMBEDDED_TABLE),
    "68051003": ("OfflineAddressBookTruncatedProperties", PTYP_MULTIPLE_INTEGER32),
    "8C9E0102": ("ThumbnailPhoto", PTYP_BINARY),
    "8CC20102": ("SpokenName", PTYP_BINARY),
    "8CD8000D": ("AddressBookAuthorizedSenders", PTYP_OBJECT),
    "8CD9000D": ("AddressBookUnauthorizedSenders", PTYP_OBJECT),
    "8073000D": ("AddressBookDistributionListMemberSubmitAccepted", PTYP_OBJECT),
    "8CDA000D": ("AddressBookDistributionListMemberSubmitRejected", PTYP_OBJECT),
    "8CDB000D": ("AddressBookDistributionListRejectMessagesFromDLMembers", PTYP_OBJECT),
    # OAB header-record properties
    "6800001F": ("OfflineAddressBookName", PTYP_STRING),
    "6801001F": ("OfflineAddressBookSequence", PTYP_STRING),
    "68010003": ("OfflineAddressBookSequence", PTYP_INTEGER32),
    "6802001E": ("OfflineAddressBookContainerGuid", PTYP_STRING8),
    "6803001E": ("OfflineAddressBookContainerGuid", PTYP_STRING8),
    "6804001E": ("OfflineAddressBookDistinguishedName", PTYP_STRING8),
    "8C98001E": ("AddressBookHierarchicalRoot", PTYP_STRING8),
    # Extended address-book attributes commonly seen in modern OABs
    "8005001E": ("AddressBookManagerDistinguishedName", PTYP_STRING8),
    "8C57001E": ("AddressBookExternalMemberCount", PTYP_STRING8),
    "8C6B101E": ("AddressBookOrganizationalUnitRootDistinguishedName", PTYP_MULTIPLE_STRING8),
    "8C8D001F": ("AddressBookManager", PTYP_STRING),
    "8C9F0003": ("AddressBookHierarchicalChildDepartments", PTYP_INTEGER32),
    "8CB60003": ("AddressBookHierarchicalDepartmentMembers", PTYP_INTEGER32),
    "8C730102": ("AddressBookMailboxGuid", PTYP_BINARY),
    "8D0D001F": ("AddressBookExternalDirectoryObjectId", PTYP_STRING),
}

# Binary properties that are 16-byte little-endian Windows GUIDs (Data1/Data2/Data3
# stored LE, Data4 sequential). Rendered as standard textual UUIDs in output.
_GUID_BINARY_PROPS = frozenset({"AddressBookObjectGuid", "AddressBookMailboxGuid"})


def hexify(prop_id: int) -> str:
    return "{0:08X}".format(prop_id)


def infer_type_from_propid(prop_id: int) -> str | None:
    return TYPE_CODE_TO_NAME.get(prop_id & 0xFFFF)


class OabReader:
    """Wraps the per-record BytesIO and exposes OAB-encoded value readers."""

    def __init__(self, buf: io.BytesIO):
        self.buf = buf

    def read_exact(self, n: int) -> bytes:
        data = self.buf.read(n)
        if len(data) != n:
            raise ValueError(f"Truncated record: needed {n} bytes, got {len(data)}")
        return data

    def remaining(self) -> bytes:
        return self.buf.read()

    def read_int(self) -> int:
        b0 = self.read_exact(1)[0]
        if b0 <= 0x7F:
            return b0
        if 0x81 <= b0 <= 0x84:
            extra = self.read_exact(b0 - 0x80)
            return int.from_bytes(extra.ljust(4, b"\x00"), "little")
        raise ValueError(f"Malformed OAB varint lead byte 0x{b0:02X}")

    def read_bool(self) -> bool:
        return self.read_exact(1)[0] != 0

    def _read_cstring(self) -> bytes:
        out = bytearray()
        while True:
            ch = self.buf.read(1)
            if not ch:
                raise ValueError("Truncated record: unterminated string")
            if ch == b"\x00":
                return bytes(out)
            out += ch

    def read_str(self) -> str:
        return self._read_cstring().decode("utf-8", errors="replace")

    def read_str8(self) -> str:
        # MS-OXOAB does not pin String8 to a codepage; latin-1 is byte-preserving.
        return self._read_cstring().decode("latin-1")

    def read_binary(self) -> bytes:
        return self.read_exact(self.read_int())


def read_property(reader: OabReader, type_name: str) -> Any:
    if type_name == PTYP_STRING:
        return reader.read_str()
    if type_name == PTYP_STRING8:
        return reader.read_str8()
    if type_name == PTYP_BOOLEAN:
        return reader.read_bool()
    if type_name == PTYP_INTEGER32:
        return reader.read_int()
    if type_name == PTYP_BINARY:
        return binascii.hexlify(reader.read_binary()).decode("ascii")
    if type_name == PTYP_MULTIPLE_STRING:
        return [reader.read_str() for _ in range(reader.read_int())]
    if type_name == PTYP_MULTIPLE_STRING8:
        return [reader.read_str8() for _ in range(reader.read_int())]
    if type_name == PTYP_MULTIPLE_INTEGER32:
        return [reader.read_int() for _ in range(reader.read_int())]
    if type_name == PTYP_MULTIPLE_BINARY:
        return [binascii.hexlify(reader.read_binary()).decode("ascii")
                for _ in range(reader.read_int())]
    raise ValueError(
        f"Property type {type_name!r} has no scalar encoding in OAB v4 details "
        "(cannot safely skip — record alignment would be lost)"
    )


def _u32(fh) -> int:
    data = fh.read(4)
    if len(data) != 4:
        raise ValueError("Truncated input: expected 4-byte little-endian uint32")
    return unpack("<I", data)[0]


def _read_sized_chunk(fh) -> bytes:
    """Read a cbSize-prefixed chunk; size is inclusive of the 4-byte size field."""
    cb_size = _u32(fh)
    if cb_size < 4:
        raise ValueError(f"Invalid chunk size {cb_size}")
    body = fh.read(cb_size - 4)
    if len(body) != cb_size - 4:
        raise ValueError(f"Truncated chunk: wanted {cb_size - 4} body bytes, got {len(body)}")
    return body


def _parse_schema_table(meta: io.BytesIO) -> list[int]:
    count = unpack("<I", meta.read(4))[0]
    prop_ids: list[int] = []
    for _ in range(count):
        pair = meta.read(8)
        if len(pair) != 8:
            raise ValueError("Truncated metadata schema table")
        prop_id, _flags = unpack("<II", pair)
        prop_ids.append(prop_id)
    return prop_ids


def parse_metadata(fh) -> tuple[list[int], list[int]]:
    meta = io.BytesIO(_read_sized_chunk(fh))
    hdr_props = _parse_schema_table(meta)
    oab_props = _parse_schema_table(meta)
    return hdr_props, oab_props


def _presence_indices(bits: bytes, count: int) -> list[int]:
    return [i for i in range(count) if (bits[i // 8] >> (7 - (i % 8))) & 1]


_unknown_propid_warned: set[str] = set()


def _warn_unknown(prop_id_hex: str, verbose_stream) -> None:
    if prop_id_hex not in _unknown_propid_warned:
        _unknown_propid_warned.add(prop_id_hex)
        print(f"oabparser: warning: unknown PropID 0x{prop_id_hex} "
              "(using inferred type from low 16 bits)", file=verbose_stream)


def parse_record(fh, prop_ids: list[int], *, strict: bool = False,
                 warn_stream=sys.stderr) -> dict:
    body = _read_sized_chunk(fh)
    chunk = io.BytesIO(body)
    bitmap_len = (len(prop_ids) + 7) // 8
    bits = chunk.read(bitmap_len)
    if len(bits) != bitmap_len:
        raise ValueError("Truncated record: presence bitmap")
    reader = OabReader(chunk)
    record: dict[str, Any] = {}
    for i in _presence_indices(bits, len(prop_ids)):
        prop_id = prop_ids[i]
        tag_hex = hexify(prop_id)
        entry = PID_TAG_SCHEMA.get(tag_hex)
        if entry is None:
            if strict:
                raise ValueError(f"Unknown PropID 0x{tag_hex} (strict mode)")
            inferred = infer_type_from_propid(prop_id)
            if inferred is None:
                raise ValueError(
                    f"Unknown PropID 0x{tag_hex} with unrecognised type code "
                    f"0x{prop_id & 0xFFFF:04X}; cannot skip safely"
                )
            _warn_unknown(tag_hex, warn_stream)
            value = read_property(reader, inferred)
            record[f"PropTag_{tag_hex}"] = value
        else:
            name, type_name = entry
            value = read_property(reader, type_name)
            if name in _GUID_BINARY_PROPS and isinstance(value, str):
                value = str(uuid.UUID(bytes_le=bytes.fromhex(value)))
            elif name == "OfflineAddressBookTruncatedProperties" and isinstance(value, list):
                value = [PID_TAG_SCHEMA.get(hexify(v), (hexify(v), None))[0] for v in value]
            record[name] = value
    leftover = reader.remaining()
    if leftover:
        raise ValueError(
            f"Record contains {len(leftover)} unexpected trailing bytes: "
            f"{leftover[:32].hex()}{'...' if len(leftover) > 32 else ''}"
        )
    return record


def parse_oab(path: str, *, strict: bool = False, warn_stream=sys.stderr):
    """Yield ('header', header_record), then ('record', rec) for each AB object."""
    with open(path, "rb") as fh:
        header_bytes = fh.read(12)
        if len(header_bytes) != 12:
            raise ValueError("File too small to contain OAB header")
        version, serial, tot_recs = unpack("<III", header_bytes)
        if version != OAB_V4_VERSION:
            raise ValueError(
                f"Unsupported OAB version 0x{version:X} (this parser handles v4 = 0x20). "
                "Input must be the uncompressed udetails.oab; LZX-compressed OAB files are "
                "out of scope."
            )
        hdr_props, oab_props = parse_metadata(fh)
        yield "meta", {
            "version": version,
            "serial": serial,
            "tot_recs": tot_recs,
            "hdr_props_count": len(hdr_props),
            "oab_props_count": len(oab_props),
        }
        header_rec = parse_record(fh, hdr_props, strict=strict, warn_stream=warn_stream)
        yield "header", header_rec
        for _ in range(tot_recs):
            yield "record", parse_record(fh, oab_props, strict=strict, warn_stream=warn_stream)
        # Anything after the last record is unexpected for a well-formed file
        tail = fh.read()
        if tail:
            print(f"oabparser: warning: {len(tail)} unexpected trailing bytes after "
                  "last record", file=warn_stream)


_CSV_SUPPORTED_TYPES = {
    PTYP_STRING, PTYP_STRING8, PTYP_BOOLEAN, PTYP_INTEGER32, PTYP_BINARY,
    PTYP_MULTIPLE_STRING, PTYP_MULTIPLE_STRING8, PTYP_MULTIPLE_INTEGER32,
    PTYP_MULTIPLE_BINARY,
}

_PRESET_MINIMAL = [
    "DisplayName",
    "SmtpAddress",
    "BusinessTelephoneNumber",
    "MobileTelephoneNumber",
    "Title",
]

_PRESET_CONTACT = [
    "SmtpAddress",
    "DisplayName",
    "Account",
    "GivenName",
    "Surname",
    "Title",
    "CompanyName",
    "DepartmentName",
    "OfficeLocation",
    "BusinessTelephoneNumber",
    "MobileTelephoneNumber",
    "HomeTelephoneNumber",
    "StreetAddress",
    "Locality",
    "StateOrProvince",
    "PostalCode",
    "Country",
    "AddressBookProxyAddresses",
    "AddressBookTargetAddress",
    "EmailAddress",
]


def _build_full_preset() -> list[str]:
    """Every named, CSV-serialisable property in PID_TAG_SCHEMA, contact columns first."""
    seen: set[str] = set()
    ordered: list[str] = []
    for col in _PRESET_CONTACT:
        if col not in seen:
            seen.add(col)
            ordered.append(col)
    for name, type_name in PID_TAG_SCHEMA.values():
        if type_name in _CSV_SUPPORTED_TYPES and name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered


PRESETS: dict[str, list[str]] = {
    "minimal": _PRESET_MINIMAL,
    "contact": _PRESET_CONTACT,
    "full": _build_full_preset(),
}


class ProgressBar:
    """Tiny stderr progress bar with 50 ms redraw throttle. No-op when disabled."""

    _BAR_WIDTH = 30
    _MIN_INTERVAL = 0.05

    def __init__(self, total: int, *, stream=sys.stderr, enabled: bool = True,
                 label: str = "Parsing"):
        self.total = max(total, 0)
        self.stream = stream
        self.enabled = enabled and total > 0
        self.label = label
        self.done = 0
        self._start = time.monotonic()
        self._last_draw = 0.0
        self._closed = False
        if self.enabled:
            self._draw(force=True)

    def tick(self, n: int = 1) -> None:
        if not self.enabled:
            return
        self.done += n
        now = time.monotonic()
        if self.done >= self.total or (now - self._last_draw) >= self._MIN_INTERVAL:
            self._draw(force=False, now=now)

    def _draw(self, *, force: bool, now: Optional[float] = None) -> None:
        if now is None:
            now = time.monotonic()
        self._last_draw = now
        done = min(self.done, self.total)
        frac = done / self.total if self.total else 1.0
        filled = int(round(frac * self._BAR_WIDTH))
        bar = "█" * filled + "░" * (self._BAR_WIDTH - filled)
        elapsed = max(now - self._start, 1e-6)
        eta = elapsed * (self.total - done) / done if done else 0.0
        msg = (f"\r{self.label} [{bar}] {done}/{self.total} "
               f"({frac * 100:5.1f}%)  eta {eta:5.1f}s")
        try:
            self.stream.write(msg)
            self.stream.flush()
        except Exception:
            self.enabled = False

    def close(self) -> None:
        if self._closed or not self.enabled:
            self._closed = True
            return
        self._draw(force=True)
        elapsed = time.monotonic() - self._start
        try:
            self.stream.write(f"\n{self.label}: {self.done} records in {elapsed:.2f}s\n")
            self.stream.flush()
        except Exception:
            pass
        self._closed = True

    def __enter__(self) -> "ProgressBar":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _flatten_for_csv(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return "; ".join(_flatten_for_csv(v) for v in value)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def emit_ndjson(records: Iterator[dict], fh,
                progress: Optional[Callable[[], None]] = None) -> int:
    n = 0
    for rec in records:
        fh.write(json.dumps(rec, ensure_ascii=False))
        fh.write("\n")
        n += 1
        if progress is not None:
            progress()
    return n


def emit_csv(records: Iterator[dict], fh, columns: list[str],
             progress: Optional[Callable[[], None]] = None) -> int:
    writer = csv.writer(fh, lineterminator="\n")
    writer.writerow(columns)
    n = 0
    for rec in records:
        writer.writerow([_flatten_for_csv(rec.get(col)) for col in columns])
        n += 1
        if progress is not None:
            progress()
    return n


def _format_serial(serial: int) -> str:
    return f"0x{serial:08X}"


def _stats_summary(meta: dict, header_rec: dict) -> str:
    lines = [
        f"OAB v{meta['version']:#04x} (Full Details)",
        f"  serial:     {_format_serial(meta['serial'])} ({meta['serial']})",
        f"  records:    {meta['tot_recs']}",
        f"  hdr_props:  {meta['hdr_props_count']}",
        f"  oab_props:  {meta['oab_props_count']}",
    ]
    for key in ("OfflineAddressBookName", "OfflineAddressBookDistinguishedName",
                "OfflineAddressBookContainerGuid", "OfflineAddressBookSequence"):
        if key in header_rec:
            lines.append(f"  {key}: {header_rec[key]}")
    return "\n".join(lines)


def _collect_meta_and_header(stream):
    meta = None
    header = None
    for kind, payload in stream:
        if kind == "meta":
            meta = payload
        elif kind == "header":
            header = payload
            break
    return meta, header


def _print_presets(stream=sys.stdout) -> None:
    for name in ("minimal", "contact", "full"):
        cols = PRESETS[name]
        print(f"{name} ({len(cols)} columns):", file=stream)
        for c in cols:
            print(f"  {c}", file=stream)
        print(file=stream)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="oabparser",
        description="Parse an uncompressed OAB v4 Full Details file (udetails.oab).",
    )
    p.add_argument("input", nargs="?",
                   help="Path to udetails.oab (omit with --list-presets)")
    p.add_argument("-f", "--format", choices=("ndjson", "csv"), default="ndjson",
                   help="Output format (default: ndjson)")
    p.add_argument("-o", "--output", help="Output path (default: stdout)")
    p.add_argument("--preset", choices=("minimal", "contact", "full"),
                   help="CSV column preset (default: contact). Ignored if --columns is given.")
    p.add_argument("--columns",
                   help="Ad-hoc comma-separated CSV column list (overrides --preset)")
    p.add_argument("--list-presets", action="store_true",
                   help="Print built-in CSV presets and exit")
    p.add_argument("--include-header", action="store_true",
                   help="Also emit the OAB header record as the first row")
    p.add_argument("--strict", action="store_true",
                   help="Fail on unknown PropIDs instead of warning + inferring type")
    p.add_argument("--stats", action="store_true",
                   help="Print header summary and exit without dumping records")
    p.add_argument("--no-progress", action="store_true",
                   help="Suppress the progress bar")
    p.add_argument("--no-banner", action="store_true",
                   help="Suppress the startup banner")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Print final write-count summary to stderr")
    args = p.parse_args(argv)

    if not args.no_banner:
        print_banner(sys.stderr)

    if args.list_presets:
        _print_presets()
        return 0

    if not args.input:
        p.error("the following arguments are required: input")

    warn_stream = sys.stderr

    if args.stats:
        stream = parse_oab(args.input, strict=args.strict, warn_stream=warn_stream)
        meta, header_rec = _collect_meta_and_header(stream)
        print(_stats_summary(meta, header_rec or {}))
        return 0

    if args.output:
        out = open(args.output, "w", encoding="utf-8", newline="")
    else:
        out = sys.stdout

    bar: Optional[ProgressBar] = None
    try:
        stream = parse_oab(args.input, strict=args.strict, warn_stream=warn_stream)
        meta_kind, meta = next(stream)
        if meta_kind != "meta":
            raise ValueError(f"Expected meta event first, got {meta_kind!r}")
        header_kind, header_rec = next(stream)
        if header_kind != "header":
            raise ValueError(f"Expected header event after meta, got {header_kind!r}")

        def records_iter():
            if args.include_header:
                yield {"_kind": "header", **header_rec}
            for kind, payload in stream:
                if kind == "record":
                    yield payload

        bar_total = meta["tot_recs"] + (1 if args.include_header else 0)
        bar = ProgressBar(bar_total, enabled=not args.no_progress)

        if args.format == "ndjson":
            n = emit_ndjson(records_iter(), out, progress=bar.tick)
        else:
            if args.columns:
                columns = [c.strip() for c in args.columns.split(",") if c.strip()]
            else:
                columns = PRESETS[args.preset or "contact"]
            n = emit_csv(records_iter(), out, columns, progress=bar.tick)
    finally:
        if bar is not None:
            bar.close()
        if args.output:
            out.close()

    if args.verbose:
        print(f"oabparser: wrote {n} records", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
