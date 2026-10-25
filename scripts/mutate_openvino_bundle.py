#!/usr/bin/env python3
"""Deterministically mutate paired OpenVINO IR model.xml/model.bin FZB1 inputs."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import xml.etree.ElementTree as ET
from typing import Any, Callable, NoReturn


SCHEMA_VERSION = "openvino-ir-mutation-v1"
OPERATORS = (
    "constant_layout",
    "shape_dtype",
    "graph_edge_port",
    "operation_attribute",
    "node_identity",
    "ir_metadata",
)
MODES = ("valid", "boundary", "mixed")
FIELDS = {
    "constant_layout": "constant.offset_size",
    "shape_dtype": "graph.shape_dtype",
    "graph_edge_port": "graph.edge_port",
    "operation_attribute": "operation.attribute",
    "node_identity": "node.name_id",
    "ir_metadata": "ir.metadata",
}
SUPPORTED_IR_VERSIONS = {"10", "11"}
DTYPE_WIDTH = {
    "boolean": 1,
    "bf16": 2,
    "f16": 2,
    "f32": 4,
    "f64": 8,
    "i8": 1,
    "i16": 2,
    "i32": 4,
    "i64": 8,
    "u8": 1,
    "u16": 2,
    "u32": 4,
    "u64": 8,
}


class MutationError(RuntimeError):
    """An input or candidate violates the OVI-04 mutation contract."""


class InapplicableError(MutationError):
    """The selected operator has no applicable structure in this input."""


def fail(message: str) -> NoReturn:
    raise MutationError(message)


def inapplicable(message: str) -> NoReturn:
    raise InapplicableError(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def import_bundle_codec() -> Any:
    path = Path(__file__).resolve().with_name("model_bundle.py")
    if not path.is_file() or path.is_symlink():
        fail(f"FZB1 codec is unavailable: {path}")
    specification = importlib.util.spec_from_file_location("openvino_mutation_bundle", path)
    if specification is None or specification.loader is None:
        fail(f"cannot import FZB1 codec: {path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules["openvino_mutation_bundle"] = module
    specification.loader.exec_module(module)
    return module


def require_regular(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        fail(f"{label} is unavailable: {path}: {error}")
    if not path.is_file() or path.is_symlink() or metadata.st_size < 0:
        fail(f"{label} must be a regular non-symlink file: {path}")


def read_input(path: Path, maximum: int) -> bytes:
    require_regular(path, "input bundle")
    if path.stat().st_size > maximum:
        fail(f"input bundle exceeds {maximum} bytes")
    try:
        value = path.read_bytes()
    except OSError as error:
        fail(f"cannot read input bundle {path}: {error}")
    if not value:
        fail("input bundle is empty")
    return value


def entry_map(codec: Any, blob: bytes) -> dict[str, bytes]:
    try:
        decoded = codec.decode_bundle(blob)
        codec.require_allowlist(decoded, ("model.bin", "model.xml"))
    except (ValueError, UnicodeError) as error:
        fail(f"invalid OpenVINO FZB1 pair: {error}")
    return dict(decoded)


def parse_xml(value: bytes) -> ET.Element:
    try:
        root = ET.fromstring(value)
    except ET.ParseError as error:
        fail(f"model.xml is not well-formed: {error}")
    if root.tag != "net" or root.find("./layers") is None or root.find("./edges") is None:
        fail("model.xml is not an OpenVINO IR net with layers and edges")
    return root


def serialize_xml(root: ET.Element) -> bytes:
    ET.indent(root, space="    ")
    return ET.tostring(root, encoding="utf-8", short_empty_elements=True) + b"\n"


def layers(root: ET.Element) -> list[ET.Element]:
    return root.findall("./layers/layer")


def constant_rows(root: ET.Element) -> list[tuple[ET.Element, ET.Element]]:
    result: list[tuple[ET.Element, ET.Element]] = []
    for layer in layers(root):
        if layer.get("type") not in ("Const", "Constant"):
            continue
        data = layer.find("./data")
        if data is None:
            fail(f"Constant layer {layer.get('id')!r} has no data element")
        result.append((layer, data))
    return result


def parse_uint(value: str | None, label: str) -> int:
    if value is None or not value.isascii() or not value.isdecimal():
        fail(f"{label} is not an unsigned decimal integer")
    return int(value, 10)


def parse_shape(value: str | None) -> list[int]:
    if value is None or value == "":
        fail("Constant shape is missing")
    result: list[int] = []
    for item in value.split(","):
        number = parse_uint(item.strip(), "Constant shape dimension")
        result.append(number)
    return result


def element_count(shape: list[int]) -> int:
    count = 1
    for dimension in shape:
        count *= dimension
        if count > 1_048_576:
            fail("Constant shape exceeds the OVI-04 validation limit")
    return count


def constant_range(data: ET.Element, binary: bytes) -> tuple[int, int]:
    offset = parse_uint(data.get("offset"), "Constant offset")
    size = parse_uint(data.get("size"), "Constant size")
    end = offset + size
    if end > len(binary):
        fail(
            f"Constant range exceeds model.bin: offset={offset} size={size} bytes={len(binary)}"
        )
    return offset, size


def first_constant_payload(root: ET.Element, binary: bytes) -> bytes:
    constants = constant_rows(root)
    if not constants:
        inapplicable("input has no Constant layer")
    _, data = constants[0]
    offset, size = constant_range(data, binary)
    if size == 0:
        inapplicable("input Constant payload is empty")
    return binary[offset : offset + size]


def mutate_payload_same_size(
    root: ET.Element, binary: bytes, operator: str, seed: int
) -> tuple[bytes, str, str]:
    constants = constant_rows(root)
    if not constants:
        inapplicable("input has no Constant layer")
    _, data = constants[0]
    offset, size = constant_range(data, binary)
    if size == 0:
        inapplicable("input Constant payload is empty")
    before = binary[offset : offset + size]
    digest = hashlib.sha256(f"{operator}:{seed}".encode("ascii")).digest()
    index = digest[0] % min(size, 2)
    mask = 1 << (digest[1] % 7)
    output = bytearray(binary)
    output[offset + index] ^= mask
    after = bytes(output[offset : offset + size])
    if before == after:
        fail("Constant payload mutation was a no-op")
    return bytes(output), before.hex(), after.hex()


def evidence(field: str, before: str, after: str, fixups: list[str]) -> dict[str, Any]:
    return {"field": field, "before": before, "after": after, "fixups": fixups}


def mutate_constant_layout(
    entries: dict[str, bytes], mode: str, seed: int
) -> tuple[dict[str, bytes], dict[str, Any]]:
    root = parse_xml(entries["model.xml"])
    constants = constant_rows(root)
    if not constants:
        inapplicable("constant_layout requires a Constant layer")
    for _, data in constants:
        constant_range(data, entries["model.bin"])
    selected_data = constants[0][1]
    old_offset = parse_uint(selected_data.get("offset"), "Constant offset")
    old_size = parse_uint(selected_data.get("size"), "Constant size")
    old_payload = entries["model.bin"][old_offset : old_offset + old_size]
    if not old_payload:
        inapplicable("constant_layout requires a non-empty Constant payload")
    if mode == "boundary":
        selected_data.set("size", str(old_size + 1))
        truncated = entries["model.bin"][:-1]
        if truncated == entries["model.bin"]:
            inapplicable("constant_layout cannot truncate an empty model.bin")
        return (
            {"model.xml": serialize_xml(root), "model.bin": truncated},
            evidence(
                FIELDS["constant_layout"],
                f"offset={old_offset};size={old_size};bin_bytes={len(entries['model.bin'])}",
                f"offset={old_offset};size={old_size + 1};bin_bytes={len(truncated)}",
                ["mutate XML Constant size", "intentionally omit BIN extent fixup"],
            ),
        )

    if len(constants) != 1:
        inapplicable("constant_layout valid mode requires exactly one Constant layer")
    dtype = selected_data.get("element_type")
    shape = parse_shape(selected_data.get("shape"))
    if dtype not in DTYPE_WIDTH or shape != [1] or old_size != DTYPE_WIDTH[str(dtype)]:
        inapplicable("constant_layout valid mode requires one rank-one scalar Constant")
    for layer in layers(root):
        data = layer.find("./data")
        if data is not None and data.get("shape") is not None:
            if parse_shape(data.get("shape")) != [1]:
                inapplicable("constant_layout valid mode requires rank-one scalar layer shapes")
            data.set("shape", "2")
        for port in layer.findall("./input/port") + layer.findall("./output/port"):
            dimensions = port.findall("./dim")
            if len(dimensions) != 1 or (dimensions[0].text or "").strip() != "1":
                inapplicable("constant_layout valid mode requires rank-one scalar ports")
            dimensions[0].text = "2"
    new_size = old_size * 2
    selected_data.set("size", str(new_size))
    padding_size = 4 * (1 + seed % 2)
    padding = hashlib.sha256(f"padding:{seed}".encode("ascii")).digest()[:padding_size]
    binary = padding + entries["model.bin"]
    for _, data in constants:
        offset = parse_uint(data.get("offset"), "Constant offset")
        data.set("offset", str(offset + padding_size))
    new_offset = old_offset + padding_size
    second_element = bytearray(old_payload)
    mask = 1 << (seed % 7)
    second_element[0] ^= mask
    new_payload = old_payload + bytes(second_element)
    binary = binary[:new_offset] + new_payload + binary[new_offset + old_size :]
    return (
        {"model.xml": serialize_xml(root), "model.bin": binary},
        evidence(
            FIELDS["constant_layout"],
            f"offset={old_offset};size={old_size};bin_bytes={len(entries['model.bin'])};payload={old_payload.hex()}",
            f"offset={new_offset};size={new_size};bin_bytes={len(binary)};payload={new_payload.hex()}",
            ["prepend deterministic BIN padding", "regenerate every Constant offset", "resize Constant payload and XML size", "rewrite connected rank-one shapes"],
        ),
    )


def rewrite_shape_dtype(root: ET.Element) -> None:
    for layer in layers(root):
        data = layer.find("./data")
        if data is not None and data.get("element_type") is not None:
            data.set("element_type", "i32")
            data.set("shape", "2")
        for port in layer.findall("./input/port") + layer.findall("./output/port"):
            port.set("precision", "I32")
            dimensions = port.findall("./dim")
            if len(dimensions) != 1:
                inapplicable("shape_dtype currently requires rank-one IR ports")
            dimensions[0].text = "2"


def mutate_shape_dtype(
    entries: dict[str, bytes], mode: str, seed: int
) -> tuple[dict[str, bytes], dict[str, Any]]:
    root = parse_xml(entries["model.xml"])
    constants = constant_rows(root)
    if len(constants) != 1:
        inapplicable("shape_dtype requires exactly one Constant layer")
    _, data = constants[0]
    offset, size = constant_range(data, entries["model.bin"])
    if data.get("element_type") != "f32" or parse_shape(data.get("shape")) != [1] or size != 4:
        inapplicable("shape_dtype requires a rank-one f32 Constant with one element")
    rewrite_shape_dtype(root)
    data.set("size", "8")
    before_payload = entries["model.bin"][offset : offset + size]
    if mode == "boundary":
        return (
            {"model.xml": serialize_xml(root), "model.bin": entries["model.bin"]},
            evidence(
                FIELDS["shape_dtype"],
                f"dtype=f32;shape=1;size=4;payload={before_payload.hex()}",
                f"dtype=i32;shape=2;size=8;payload_bytes={len(before_payload)}",
                ["rewrite graph dtype and dimensions", "intentionally omit BIN resize"],
            ),
        )
    first = 1 + int(seed % 1_000_000)
    second = -first
    new_payload = struct.pack("<ii", first, second)
    binary = entries["model.bin"][:offset] + new_payload + entries["model.bin"][offset + size :]
    return (
        {"model.xml": serialize_xml(root), "model.bin": binary},
        evidence(
            FIELDS["shape_dtype"],
            f"dtype=f32;shape=1;size=4;payload={before_payload.hex()}",
            f"dtype=i32;shape=2;size=8;payload={new_payload.hex()}",
            ["rewrite every typed layer", "rewrite every port precision/dimension", "resize Constant payload and XML size"],
        ),
    )


def mutate_graph_edge_port(
    entries: dict[str, bytes], mode: str, seed: int
) -> tuple[dict[str, bytes], dict[str, Any]]:
    root = parse_xml(entries["model.xml"])
    edges = root.findall("./edges/edge")
    if not edges:
        inapplicable("graph_edge_port requires at least one edge")
    if mode == "boundary":
        before = edges[0].get("to-port")
        edges[0].set("to-port", "999999")
        return (
            {"model.xml": serialize_xml(root), "model.bin": entries["model.bin"]},
            evidence(
                FIELDS["graph_edge_port"],
                f"first_to_port={before}",
                "first_to_port=999999",
                ["intentionally leave edge pointing at a missing input port"],
            ),
        )

    delta = 10 + seed % 17
    input_map: dict[tuple[str, str], str] = {}
    output_map: dict[tuple[str, str], str] = {}
    changed = 0
    for layer in layers(root):
        layer_id = layer.get("id")
        if layer_id is None:
            fail("layer id is missing")
        for kind, destination in (("input", input_map), ("output", output_map)):
            for port in layer.findall(f"./{kind}/port"):
                old = port.get("id")
                if old is None:
                    fail(f"{kind} port id is missing")
                new = str(parse_uint(old, f"{kind} port id") + delta)
                destination[(layer_id, old)] = new
                port.set("id", new)
                changed += 1
    for edge in edges:
        source_key = (str(edge.get("from-layer")), str(edge.get("from-port")))
        target_key = (str(edge.get("to-layer")), str(edge.get("to-port")))
        if source_key not in output_map or target_key not in input_map:
            fail("source graph already has an unresolved edge/port reference")
        edge.set("from-port", output_map[source_key])
        edge.set("to-port", input_map[target_key])
    binary, payload_before, payload_after = mutate_payload_same_size(
        root, entries["model.bin"], "graph_edge_port", seed
    )
    return (
        {"model.xml": serialize_xml(root), "model.bin": binary},
        evidence(
            FIELDS["graph_edge_port"],
            f"ports={changed};delta=0;payload={payload_before}",
            f"ports={changed};delta={delta};payload={payload_after}",
            ["renumber every input/output port", "rewrite every edge endpoint", "mutate paired Constant payload"],
        ),
    )


def mutate_operation_attribute(
    entries: dict[str, bytes], mode: str, seed: int
) -> tuple[dict[str, bytes], dict[str, Any]]:
    root = parse_xml(entries["model.xml"])
    candidates: list[ET.Element] = []
    for layer in layers(root):
        if layer.get("type") == "Add":
            data = layer.find("./data")
            if data is not None and data.get("auto_broadcast") is not None:
                candidates.append(data)
    if not candidates:
        inapplicable("operation_attribute requires Add auto_broadcast metadata")
    selected = candidates[seed % len(candidates)]
    before = str(selected.get("auto_broadcast"))
    if mode == "boundary":
        after = "invalid_mode"
        selected.set("auto_broadcast", after)
        return (
            {"model.xml": serialize_xml(root), "model.bin": entries["model.bin"]},
            evidence(
                FIELDS["operation_attribute"],
                f"auto_broadcast={before}",
                f"auto_broadcast={after}",
                ["intentionally select a value outside the opset schema"],
            ),
        )
    after = "none" if before != "none" else "numpy"
    selected.set("auto_broadcast", after)
    binary, payload_before, payload_after = mutate_payload_same_size(
        root, entries["model.bin"], "operation_attribute", seed
    )
    return (
        {"model.xml": serialize_xml(root), "model.bin": binary},
        evidence(
            FIELDS["operation_attribute"],
            f"auto_broadcast={before};payload={payload_before}",
            f"auto_broadcast={after};payload={payload_after}",
            ["select a supported opset attribute", "preserve equal input shapes", "mutate paired Constant payload"],
        ),
    )


def mutate_node_identity(
    entries: dict[str, bytes], mode: str, seed: int
) -> tuple[dict[str, bytes], dict[str, Any]]:
    root = parse_xml(entries["model.xml"])
    nodes = layers(root)
    if not nodes:
        inapplicable("node_identity requires at least one layer")
    if mode == "boundary":
        old = nodes[0].get("id")
        nodes[0].set("id", "999999")
        return (
            {"model.xml": serialize_xml(root), "model.bin": entries["model.bin"]},
            evidence(
                FIELDS["node_identity"],
                f"first_id={old}",
                "first_id=999999;edges=stale",
                ["intentionally omit graph edge ID fixups"],
            ),
        )
    delta = 100 + seed % 101
    suffix = f"_m{seed % 10007}"
    id_map: dict[str, str] = {}
    old_names: list[str] = []
    new_names: list[str] = []
    for node in nodes:
        old_id = node.get("id")
        old_name = node.get("name")
        if old_id is None or old_name is None:
            fail("node_identity requires every layer to have an id and name")
        new_id = str(parse_uint(old_id, "layer id") + delta)
        new_name = old_name + suffix
        id_map[old_id] = new_id
        node.set("id", new_id)
        node.set("name", new_name)
        old_names.append(old_name)
        new_names.append(new_name)
    for edge in root.findall("./edges/edge"):
        for attribute in ("from-layer", "to-layer"):
            old_id = edge.get(attribute)
            if old_id not in id_map:
                fail("source graph already has an unresolved layer reference")
            edge.set(attribute, id_map[str(old_id)])
    binary, payload_before, payload_after = mutate_payload_same_size(
        root, entries["model.bin"], "node_identity", seed
    )
    return (
        {"model.xml": serialize_xml(root), "model.bin": binary},
        evidence(
            FIELDS["node_identity"],
            f"ids={','.join(sorted(id_map))};names={','.join(old_names)};payload={payload_before}",
            f"ids={','.join(sorted(id_map.values()))};names={','.join(new_names)};payload={payload_after}",
            ["rename every layer", "renumber every layer", "rewrite every edge layer reference", "mutate paired Constant payload"],
        ),
    )


def mutate_ir_metadata(
    entries: dict[str, bytes], mode: str, seed: int
) -> tuple[dict[str, bytes], dict[str, Any]]:
    root = parse_xml(entries["model.xml"])
    before_name = root.get("name")
    before_version = root.get("version")
    if before_name is None or before_version is None:
        inapplicable("ir_metadata requires net name and version")
    if mode == "boundary":
        root.set("version", "999")
        return (
            {"model.xml": serialize_xml(root), "model.bin": entries["model.bin"]},
            evidence(
                FIELDS["ir_metadata"],
                f"name={before_name};version={before_version}",
                f"name={before_name};version=999",
                ["intentionally select an unsupported IR version"],
            ),
        )
    after_version = "10" if before_version != "10" else "11"
    after_name = f"{before_name}-m{seed % 10007}"
    root.set("name", after_name)
    root.set("version", after_version)
    binary, payload_before, payload_after = mutate_payload_same_size(
        root, entries["model.bin"], "ir_metadata", seed
    )
    return (
        {"model.xml": serialize_xml(root), "model.bin": binary},
        evidence(
            FIELDS["ir_metadata"],
            f"name={before_name};version={before_version};payload={payload_before}",
            f"name={after_name};version={after_version};payload={payload_after}",
            ["reserialize within the supported IR versions", "rename the net", "mutate paired Constant payload"],
        ),
    )


MUTATORS: dict[
    str, Callable[[dict[str, bytes], str, int], tuple[dict[str, bytes], dict[str, Any]]]
] = {
    "constant_layout": mutate_constant_layout,
    "shape_dtype": mutate_shape_dtype,
    "graph_edge_port": mutate_graph_edge_port,
    "operation_attribute": mutate_operation_attribute,
    "node_identity": mutate_node_identity,
    "ir_metadata": mutate_ir_metadata,
}


def validate_graph(root: ET.Element) -> None:
    rows = layers(root)
    ids = [layer.get("id") for layer in rows]
    if any(value is None for value in ids) or len(set(ids)) != len(ids):
        fail("valid candidate has missing or duplicate layer IDs")
    names = [layer.get("name") for layer in rows]
    if any(value is None for value in names) or len(set(names)) != len(names):
        fail("valid candidate has missing or duplicate layer names")
    by_id = {str(layer.get("id")): layer for layer in rows}
    for edge in root.findall("./edges/edge"):
        source = by_id.get(str(edge.get("from-layer")))
        target = by_id.get(str(edge.get("to-layer")))
        if source is None or target is None:
            fail("valid candidate has an unresolved edge layer reference")
        source_ports = {port.get("id") for port in source.findall("./output/port")}
        target_ports = {port.get("id") for port in target.findall("./input/port")}
        if edge.get("from-port") not in source_ports:
            fail("valid candidate has an unresolved edge output port")
        if edge.get("to-port") not in target_ports:
            fail("valid candidate has an unresolved edge input port")


def validate_constants(root: ET.Element, binary: bytes) -> None:
    for layer, data in constant_rows(root):
        offset, size = constant_range(data, binary)
        dtype = data.get("element_type")
        if dtype not in DTYPE_WIDTH:
            fail(f"valid Constant {layer.get('id')!r} has an unsupported dtype: {dtype!r}")
        expected = element_count(parse_shape(data.get("shape"))) * DTYPE_WIDTH[str(dtype)]
        if size != expected:
            fail(
                f"valid Constant {layer.get('id')!r} size {size} does not match dtype/shape bytes {expected}"
            )
        if offset + size > len(binary):
            fail(f"valid Constant {layer.get('id')!r} exceeds model.bin")


def validate_attributes(root: ET.Element) -> None:
    for layer in layers(root):
        if layer.get("type") != "Add":
            continue
        data = layer.find("./data")
        if data is not None and data.get("auto_broadcast") not in (None, "none", "numpy", "explicit"):
            fail("valid Add auto_broadcast is outside the supported opset schema")


def validate_candidate(
    source: dict[str, bytes],
    candidate: dict[str, bytes],
    operator: str,
    effective_mode: str,
    operator_evidence: dict[str, Any],
) -> None:
    if set(source) != {"model.bin", "model.xml"} or set(candidate) != set(source):
        fail("candidate does not preserve the exact model.xml/model.bin pair")
    if candidate == source:
        fail("mutation is a no-op")
    before = operator_evidence.get("before")
    after = operator_evidence.get("after")
    fixups = operator_evidence.get("fixups")
    if not isinstance(before, str) or not before or not isinstance(after, str) or not after:
        fail("operator evidence has no before/after state")
    if before == after:
        fail("operator evidence records a no-op")
    if not isinstance(fixups, list) or not fixups or not all(isinstance(row, str) for row in fixups):
        fail("operator evidence has no fixup list")
    if effective_mode != "valid":
        return
    if candidate["model.xml"] == source["model.xml"]:
        fail("valid mutation did not update model.xml")
    if candidate["model.bin"] == source["model.bin"]:
        fail("valid mutation did not update model.bin")
    root = parse_xml(candidate["model.xml"])
    if root.get("version") not in SUPPORTED_IR_VERSIONS:
        fail("valid mutation selected an unsupported IR version")
    validate_graph(root)
    validate_constants(root, candidate["model.bin"])
    validate_attributes(root)
    source_root = parse_xml(source["model.xml"])
    if first_constant_payload(root, candidate["model.bin"]) == first_constant_payload(
        source_root, source["model.bin"]
    ):
        fail("valid mutation did not change the paired Constant payload")
    if operator == "operation_attribute":
        attributes = [
            data.get("auto_broadcast")
            for data in root.findall("./layers/layer[@type='Add']/data")
        ]
        if not attributes:
            fail("operation_attribute removed its applicable field")


def effective_mode(operator: str, requested: str, seed: int) -> str:
    if requested != "mixed":
        return requested
    selector = hashlib.sha256(f"mixed:{operator}:{seed}".encode("ascii")).digest()[0]
    return "valid" if selector % 2 == 0 else "boundary"


def manifest_for(
    source_blob: bytes,
    output_blob: bytes,
    source: dict[str, bytes],
    candidate: dict[str, bytes],
    operator: str,
    requested_mode: str,
    selected_mode: str,
    seed: int,
    operator_evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "bundle_format": "FZB1",
        "effective_mode": selected_mode,
        "entries": {
            name: {
                "after_sha256": sha256_bytes(candidate[name]),
                "after_size": len(candidate[name]),
                "before_sha256": sha256_bytes(source[name]),
                "before_size": len(source[name]),
                "changed": candidate[name] != source[name],
            }
            for name in ("model.bin", "model.xml")
        },
        "evidence": operator_evidence,
        "expected_loader": "accept" if selected_mode == "valid" else "reject",
        "operator": operator,
        "output_sha256": sha256_bytes(output_blob),
        "requested_mode": requested_mode,
        "schema_version": SCHEMA_VERSION,
        "seed": seed,
        "source_sha256": sha256_bytes(source_blob),
        "target": "openvino-ir",
    }


def mutate_bundle(
    codec: Any, source_blob: bytes, operator: str, requested_mode: str, seed: int
) -> tuple[bytes, dict[str, Any]]:
    source = entry_map(codec, source_blob)
    parse_xml(source["model.xml"])
    selected_mode = effective_mode(operator, requested_mode, seed)
    candidate, operator_evidence = MUTATORS[operator](source, selected_mode, seed)
    validate_candidate(source, candidate, operator, selected_mode, operator_evidence)
    try:
        output_blob = codec.encode_bundle(candidate.items())
    except (ValueError, UnicodeError) as error:
        fail(f"cannot encode mutated FZB1 pair: {error}")
    if output_blob == source_blob:
        fail("encoded FZB1 mutation is a no-op")
    manifest = manifest_for(
        source_blob,
        output_blob,
        source,
        candidate,
        operator,
        requested_mode,
        selected_mode,
        seed,
        operator_evidence,
    )
    return output_blob, manifest


def write_new(path: Path, value: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        fail(f"cannot create fresh output {path}: {error}")
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                fail(f"short write to {path}")
            view = view[written:]
        os.fsync(descriptor)
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)


def publish(output: Path, output_blob: bytes, manifest: dict[str, Any]) -> Path:
    manifest_path = output.with_name(output.name + ".manifest.json")
    if output.exists() or output.is_symlink() or manifest_path.exists() or manifest_path.is_symlink():
        fail("output bundle and manifest paths must both be fresh")
    manifest_bytes = (
        json.dumps(manifest, indent=2, sort_keys=True, separators=(",", ": ")) + "\n"
    ).encode("utf-8")
    write_new(output, output_blob)
    try:
        write_new(manifest_path, manifest_bytes)
    except Exception:
        try:
            output.unlink()
        except OSError:
            pass
        raise
    return manifest_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--operator", required=True, choices=OPERATORS)
    parser.add_argument("--mode", required=True, choices=MODES)
    parser.add_argument("--seed", required=True, type=int)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.seed < 0 or args.seed > (1 << 64) - 1:
        print("OPENVINO_MUTATION_FAIL seed must be in 0..=2^64-1", file=sys.stderr)
        return 2
    try:
        codec = import_bundle_codec()
        source_blob = read_input(args.input, codec.MAX_BUNDLE_BYTES)
        output_blob, manifest = mutate_bundle(
            codec, source_blob, args.operator, args.mode, args.seed
        )
        manifest_path = publish(args.output, output_blob, manifest)
    except InapplicableError as error:
        print(
            f"OPENVINO_MUTATION_INAPPLICABLE operator={args.operator} reason={error}",
            file=sys.stderr,
        )
        return 3
    except (MutationError, OSError, UnicodeError, ValueError) as error:
        print(f"OPENVINO_MUTATION_FAIL {error}", file=sys.stderr)
        return 1
    print(
        f"OPENVINO_MUTATION_OK operator={args.operator} requested_mode={args.mode} "
        f"effective_mode={manifest['effective_mode']} expected_loader={manifest['expected_loader']} "
        f"output_sha256={manifest['output_sha256']} manifest={manifest_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
