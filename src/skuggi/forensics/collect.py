"""The deterministic collect phase: run the analyzer battery over the evidence.

Unlike the OSINT/research loops (an adaptive, LLM-planned source DAG), forensic
collection is exhaustive and in-process: every evidence file is hashed (the
acquisition record), classified, and run through the fitting pure-Python analyzers.
Every file acquisition is a ``record_evidence`` row and every analyzer run a
``record_procedure`` row in the case ledger -- the chain of custody -- and each
file's observations are written as a confined, redacted JSON artifact. No binary is
executed and no evidence file is written; the battery only reads.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterator
from pathlib import Path

from skuggi import __version__ as skuggi_version
from skuggi.agent import vision
from skuggi.forensics.analyzers import (
    Observation,
    encoding,
    entropy,
    executable,
    fuzzyhash,
    hashes,
    hexview,
    logparse,
    magic,
    ocr,
    strings,
)
from skuggi.forensics.analyzers.base import sha256_of
from skuggi.forensics.deps import ForensicsDeps
from skuggi.intel import store as intel_store
from skuggi.intel.schema import IntelItem, IntelResult
from skuggi.security.policy import RedactionPolicy
from skuggi.security.tripwire import scrub


def _evidence_files(root: Path, max_files: int) -> list[Path]:
    """Every regular file under the case evidence dir, sorted, capped at `max_files`."""
    if not root.is_dir():
        return []
    files = sorted(p for p in root.rglob("*") if p.is_file())
    return files[:max_files]


def _media_type(path: Path) -> str:
    """The magic-identified media type of `path` (octet-stream when unknown)."""
    [obs] = magic.analyze(path)
    return obs.attributes.get("media_type", "application/octet-stream")


def _run(op: str, fn: Callable[[], list[Observation]]) -> list[Observation]:
    """Run one analyzer, isolating a failure as a note so it never aborts the file.

    The battery runs many analyzers over one artifact; a single parser choking on a
    malformed or hostile input must not lose the other analyzers' observations -- or,
    worse, the file's acquisition/custody record. Any exception becomes one ``note``
    observation naming the analyzer, and collection carries on (audit F0).
    """
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 -- deliberate per-analyzer isolation
        return [
            Observation(
                kind="note",
                value=f"{op} analyzer failed: {exc.__class__.__name__}",
            )
        ]


def _battery(
    path: Path, media_type: str, deps: ForensicsDeps
) -> Iterator[tuple[str, str, list[Observation]]]:
    """Yield ``(operation, actor, observations)`` for each analyzer fitting `path`.

    Selection is by media type: text gets string/encoding/log analysis, images get
    OCR (+ optional AI vision), everything else the binary battery. ``hash``,
    ``magic`` and ``fuzzyhash`` always run. Every analyzer is run through
    :func:`_run`, so one raising never aborts the file's collection (audit F0).
    """
    yield "hash", "in-process", _run("hash", lambda: hashes.analyze(path))
    yield "magic", "in-process", _run("magic", lambda: magic.analyze(path))
    yield "fuzzyhash", "in-process", _run("fuzzyhash", lambda: fuzzyhash.analyze(path))
    if media_type == "text/plain":
        yield "strings", "in-process", _run("strings", lambda: strings.analyze(path))
        yield "encoding", "in-process", _run("encoding", lambda: encoding.analyze(path))
        yield "logparse", "in-process", _run("logparse", lambda: logparse.analyze(path))
    elif media_type.startswith("image/"):
        yield "ocr", "in-process", _run("ocr", lambda: ocr.analyze(path))
        if deps.vision and vision.vision_available(deps.provider):
            report = vision.describe_image(
                deps.llm, deps.provider, path, native=deps.native_structured
            )
            if report is not None:
                obs = [
                    Observation(
                        kind="vision",
                        value=o.text,
                        attributes={"speculative": str(o.speculative)},
                    )
                    for o in report.observations
                ]
                yield "vision", "vision", obs
    else:
        exe = _run("executable", lambda: executable.analyze(path))
        if exe:  # a recognized ELF/PE/Mach-O header -> structured format observation
            yield "executable", "in-process", exe
        yield "strings", "in-process", _run("strings", lambda: strings.analyze(path))
        yield "hexdump", "in-process", _run("hexdump", lambda: hexview.analyze(path))
        yield "entropy", "in-process", _run("entropy", lambda: entropy.analyze(path))
        yield "encoding", "in-process", _run("encoding", lambda: encoding.analyze(path))


def collect_evidence(deps: ForensicsDeps) -> list[IntelResult]:
    """Run the battery over every evidence file; record custody; write artifacts.

    Returns one :class:`IntelResult` per evidence file (its observations as items),
    tagged with the evidence ID ``E1``/``E2``… that the examiner cites. A missing
    workspace/ledger/output root yields an empty list (the caller guarded this).
    """
    ws, ledger, out = deps.workspace, deps.ledger, deps.output_root
    if ws is None or ledger is None or out is None:
        return []
    policy = deps.redaction_policy or RedactionPolicy()

    def clean(text: str) -> str:
        return scrub(text, policy)

    results: list[IntelResult] = []
    step = 0
    for idx, path in enumerate(_evidence_files(ws.evidence_dir, deps.max_files), 1):
        eid = f"E{idx}"
        rel = str(path.relative_to(ws.evidence_dir))
        sha, size = sha256_of(path)
        media_type = _media_type(path)
        ledger.record_evidence(
            session_id=deps.session_id,
            source_path=rel,
            sha256=sha,
            size=size,
            media_type=media_type,
            note=eid,
        )
        items: list[IntelItem] = []
        for op, actor, observations in _battery(path, media_type, deps):
            items.extend(
                IntelItem(
                    kind=o.kind,
                    value=o.value,
                    attributes={**o.attributes, "evidence": eid, "operation": op},
                )
                for o in observations
            )
            # A non-deterministic AI-vision description is NOT reproducible, so it
            # never enters the chain-of-custody procedure log (its output_digest
            # could not be re-derived); it stays only as a clearly-attributed,
            # speculative observation for the report (audit E22).
            if actor == "vision":
                continue
            step += 1
            digest = hashlib.sha256(
                "\n".join(o.value for o in observations).encode("utf-8")
            ).hexdigest()
            ledger.record_procedure(
                session_id=deps.session_id,
                step=step,
                operation=op,
                actor=actor,
                input_sha256=sha,
                output_digest=digest,
                note=eid,
                examiner=deps.examiner,
                tool_version=f"skuggi {skuggi_version}",
            )
        result = IntelResult(
            task_id=eid,
            source="analyzers",
            subject=f"{eid}-{path.name}",
            items=tuple(items),
            note=f"{media_type}; {len(items)} observations",
        )
        intel_store.write_result(out, result, clean=clean)
        results.append(result)
    return results
