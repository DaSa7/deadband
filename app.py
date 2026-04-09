"""
app.py — Flask web UI for Deadband.

Three core ideas:
1. POST /run starts the pipeline in a background thread and returns an SSE
   stream — the browser gets live log lines without polling.
2. A thread-aware stdout shim routes every print() call from the pipeline
   modules into the current thread's queue. Other threads (Flask workers,
   the main thread) still write to the real stdout unchanged.
3. Job state lives in a plain dict — one process, no database needed.
"""

import io
import json
import os
import queue
import sys
import threading
import uuid
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, render_template, request, send_file, stream_with_context

from src.collector import collect_all
from src.mapper import map_cves_to_techniques
from src.gap_analyzer import load_coverage_config, analyze_gaps, list_platforms, list_categories
from src.reporter import generate_report


# ---------------------------------------------------------------------------
# Thread-aware stdout — routes print() into the right job queue
# ---------------------------------------------------------------------------

_real_stdout = sys.stdout
_thread_local = threading.local()


class _ThreadRouter(io.TextIOBase):
    """
    Drop-in stdout replacement. If the current thread has a log_queue attached,
    any non-blank write() goes into the queue. Otherwise falls through to the
    real stdout so Flask's own logging still works normally.
    """

    def write(self, text: str) -> int:
        q = getattr(_thread_local, "log_queue", None)
        if q is not None and text.strip():
            q.put(text.rstrip("\n"))
            return len(text)
        return _real_stdout.write(text)

    def flush(self) -> None:
        if getattr(_thread_local, "log_queue", None) is None:
            _real_stdout.flush()

    # fileno() needed so weasyprint/other C-level code doesn't blow up
    def fileno(self) -> int:
        return _real_stdout.fileno()


sys.stdout = _ThreadRouter()


# ---------------------------------------------------------------------------
# In-memory job store
# ---------------------------------------------------------------------------

# job_id → {status, result, error, report_filename, log_lines}
jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()
MAX_JOBS = 100


def _new_job(job_id: str) -> None:
    with _jobs_lock:
        # evict oldest finished jobs when the store gets too large
        if len(jobs) >= MAX_JOBS:
            finished = [k for k, v in jobs.items() if v["status"] in ("done", "failed")]
            for k in finished[:len(finished) // 2 or 1]:
                del jobs[k]
        jobs[job_id] = {
            "status": "running",
            "result": None,
            "error": None,
            "report_filename": None,
            "log_lines": [],
        }


# ---------------------------------------------------------------------------
# CVE deduplication
# ---------------------------------------------------------------------------

def _deduplicate_cves(cves: list[dict]) -> list[dict]:
    """Remove duplicate CVEs (by cve_id), keeping the first occurrence."""
    seen: set[str] = set()
    unique = []
    for cve in cves:
        cve_id = cve.get("cve_id")
        if cve_id and cve_id not in seen:
            seen.add(cve_id)
            unique.append(cve)
    return unique


# ---------------------------------------------------------------------------
# Background pipeline runner
# ---------------------------------------------------------------------------

def _run_pipeline(job_id: str, vendor: str, platform: str, log_queue: queue.Queue) -> None:
    """
    Runs the full collect → map → gap-analyse → report pipeline.
    All print() calls inside the pipeline end up in log_queue.
    Puts None into the queue when finished (sentinel for the SSE generator).
    """
    _thread_local.log_queue = log_queue

    try:
        # Step 1 — collect CVEs from NVD + CISA
        collection = collect_all(vendor)
        all_cves = _deduplicate_cves(collection["nvd"] + collection["cisa"])

        # Step 2 — map CVEs to ATT&CK ICS techniques
        mapped_results = map_cves_to_techniques(all_cves)

        # Step 3 — gap analysis against the chosen platform
        config = load_coverage_config()
        gap_report = analyze_gaps(platform, mapped_results, config=config)

        # Step 4 — generate PDF report
        safe_vendor = vendor.lower().replace(" ", "_")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"deadband_{safe_vendor}_{platform}_{timestamp}.pdf"
        output_path = os.path.join("reports", filename)

        generate_report(
            vendor=vendor,
            platform=platform,
            mapped_results=mapped_results,
            gap_report=gap_report,
            output_path=output_path,
        )

        # build a compact result summary — the full gap_report is large
        jobs[job_id]["status"] = "done"
        jobs[job_id]["report_filename"] = filename
        jobs[job_id]["result"] = {
            "total_cves": len(all_cves),
            "total_techniques": gap_report["total_techniques"],
            "covered": gap_report["covered"],
            "gaps": gap_report["gaps"],
            "coverage_pct": gap_report["coverage_pct"],
            "platform": platform,
            "platform_category": gap_report.get("platform_category", ""),
            "report_filename": filename,
            # top 10 blind spots for the done-event summary card
            "gap_techniques": [
                {
                    "technique_id": t["technique_id"],
                    "name": t["name"],
                    "tactics": t["tactics"],
                    "groups": [g["name"] for g in t.get("groups", [])],
                }
                for t in gap_report["gap_techniques"][:10]
            ],
        }

    except Exception as exc:
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["error"] = str(exc)
        log_queue.put(f"[ERROR] Pipeline crashed: {exc}")

    finally:
        # None is the sentinel — tells the SSE generator the stream is over
        log_queue.put(None)
        _thread_local.log_queue = None


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/platforms")
def platforms():
    """
    Returns all platforms from detection_coverage.json, grouped by category.
    The frontend uses this to populate the platform dropdown on page load.
    """
    try:
        config = load_coverage_config()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    groups: dict[str, list] = {}
    for p in list_platforms(config):
        cat = config[p].get("category", "other")
        # just the first sentence of the description — enough for a tooltip
        desc = config[p].get("description", "").split(".")[0]
        groups.setdefault(cat, []).append({
            "id": p,
            "label": p.title(),
            "description": desc,
            "technique_count": len(config[p].get("techniques", [])),
        })

    for cat in groups:
        groups[cat].sort(key=lambda x: x["id"])

    return jsonify({
        "platforms": groups,
        "categories": sorted(groups.keys()),
    })


@app.post("/run")
def run():
    """
    Kicks off the pipeline in a background thread and immediately returns an
    SSE response. The client reads the stream line by line.

    Event format:
      data: {"type": "job_id",  "job_id": "abc123"}
      data: {"type": "log",     "message": "[NVD] Fetching CVEs ..."}
      data: [DONE]  <JSON result object>    ← job finished successfully
      data: [ERROR] <JSON error object>     ← job failed
    """
    body = request.get_json(silent=True) or {}
    vendor = (body.get("vendor") or "").strip()[:200]
    platform = (body.get("platform") or "").strip().lower()

    if not vendor or not platform:
        return jsonify({"error": "vendor and platform are both required"}), 400

    # validate platform up front — no point starting a thread for a typo
    try:
        config = load_coverage_config()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    if platform not in config:
        return jsonify({
            "error": f"Unknown platform '{platform}'",
            "available": list_platforms(config),
        }), 400

    job_id = uuid.uuid4().hex[:10]
    log_queue: queue.Queue = queue.Queue()
    _new_job(job_id)

    t = threading.Thread(
        target=_run_pipeline,
        args=(job_id, vendor, platform, log_queue),
        daemon=True,
        name=f"pipeline-{job_id}",
    )
    t.start()

    @stream_with_context
    def generate():
        # first event — client needs this to poll /status later
        yield f"data: {json.dumps({'type': 'job_id', 'job_id': job_id})}\n\n"

        while True:
            try:
                line = log_queue.get(timeout=180)  # 3-min ceiling per log line
            except queue.Empty:
                msg = "[Timeout] No output for 3 minutes — pipeline may be stuck."
                jobs[job_id]["status"] = "failed"
                jobs[job_id]["error"] = msg
                yield f"data: {json.dumps({'type': 'log', 'message': msg})}\n\n"
                yield f"data: [ERROR] {json.dumps({'error': msg})}\n\n"
                return

            if line is None:   # sentinel — pipeline thread is done
                break

            jobs[job_id]["log_lines"].append(line)
            yield f"data: {json.dumps({'type': 'log', 'message': line})}\n\n"

        job = jobs[job_id]
        if job["status"] == "done":
            yield f"data: [DONE] {json.dumps(job['result'])}\n\n"
        else:
            error = job.get("error") or "Unknown error"
            yield f"data: [ERROR] {json.dumps({'error': error})}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # tells Nginx not to buffer this response
        },
    )


@app.get("/status/<job_id>")
def status(job_id: str):
    """
    Point-in-time snapshot of a job. Useful if the client reconnects after
    losing the SSE stream, or just wants to check programmatically.
    """
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": f"No job with id '{job_id}'"}), 404

    return jsonify({
        "job_id": job_id,
        "status": job["status"],          # running | done | failed
        "result": job["result"],
        "error": job["error"],
        "report_filename": job["report_filename"],
        "log_line_count": len(job["log_lines"]),
    })


@app.get("/report/<filename>")
def report(filename: str):
    """
    Serves a generated PDF for download. Strictly validates the filename to
    prevent path traversal — only plain filenames, no slashes or dots that
    would let someone escape the reports/ directory.
    """
    if ".." in filename or "/" in filename or "\\" in filename:
        return jsonify({"error": "Invalid filename"}), 400

    path = os.path.abspath(os.path.join("reports", filename))
    reports_dir = os.path.abspath("reports")

    # double-check the resolved path actually lives under reports/
    if not path.startswith(reports_dir + os.sep):
        return jsonify({"error": "Invalid filename"}), 400

    if not os.path.isfile(path):
        return jsonify({"error": "Report not found"}), 404

    return send_file(
        path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    os.makedirs("reports", exist_ok=True)
    os.makedirs("templates", exist_ok=True)
    _real_stdout.write("// deadband web UI → http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True, use_reloader=False)
