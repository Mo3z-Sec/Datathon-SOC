"""FastAPI application: JSON API under /api plus the static single-page dashboard.

Security model
  * every /api route except /api/health requires a bearer token (Authorization: Bearer <token>)
  * two roles: "analyst" (may change status, add notes, generate data) and "viewer" (read-only)
  * tokens are compared in constant time; the interactive API docs are disabled
  * the app never talks to hospital systems: it only reads its own SQLite database
"""
import hmac
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel

from . import __version__
from .config import load_settings
from .service import NotFound, SocService

STATIC_DIR = Path(__file__).resolve().parent / "static"
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


class StatusIn(BaseModel):
    status: str


class NoteIn(BaseModel):
    text: str


class SimulateIn(BaseModel):
    seed: Optional[int] = None
    benign: int = 300
    scenarios: Optional[List[str]] = None
    replace: bool = True


class ResetIn(BaseModel):
    confirm: bool = False


def create_app(settings=None, service=None):
    settings = settings or load_settings()
    svc = service or SocService(settings)
    app = FastAPI(title="Hospital SOC Alert System (simulated data)", version=__version__,
                  docs_url=None, redoc_url=None, openapi_url=None)
    static = {name: (STATIC_DIR / name).read_bytes() for name in ("index.html", "app.js", "style.css")}

    # ------------------------------------------------------------------ auth
    def role_for(token):
        if not token:
            return None
        if hmac.compare_digest(token.encode(), settings.analyst_token.encode()):
            return "analyst"
        if settings.viewer_token and hmac.compare_digest(token.encode(), settings.viewer_token.encode()):
            return "viewer"
        return None

    def current_role(authorization: Optional[str] = Header(None), x_api_key: Optional[str] = Header(None)):
        token = None
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
        elif x_api_key:
            token = x_api_key.strip()
        role = role_for(token)
        if role is None:
            raise HTTPException(status_code=401, detail="Missing or invalid access token",
                                headers={"WWW-Authenticate": "Bearer"})
        return role

    def analyst_only(role: str = Depends(current_role)):
        if role != "analyst":
            raise HTTPException(status_code=403, detail="This action needs the analyst role (viewer is read-only)")
        return role

    def run(fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except NotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))

    def download(content, media_type, filename):
        return Response(content=content, media_type=media_type,
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    # ------------------------------------------------------------------ headers
    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = CSP
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # ------------------------------------------------------------------ static
    @app.get("/", include_in_schema=False)
    def index():
        return Response(content=static["index.html"], media_type="text/html; charset=utf-8")

    @app.get("/static/app.js", include_in_schema=False)
    def app_js():
        return Response(content=static["app.js"], media_type="application/javascript; charset=utf-8")

    @app.get("/static/style.css", include_in_schema=False)
    def style_css():
        return Response(content=static["style.css"], media_type="text/css; charset=utf-8")

    # ------------------------------------------------------------------ meta
    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": __version__, "simulated_data_only": True}

    @app.get("/api/me")
    def me(role: str = Depends(current_role)):
        return {"role": role}

    @app.get("/api/config")
    def config(role: str = Depends(current_role)):
        return {"simulated": True, "version": __version__, "ai_enabled": settings.ai_enabled,
                "ai_provider": settings.ai_provider if settings.ai_enabled else "none",
                "ai_model": settings.ai_model if settings.ai_enabled else None,
                "utc_offset_hours": settings.utc_offset_hours, "read_only_system": True}

    @app.get("/api/options")
    def options(role: str = Depends(current_role)):
        return svc.filter_options()

    @app.get("/api/stats")
    def stats(role: str = Depends(current_role)):
        return svc.stats()

    @app.get("/api/assets")
    def assets(role: str = Depends(current_role)):
        return svc.assets_overview()

    # ------------------------------------------------------------------ alerts
    @app.get("/api/alerts")
    def list_alerts(request: Request, role: str = Depends(current_role)):
        return run(svc.list_alerts, dict(request.query_params))

    @app.get("/api/alerts/{alert_id}")
    def alert_detail(alert_id: int, role: str = Depends(current_role)):
        return run(svc.alert_detail, alert_id)

    @app.post("/api/alerts/{alert_id}/status")
    def alert_status(alert_id: int, body: StatusIn, role: str = Depends(analyst_only)):
        return run(svc.set_status, alert_id, body.status, role)

    @app.post("/api/alerts/{alert_id}/notes")
    def alert_note(alert_id: int, body: NoteIn, role: str = Depends(analyst_only)):
        return run(svc.add_note, alert_id, body.text, role)

    @app.post("/api/alerts/{alert_id}/explain")
    def alert_explain(alert_id: int, role: str = Depends(analyst_only)):
        return run(svc.explain, alert_id, role)

    # ------------------------------------------------------------------ logs
    @app.get("/api/logs")
    def list_logs(request: Request, role: str = Depends(current_role)):
        return run(svc.list_logs, dict(request.query_params))

    # ------------------------------------------------------------------ actions on data
    @app.post("/api/simulate")
    def simulate(body: SimulateIn, role: str = Depends(analyst_only)):
        return run(svc.simulate, seed=body.seed, benign=body.benign, scenarios=body.scenarios,
                   replace=body.replace, actor=role)

    @app.post("/api/detect")
    def detect(role: str = Depends(analyst_only)):
        return run(svc.run_detection, role)

    @app.post("/api/reset")
    def reset(body: ResetIn, role: str = Depends(analyst_only)):
        if body.confirm is not True:
            raise HTTPException(status_code=422, detail="Set confirm=true to delete all simulated logs, alerts and notes")
        return run(svc.reset, role)

    @app.get("/api/audit")
    def audit(request: Request, role: str = Depends(analyst_only)):
        q = dict(request.query_params)
        return run(lambda: svc.db.list_audit(limit=min(int(q.get("limit", 50)), 500), offset=max(int(q.get("offset", 0)), 0)))

    # ------------------------------------------------------------------ exports
    @app.get("/api/export/logs.csv")
    def export_logs_csv(request: Request, role: str = Depends(current_role)):
        content = run(svc.export_logs, dict(request.query_params), "csv")
        svc.db.audit(role, "export_logs", "csv")
        return download(content, "text/csv; charset=utf-8", "simulated-logs.csv")

    @app.get("/api/export/logs.jsonl")
    def export_logs_jsonl(request: Request, role: str = Depends(current_role)):
        content = run(svc.export_logs, dict(request.query_params), "jsonl")
        svc.db.audit(role, "export_logs", "jsonl")
        return download(content, "application/x-ndjson; charset=utf-8", "simulated-logs.jsonl")

    @app.get("/api/export/alerts.csv")
    def export_alerts_csv(request: Request, role: str = Depends(current_role)):
        content = run(svc.export_alerts, dict(request.query_params))
        svc.db.audit(role, "export_alerts", "csv")
        return download(content, "text/csv; charset=utf-8", "simulated-alerts.csv")

    @app.get("/api/export/contract.csv")
    def export_contract_csv(role: str = Depends(current_role)):
        content = run(svc.export_contract)
        svc.db.audit(role, "export_contract", "csv")
        return download(content, "text/csv; charset=utf-8", "alerts-team-contract.csv")

    return app
