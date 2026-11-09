from typing import Literal
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .db import Finding, Project, get_session
from .schemas import SarifInput, VexInput, RetentionInput, ScanView
from .services.sarif_import import import_sarif
from .services.vex import import_vex, export_vex
from .services.retention import apply_retention

router = APIRouter(prefix="/api", tags=["External evidence"])


@router.get("/retention")
def retention_plan(session: Session = Depends(get_session)):
    return apply_retention(session, dry_run=True)


@router.post("/retention")
def retention_apply(body: RetentionInput, session: Session = Depends(get_session)):
    return apply_retention(session, dry_run=not body.apply)


@router.post("/projects/{identifier}/imports/sarif", status_code=201, response_model=ScanView)
def sarif_import(identifier: int, body: SarifInput, session: Session = Depends(get_session)):
    if session.get(Project, identifier) is None:
        raise HTTPException(404, "Projeto não encontrado")
    try:
        return import_sarif(session, identifier, body.document)
    except ValueError as exc:
        session.rollback()
        raise HTTPException(422, str(exc))


@router.post("/findings/{identifier}/vex", status_code=201)
def vex_import(identifier: int, body: VexInput, session: Session = Depends(get_session)):
    finding = session.get(Finding, identifier)
    if finding is None:
        raise HTTPException(404)
    if len(body.reason) > 4000:
        raise HTTPException(422, "Justificativa excede 4000 caracteres")
    try:
        return import_vex(session, finding, body.document, body.format, body.apply_decision, body.reason)
    except (ValueError, TypeError, AttributeError, KeyError):
        session.rollback()
        raise HTTPException(422, "VEX inválido ou sem correspondência exata de vulnerabilidade/versão; confira contexto, justificativa e timestamp")


@router.get("/findings/{identifier}/vex")
def vex_export(identifier: int, format: Literal["openvex", "cyclonedx"] = "openvex", session: Session = Depends(get_session)):
    finding = session.get(Finding, identifier)
    if finding is None:
        raise HTTPException(404)
    try:
        return export_vex(session, finding, format)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
