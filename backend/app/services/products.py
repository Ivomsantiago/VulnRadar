"""NVD CPE matching keeps applicability unknown when constraints cannot be proven."""

import re
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field
from ..schemas import InputModel
from sqlalchemy import select, or_
from sqlalchemy.orm import Session
from ..db import Advisory, AffectedProduct, ProductWatch, Source, Activity, PlatformSetting, get_session

router = APIRouter(prefix="/api", tags=["Product intelligence"])


def cpe_products(raw):
    def walk(nodes, conditional=False):
        for node in nodes:
            conditional_node = conditional or bool(node.get("negate")) or node.get("operator") == "AND"
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                parts = re.split(r"(?<!\\):", match.get("criteria", ""))
                if len(parts) < 13 or parts[:2] != ["cpe", "2.3"]:
                    continue

                def unescape(value):
                    return re.sub(r"\\(.)", r"\1", value)

                yield {
                    "vendor": unescape(parts[3]),
                    "product": unescape(parts[4]),
                    "version": unescape(parts[5]),
                    "update": unescape(parts[6]),
                    "part": parts[2],
                    "cpe": match["criteria"],
                    "conditional": conditional_node or any(value not in {"*", "-"} for value in parts[6:]),
                    **{key: match[key] for key in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding") if key in match},
                }
            yield from walk(node.get("nodes", []) + node.get("children", []), conditional_node)

    yield from walk(raw.get("cve", raw).get("configurations", []))


def version_match(item, version):
    """Three-valued CPE result; CPE conditions and unsupported ordering stay unknown."""
    if not version:
        return "unknown"
    exact = item.get("version", "*")
    if exact != "*" and any(token in exact for token in ("*", "?")):
        return "unknown"
    if exact not in {"*", "-"}:
        matched = exact.casefold() == version.casefold()
        if not matched:
            if item.get("update", "*") not in {"*", "-"} and version.startswith(exact + "_"):
                return "unknown"
            return "not_affected"
    boundaries = [(key, item[key]) for key in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding") if item.get(key)]

    def numeric(value):
        if not re.fullmatch(r"\d+(?:\.\d+){0,5}(?:[-.]?(?:alpha|beta|a|b|rc)\d*)?", value, re.I):
            return None
        from packaging.version import Version

        return Version(value)

    if boundaries:
        current = numeric(version)
        for key, value in boundaries:
            bound = numeric(value)
            if current is None or bound is None:
                return "unknown"
            if (
                (key == "versionStartIncluding" and current < bound)
                or (key == "versionStartExcluding" and current <= bound)
                or (key == "versionEndIncluding" and current > bound)
                or (key == "versionEndExcluding" and current >= bound)
            ):
                return "not_affected"
    if item.get("conditional") or exact == "-":
        return "unknown"
    return "affected"


def product_rows(session, vendor=None, product=None, version=None, q=""):
    statement = select(AffectedProduct, Advisory.vulnerability_id).join(Advisory, Advisory.id == AffectedProduct.advisory_id)
    if vendor:
        statement = statement.where(AffectedProduct.vendor == vendor.casefold())
    if product:
        statement = statement.where(AffectedProduct.product == product.casefold())
    if q:
        statement = statement.where(or_(AffectedProduct.vendor.ilike(f"%{q}%"), AffectedProduct.product.ilike(f"%{q}%")))
    for record, identifier in session.execute(statement.order_by(AffectedProduct.id).execution_options(yield_per=500)):
        item = record.constraints
        match = version_match(item, version)
        if version and match == "not_affected":
            continue
        yield {**item, "vulnerability_id": identifier, "source": "nvd", "version_match": match}


def index_products(session, advisory_id, raw):
    from sqlalchemy import delete

    session.execute(delete(AffectedProduct).where(AffectedProduct.advisory_id == advisory_id))
    for item in cpe_products(raw):
        item["modified"] = raw.get("cve", raw).get("lastModified")
        session.add(AffectedProduct(advisory_id=advisory_id, vendor=item["vendor"].casefold(), product=item["product"].casefold(), constraints=item))


def ensure_product_index(session):
    if session.get(PlatformSetting, "products.index.v1"):
        return
    for advisory in session.scalars(select(Advisory).where(Advisory.source == "nvd")):
        index_products(session, advisory.id, advisory.payload)
    session.add(PlatformSetting(key="products.index.v1", value={"complete": True}))
    session.commit()


@router.get("/products")
def products(
    q: str = Query("", max_length=200),
    vendor: str | None = None,
    product: str | None = None,
    version: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    session: Session = Depends(get_session),
):
    items, total = [], 0
    for row in product_rows(session, vendor, product, version, q):
        if (page - 1) * page_size <= total < page * page_size:
            items.append(row)
        total += 1
    source = session.get(Source, "nvd")
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "source_status": source.status if source else "never",
        "last_updated": source.last_run if source else None,
        "scope": "CPEs NVD coletados; condições de plataforma ou versões sem ordenação verificável permanecem desconhecidas. Correspondência não prova explorabilidade.",
    }


class ProductWatchInput(InputModel):
    vendor: str = Field(min_length=1, max_length=200)
    product: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=100)
    alerts_enabled: bool = True


@router.get("/product-watches")
def watches(session: Session = Depends(get_session)):
    return list(session.scalars(select(ProductWatch).order_by(ProductWatch.id.desc())))


@router.post("/product-watches", status_code=201)
def add_watch(body: ProductWatchInput, session: Session = Depends(get_session)):
    existing = session.scalar(select(ProductWatch).where(ProductWatch.vendor == body.vendor, ProductWatch.product == body.product, ProductWatch.version == body.version))
    if existing:
        raise HTTPException(409, "Produto e versão já monitorados")
    item = ProductWatch(**body.model_dump())
    session.add(item)
    session.commit()
    return item


@router.delete("/product-watches/{identifier}", status_code=204)
def delete_watch(identifier: int, session: Session = Depends(get_session)):
    item = session.get(ProductWatch, identifier)
    if not item:
        raise HTTPException(404)
    session.delete(item)
    session.commit()


def check_product_watch(session, watch):
    items = list(product_rows(session, watch.vendor, watch.product, watch.version))
    for item in items:
        subject = f"product-watch:{watch.id}:{item['vulnerability_id']}:{item['modified']}"
        if watch.alerts_enabled and item["version_match"] == "affected" and not session.scalar(select(Activity.id).where(Activity.kind == "alert", Activity.subject == subject)):
            session.add(
                Activity(
                    kind="alert",
                    subject=subject,
                    data={
                        "reason": "Produto e versão correspondem ao CPE NVD",
                        "vendor": watch.vendor,
                        "product": watch.product,
                        "version": watch.version,
                        "vulnerability": item["vulnerability_id"],
                        "source": "nvd",
                    },
                )
            )
    session.add(Activity(kind="product.checked", subject=str(watch.id), data={"candidates": len(items), "affected": sum(item["version_match"] == "affected" for item in items)}))
    session.commit()
    return {"items": items, "scope": "Base NVD local coletada; ausência de correspondências não comprova segurança"}


@router.post("/product-watches/{identifier}/check")
def check_watch(identifier: int, session: Session = Depends(get_session)):
    watch = session.get(ProductWatch, identifier)
    if not watch:
        raise HTTPException(404)
    return check_product_watch(session, watch)
