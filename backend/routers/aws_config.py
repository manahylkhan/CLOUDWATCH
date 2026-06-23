import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models import AWSAccount
from modules.aws.credentials import encrypt_credential, decrypt_credential
from modules.aws.session import create_session, get_account_id, list_enabled_regions
from modules.aws.permissions import READ_ONLY_POLICY

router = APIRouter(prefix="/api/aws", tags=["aws"])


class ConnectRequest(BaseModel):
    alias: str
    access_key: str
    secret_key: str
    region: str = "us-east-1"
    scan_all_regions: bool = True


@router.post("/connect")
def connect_aws(req: ConnectRequest, db: Session = Depends(get_db)):
    try:
        session = create_session(req.access_key, req.secret_key, req.region)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    account_id = get_account_id(session)
    regions = list_enabled_regions(session)

    # Save encrypted credentials
    account = AWSAccount(
        account_alias=req.alias,
        account_id=account_id,
        access_key_encrypted=encrypt_credential(req.access_key),
        secret_key_encrypted=encrypt_credential(req.secret_key),
        default_region=req.region,
        scan_all_regions=req.scan_all_regions,
    )
    db.add(account)
    db.commit()
    db.refresh(account)

    return {
        "id": account.id,
        "account_id": account_id,
        "alias": req.alias,
        "regions_count": len(regions),
        "default_region": req.region,
    }


@router.get("/accounts")
def list_accounts(db: Session = Depends(get_db)):
    accounts = db.query(AWSAccount).all()
    return [
        {
            "id": a.id,
            "alias": a.account_alias,
            "account_id": a.account_id,
            "default_region": a.default_region,
            "scan_all_regions": a.scan_all_regions,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "last_scan_at": a.last_scan_at.isoformat() if a.last_scan_at else None,
        }
        for a in accounts
    ]


@router.delete("/accounts/{account_id}")
def delete_account(account_id: str, db: Session = Depends(get_db)):
    account = db.query(AWSAccount).filter(AWSAccount.id == account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    db.delete(account)
    db.commit()
    return {"ok": True}


@router.get("/policy")
def get_required_policy():
    return READ_ONLY_POLICY
