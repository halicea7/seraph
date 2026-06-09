"""AWS EC2 → C2 orchestration — provision cloud C2 nodes from Seraph."""
import json
import secrets
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import AppSetting, C2Node, CloudC2Instance, Credential, get_db
from services.vault import decrypt, encrypt

router = APIRouter(prefix="/cloud", tags=["cloud"])

# ── AppSetting helpers ────────────────────────────────────────────────────────

def _get_setting(db: Session, key: str, default: str = "") -> str:
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    return row.value if row else default


def _set_setting(db: Session, key: str, value: str) -> None:
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(AppSetting(key=key, value=value))


def _get_boto3_session(db: Session):
    """Return an authenticated boto3 Session using stored credentials."""
    try:
        import boto3
    except ImportError:
        raise HTTPException(501, "boto3 not installed — run: pip install boto3")

    raw_key = _get_setting(db, "cloud_aws_access_key")
    raw_secret = _get_setting(db, "cloud_aws_secret_key")
    region = _get_setting(db, "cloud_aws_default_region", "us-east-1")

    if not raw_key or not raw_secret:
        raise HTTPException(400, "AWS credentials not configured")

    try:
        access_key = decrypt(raw_key)
        secret_key = decrypt(raw_secret)
    except Exception:
        raise HTTPException(400, "Failed to decrypt AWS credentials")

    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )


# ── Static AMI map (Ubuntu 22.04 LTS per region) ─────────────────────────────
# AMI IDs for Ubuntu 22.04 LTS (Jammy) — us-east-1 canonical images
_UBUNTU_AMIS = {
    "us-east-1":      "ami-0c7217cdde317cfec",
    "us-east-2":      "ami-05fb0b8c1424f266b",
    "us-west-1":      "ami-0ce2cb35386fc22e9",
    "us-west-2":      "ami-008fe2fc65df48dac",
    "eu-west-1":      "ami-0905a3c97561e0b69",
    "eu-west-2":      "ami-0e5f882be1900e43b",
    "eu-central-1":   "ami-026c3177c9bd54288",
    "ap-southeast-1": "ami-078c1149d8ad719a7",
    "ap-northeast-1": "ami-0d52744d6551d851e",
    "ap-south-1":     "ami-007020fd9ab68fa92",
    "ca-central-1":   "ami-0a2e7efb4257c0907",
    "sa-east-1":      "ami-0af6e9042ea5a4e3e",
}

_C2_PORTS = {
    "msf":   [22, 55553, 4444, 4445],
    "sliver": [22, 31337, 8443, 443, 80],
}


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/aws/status")
def aws_status(db: Session = Depends(get_db)):
    configured = bool(_get_setting(db, "cloud_aws_access_key"))
    if not configured:
        return {"configured": False, "valid": False, "account_id": None, "error": "Not configured"}
    try:
        session = _get_boto3_session(db)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        return {"configured": True, "valid": True, "account_id": identity.get("Account"), "error": None}
    except HTTPException as e:
        return {"configured": True, "valid": False, "account_id": None, "error": e.detail}
    except Exception as e:
        return {"configured": True, "valid": False, "account_id": None, "error": str(e)}


class AWSCredentialsRequest(BaseModel):
    access_key: str
    secret_key: str
    region: str = "us-east-1"


@router.post("/aws/credentials")
def save_aws_credentials(req: AWSCredentialsRequest, db: Session = Depends(get_db)):
    _set_setting(db, "cloud_aws_access_key", encrypt(req.access_key))
    _set_setting(db, "cloud_aws_secret_key", encrypt(req.secret_key))
    _set_setting(db, "cloud_aws_default_region", req.region)
    db.commit()
    return {"ok": True}


@router.get("/aws/regions")
def list_regions(db: Session = Depends(get_db)):
    try:
        session = _get_boto3_session(db)
        ec2 = session.client("ec2")
        resp = ec2.describe_regions(Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}])
        return [r["RegionName"] for r in resp.get("Regions", [])]
    except Exception:
        return sorted(_UBUNTU_AMIS.keys())


@router.get("/aws/amis")
def list_amis(region: str = "us-east-1"):
    ami = _UBUNTU_AMIS.get(region)
    return [{"id": ami, "name": "Ubuntu 22.04 LTS (Jammy)", "region": region}] if ami else []


@router.get("/instances")
def list_instances(db: Session = Depends(get_db)):
    instances = db.query(CloudC2Instance).order_by(CloudC2Instance.created_at.desc()).all()
    return [_inst_to_dict(i) for i in instances]


@router.get("/instances/{instance_db_id}")
def get_instance(instance_db_id: str, db: Session = Depends(get_db)):
    inst = db.query(CloudC2Instance).filter(CloudC2Instance.id == instance_db_id).first()
    if not inst:
        raise HTTPException(404, "Instance not found")
    d = _inst_to_dict(inst)
    d["provision_log"] = inst.provision_log or ""
    return d


def _inst_to_dict(inst: CloudC2Instance) -> dict:
    return {
        "id": inst.id,
        "name": inst.name,
        "provider": inst.provider,
        "instance_id": inst.instance_id,
        "region": inst.region,
        "public_ip": inst.public_ip,
        "status": inst.status,
        "c2_type": inst.c2_type,
        "ami_id": inst.ami_id,
        "instance_type": inst.instance_type,
        "key_name": inst.key_name,
        "node_id": inst.node_id,
        "error_msg": inst.error_msg,
        "created_at": inst.created_at.isoformat() if inst.created_at else None,
    }


class LaunchInstanceRequest(BaseModel):
    name: str
    region: str = "us-east-1"
    ami_id: Optional[str] = None
    instance_type: str = "t3.medium"
    c2_type: str = "msf"
    create_keypair: bool = True
    existing_key_name: Optional[str] = None


@router.post("/instances")
def launch_instance(req: LaunchInstanceRequest, db: Session = Depends(get_db)):
    """Spin up an EC2 instance and record it. Call /ws/cloud/provision/{id} to stream setup."""
    session = _get_boto3_session(db)
    ec2 = session.client("ec2", region_name=req.region)

    ami_id = req.ami_id or _UBUNTU_AMIS.get(req.region)
    if not ami_id:
        raise HTTPException(400, f"No AMI available for region {req.region}. Provide ami_id manually.")

    # Key pair
    key_name = req.existing_key_name
    key_credential_id = None
    if req.create_keypair:
        kp_name = f"seraph-c2-{uuid.uuid4().hex[:8]}"
        try:
            kp_resp = ec2.create_key_pair(KeyName=kp_name, KeyType="rsa", KeyFormat="pem")
            pem_material = kp_resp["KeyMaterial"]
        except Exception as e:
            raise HTTPException(502, f"Failed to create key pair: {e}")

        # Store the private key in the Credential vault
        # Use a dummy project-less credential — store with project_id="" won't work due to FK
        # Instead, store in a "seraph_system" project or leave nullable.
        # For now, store with the first available project, or use a placeholder.
        cred = Credential(
            id=str(uuid.uuid4()),
            project_id="00000000-0000-0000-0000-000000000000",  # placeholder, no real FK cascade needed
            username="ubuntu",
            secret=pem_material,
            cred_type="key",
            source="aws_ec2",
            target_host="",
            notes=f"AWS key pair: {kp_name}",
        )
        # Try adding; if FK constraint fails, set project_id from first project
        try:
            db.add(cred)
            db.flush()
        except Exception:
            db.rollback()
            from database import Project
            proj = db.query(Project).first()
            if proj:
                cred.project_id = proj.id
            db.add(cred)
            db.flush()
        key_name = kp_name
        key_credential_id = cred.id

    # Security group
    sg_name = f"seraph-c2-{uuid.uuid4().hex[:6]}"
    ports = _C2_PORTS.get(req.c2_type, [22])
    try:
        sg_resp = ec2.create_security_group(
            GroupName=sg_name,
            Description=f"Seraph C2 node — {req.c2_type}",
        )
        sg_id = sg_resp["GroupId"]
        ip_perms = [
            {"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
            for p in ports
        ]
        ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=ip_perms)
    except Exception as e:
        raise HTTPException(502, f"Failed to create security group: {e}")

    # Launch instance
    try:
        run_resp = ec2.run_instances(
            ImageId=ami_id,
            InstanceType=req.instance_type,
            KeyName=key_name,
            SecurityGroupIds=[sg_id],
            MinCount=1,
            MaxCount=1,
            TagSpecifications=[{
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": req.name}, {"Key": "ManagedBy", "Value": "Seraph"}],
            }],
        )
    except Exception as e:
        raise HTTPException(502, f"Failed to launch instance: {e}")

    aws_instance_id = run_resp["Instances"][0]["InstanceId"]

    inst = CloudC2Instance(
        name=req.name,
        provider="aws",
        instance_id=aws_instance_id,
        region=req.region,
        status="launching",
        c2_type=req.c2_type,
        ami_id=ami_id,
        instance_type=req.instance_type,
        key_name=key_name,
        sg_id=sg_id,
        ssh_key_credential_id=key_credential_id,
    )
    db.add(inst)
    db.commit()
    db.refresh(inst)

    return {"instance_db_id": inst.id, "aws_instance_id": aws_instance_id}


@router.delete("/instances/{instance_db_id}")
def terminate_instance(instance_db_id: str, db: Session = Depends(get_db)):
    inst = db.query(CloudC2Instance).filter(CloudC2Instance.id == instance_db_id).first()
    if not inst:
        raise HTTPException(404, "Instance not found")

    if inst.instance_id:
        try:
            session = _get_boto3_session(db)
            ec2 = session.client("ec2", region_name=inst.region)
            ec2.terminate_instances(InstanceIds=[inst.instance_id])
        except Exception as e:
            raise HTTPException(502, f"Failed to terminate instance: {e}")

    inst.status = "terminated"
    db.commit()
    return {"ok": True}
