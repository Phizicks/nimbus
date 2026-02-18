import json
import os
import boto3

secrets = boto3.client("secretsmanager")


def lambda_handler(event, context):
    print("Rotation event:", json.dumps(event))
    secret_id = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]

    # Ensure secret version is staged correctly
    desc = secrets.describe_secret(SecretId=secret_id)
    versions = desc.get("VersionIdsToStages", {})
    if token not in versions:
        raise ValueError(f"Secret version {token} not found for rotation")

    if "AWSCURRENT" in versions[token]:
        print("Version already AWSCURRENT — nothing to do")
        return

    if "AWSPENDING" not in versions[token]:
        raise ValueError(f"Secret version {token} not marked AWSPENDING")

    # Route to correct rotation step
    if step == "createSecret":
        create_secret(secret_id, token)
    elif step == "setSecret":
        set_secret(secret_id, token)
    elif step == "testSecret":
        test_secret(secret_id, token)
    elif step == "finishSecret":
        finish_secret(secret_id, token)
    else:
        raise ValueError(f"Invalid step: {step}")


def create_secret(secret_id: str, token: str):
    try:
        secrets.get_secret_value(SecretId=secret_id, VersionId=token, VersionStage="AWSPENDING")
        print("AWSPENDING version already exists — updating with new credentials")
    except secrets.exceptions.ResourceNotFoundException:
        print("No pending version found — creating new")

    # Read current value and rotate it
    current = secrets.get_secret_value(SecretId=secret_id, VersionStage="AWSCURRENT")
    current_value = current["SecretString"]

    new_secret = current_value + "_rotated_"

    secrets.put_secret_value(
        SecretId=secret_id,
        ClientRequestToken=token,
        SecretString=new_secret,
        VersionStages=["AWSPENDING"],
    )
    print("Created new AWSPENDING secret version")


def set_secret(secret_id: str, token: str):
    """Apply new secret to the target resource (e.g., DB or API)."""
    print("STEP: setSecret")
    # creds = json.loads(secrets.get_secret_value(SecretId=secret_id, VersionStage="AWSPENDING")["SecretString"])
    # update_database_user(creds)
    pass


def test_secret(secret_id: str, token: str):
    """Verify the pending secret works."""
    print("STEP: testSecret")
    # Example: connect to database with AWSPENDING credentials and verify connection.
    # yeah, sure, it works, maybe....
    pass


def finish_secret(secret_id: str, token: str):
    """Promote the pending version to AWSCURRENT."""
    print("STEP: finishSecret")

    desc = secrets.describe_secret(SecretId=secret_id)
    versions = desc.get("VersionIdsToStages", {})

    current_version = None
    for ver, stages in versions.items():
        if "AWSCURRENT" in stages:
            current_version = ver
            break

    if current_version == token:
        print("Version already AWSCURRENT")
        return

    secrets.update_secret_version_stage(
        SecretId=secret_id,
        VersionStage="AWSCURRENT",
        MoveToVersionId=token,
        RemoveFromVersionId=current_version,
    )

    print("Rotation complete — promoted new version to AWSCURRENT")
