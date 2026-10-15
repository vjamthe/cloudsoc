import json, os
from decimal import Decimal
import boto3

table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])

def handler(event, context):
    d = event["detail"]
    item = {
        "finding_id": d["id"],
        "type": d["type"],
        "severity": Decimal(str(d["severity"])),
        "title": d.get("title", ""),
        "resource_type": d.get("resource", {}).get("resourceType", "unknown"),
        "region": d.get("region", event.get("region", "")),
        "created_at": d.get("createdAt", ""),
        "is_sample": bool(d.get("service", {}).get("additionalInfo", {}).get("sample", False)),
        "status": "NEW",
        "raw": json.dumps(d),
    }
    table.put_item(Item=item)
    print(json.dumps({"stored": item["finding_id"], "type": item["type"],
                      "severity": float(item["severity"]), "sample": item["is_sample"]}))
    return {"stored": item["finding_id"]}
