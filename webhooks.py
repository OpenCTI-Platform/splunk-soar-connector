import phantom.app as phantom
import json


def opencti_event_handler(connector, request, path_parts):
    try:
        payload = request.json
    except Exception:
        return {"success": False, "message": "Invalid JSON"}, 400

    entity_type = payload.get("entity_type") or "unknown"
    entity_name = payload.get("entity_name") or payload.get("entity_id") or "unknown"

    container = {
        "name": f"OpenCTI: {entity_type} - {entity_name}",
        "label": "opencti",
        "severity": "medium",
        "description": json.dumps(payload, indent=2),
    }

    if not connector.save_container(container):
        return {"success": False, "message": "Failed to create container"}, 500

    return {"success": True}, 200
