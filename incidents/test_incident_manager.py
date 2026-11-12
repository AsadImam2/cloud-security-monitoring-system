from incidents.incident_manager import resolve_incident

incident_id = "INC-BC549431"

resolve_incident(
    incident_id,
    "Brute-force activity confirmed. Admin account secured and unauthorized login attempts blocked."
)

print("Incident resolution test completed.")