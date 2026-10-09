def authenticated_client(client):
    registration = client.post(
        "/auth/register",
        json={
            "username": "analyst_workflow",
            "email": "analyst_workflow@example.com",
            "password": "StrongPass!123",
        },
    )
    assert registration.status_code == 200, registration.text
    client.headers["Authorization"] = f"Bearer {registration.json()['token']}"
    return client


def test_scenario_analysis_graph_dashboard_and_investigation(client):
    client = authenticated_client(client)

    generated = client.post("/demo/scenarios/device-reuse")
    assert generated.status_code == 201, generated.text
    assert generated.json()["users"] == 8
    user_id = generated.json()["user_ids"][0]

    search = client.get("/users", params={"search": str(user_id)})
    assert search.status_code == 200
    assert any(user["id"] == user_id for user in search.json())

    analysis = client.post(f"/users/{user_id}/analyze")
    assert analysis.status_code == 200, analysis.text
    assert analysis.json()["model_status"] == "loaded"
    assert any(item["indicator_type"] == "device_reuse" for item in analysis.json()["indicators"])

    risk_filtered_users = client.get("/users", params={"risk_level": analysis.json()["risk_level"]})
    assert risk_filtered_users.status_code == 200
    assert any(user["id"] == user_id for user in risk_filtered_users.json())

    indicators = client.get(f"/users/{user_id}/indicators")
    assert indicators.status_code == 200
    assert indicators.json()

    graph = client.get(f"/users/{user_id}/graph")
    assert graph.status_code == 200
    assert any(node["type"] == "device" for node in graph.json()["nodes"])

    summary = client.get("/dashboard/summary")
    assert summary.status_code == 200
    assert summary.json()["analyzed_users"] == 1

    investigation = client.post("/investigations", json={"user_id": user_id})
    assert investigation.status_code == 201
    investigation_id = investigation.json()["id"]
    updated = client.patch(
        f"/investigations/{investigation_id}",
        json={"status": "under_review", "notes": "Review shared device links."},
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "under_review"

    detail = client.get(f"/investigations/{investigation_id}")
    assert detail.status_code == 200
    assert detail.json()["graph"]["nodes"]