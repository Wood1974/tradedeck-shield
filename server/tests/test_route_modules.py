"""Features live one per file in app/routes; adding one must not mean editing main.py."""
from app.main import app
from app.routes import feature_routers


def _paths(router):
    return {(m, r.path) for r in router.routes for m in r.methods}


def test_every_route_module_is_included_in_the_app():
    app_paths = {(m, r.path) for r in app.routes if hasattr(r, "methods") for m in r.methods}
    modules = feature_routers()
    assert {name for name, _ in modules} >= {"admin", "auth", "captures", "evidence", "health", "tickets"}
    for name, router in modules:
        assert _paths(router), f"routes/{name}.py has no routes"
        assert _paths(router) <= app_paths, f"routes/{name}.py is not registered on the app"


def test_the_moved_routes_are_still_served_once():
    seen = [(m, r.path) for r in app.routes if hasattr(r, "methods") for m in r.methods]
    for want in [("POST", "/shield/captures"), ("GET", "/shield/captures"), ("GET", "/shield/captures/{record_hash}/photo"),
                 ("GET", "/shield/captures/{record_hash}/timestamp"), ("POST", "/shield/tickets"),
                 ("POST", "/shield/tickets/countersign"), ("GET", "/shield/tickets/key")]:
        assert seen.count(want) == 1, want


def test_main_py_holds_no_routes_of_its_own():
    """Routes go in app/routes so two features never edit the same lines of main.py."""
    import inspect
    import app.main as main
    assert "@app.get" not in inspect.getsource(main) and "@app.post" not in inspect.getsource(main)
