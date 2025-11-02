import asyncio

from fastapi import FastAPI


def test_import_main_and_call_root():
    # Import inside test so coverage records top-level execution in app.main
    import app.main as main

    # Ensure the FastAPI app object exists
    assert isinstance(main.app, FastAPI)

    # Call the root async function directly to avoid triggering lifespan/startup
    result = asyncio.run(main.root())
    assert isinstance(result, dict)
    assert result.get("message") == "FastAPI OpenLDAP AD Service"
