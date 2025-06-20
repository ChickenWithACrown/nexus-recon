"""Test that all modules can be imported."""

def test_import_nexusrecon():
    """Test that the main package can be imported."""
    import nexusrecon  # noqa: F401

def test_import_ui():
    """Test that the UI module can be imported."""
    from nexusrecon.ui import app  # noqa: F401

def test_import_core():
    """Test that the core module can be imported."""
    from nexusrecon.core import application  # noqa: F401

def test_import_utils():
    """Test that the utils module can be imported."""
    from nexusrecon import utils  # noqa: F401
