import floss.resources as resources


def test_resource_path_sigs():
    sigs_path = resources.resource_path("sigs")

    assert sigs_path.exists()
    assert (sigs_path / "README.md").exists()


def test_resource_path_project_scripts():
    script_path = resources.resource_path("scripts", "ghidra_floss_import.py")

    assert script_path.exists()


def test_resource_path_frozen(monkeypatch, tmp_path):
    frozen_root = tmp_path / "bundle"
    sigs_dir = frozen_root / "sigs"
    sigs_dir.mkdir(parents=True)
    readme = sigs_dir / "README.md"
    readme.write_text("test")

    monkeypatch.setattr(resources.sys, "frozen", True, raising=False)
    monkeypatch.setattr(resources.sys, "_MEIPASS", str(frozen_root), raising=False)

    assert resources.is_frozen() is True

    frozen_path = resources.resource_path("sigs")
    assert frozen_path == sigs_dir
    assert (frozen_path / "README.md").read_text() == "test"
