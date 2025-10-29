import runpy
import sys
from pathlib import Path
from xml.etree.ElementTree import parse

import pytest


@pytest.fixture
def csv_file() -> Path:
    csv_path = Path(__file__).parent / "data" / "simple.csv"
    return csv_path


@pytest.fixture
def temp_output_file(tmp_path: Path) -> Path:
    return tmp_path / "output.xml"


def test_cli_conversion(csv_file: Path, temp_output_file: Path, monkeypatch: pytest.MonkeyPatch):
    # Simulate CLI call
    sys_argv = ["csv2cmi.py", str(csv_file), "-o", str(temp_output_file)]
    monkeypatch.setattr(sys, "argv", sys_argv)
    runpy.run_module("csv2cmi", run_name="__main__")
    assert temp_output_file.exists()
    # Check XML root
    tree = parse(temp_output_file)
    root = tree.getroot()
    assert root.tag == "{http://www.tei-c.org/ns/1.0}TEI"


def test_missing_file(monkeypatch: pytest.MonkeyPatch):
    sys_argv = ["csv2cmi.py", "nonexistent.csv"]
    monkeypatch.setattr(sys, "argv", sys_argv)
    with pytest.raises(SystemExit):
        runpy.run_module("csv2cmi", run_name="__main__")


def test_notes_argument(csv_file: Path, temp_output_file: Path, monkeypatch: pytest.MonkeyPatch):
    # Simulate CLI call with --notes argument
    sys_argv = ["csv2cmi.py", str(csv_file), "-o", str(temp_output_file), "--notes"]
    monkeypatch.setattr(sys, "argv", sys_argv)
    runpy.run_module("csv2cmi", run_name="__main__")
    assert temp_output_file.exists()
    # Check for note element in XML
    tree = parse(temp_output_file)
    root = tree.getroot()
    note = root.find(".//{http://www.tei-c.org/ns/1.0}note")
    assert note is not None
    assert note.text == "This is a test note."


def test_all_argument(csv_file: Path, temp_output_file: Path, monkeypatch: pytest.MonkeyPatch):
    # Simulate CLI call with --all argument
    sys_argv = ["csv2cmi.py", str(csv_file), "-o", str(temp_output_file), "--all"]
    monkeypatch.setattr(sys, "argv", sys_argv)
    runpy.run_module("csv2cmi", run_name="__main__")
    assert temp_output_file.exists()
    # Check that all letters are included
    tree = parse(temp_output_file)
    root = tree.getroot()
    correspDesc = root.findall(".//{http://www.tei-c.org/ns/1.0}correspDesc")
    assert len(correspDesc) == 3


def test_cc0_argument(csv_file: Path, temp_output_file: Path, monkeypatch: pytest.MonkeyPatch):
    # Simulate CLI call with --cc0 argument
    sys_argv = ["csv2cmi.py", str(csv_file), "-o", str(temp_output_file), "--cc0"]
    monkeypatch.setattr(sys, "argv", sys_argv)
    runpy.run_module("csv2cmi", run_name="__main__")
    assert temp_output_file.exists()
    # Check for CC0 license in XML
    tree = parse(temp_output_file)
    root = tree.getroot()
    licence = root.find(".//{http://www.tei-c.org/ns/1.0}licence")
    assert licence is not None
    assert licence.attrib["target"] == "https://creativecommons.org/publicdomain/zero/1.0/"


def test_line_numbers_argument(csv_file: Path, temp_output_file: Path, monkeypatch: pytest.MonkeyPatch):
    # Simulate CLI call with --line-numbers argument
    sys_argv = ["csv2cmi.py", str(csv_file), "-o", str(temp_output_file), "--line-numbers"]
    monkeypatch.setattr(sys, "argv", sys_argv)
    runpy.run_module("csv2cmi", run_name="__main__")
    assert temp_output_file.exists()
    # Check for n attribute in correspDesc
    tree = parse(temp_output_file)
    root = tree.getroot()
    correspDesc = root.find(".//{http://www.tei-c.org/ns/1.0}correspDesc")
    assert correspDesc is not None
    assert "n" in correspDesc.attrib


def test_extra_delimiter_argument(csv_file: Path, temp_output_file: Path, monkeypatch: pytest.MonkeyPatch):
    # Simulate CLI call with --extra-delimiter argument
    sys_argv = ["csv2cmi.py", str(csv_file), "-o", str(temp_output_file), "--extra-delimiter", ";"]
    monkeypatch.setattr(sys, "argv", sys_argv)
    runpy.run_module("csv2cmi", run_name="__main__")
    assert temp_output_file.exists()
    # Check for multiple senders
    tree = parse(temp_output_file)
    root = tree.getroot()
    senders = root.findall(".//{http://www.tei-c.org/ns/1.0}correspAction[@type='sent']/{http://www.tei-c.org/ns/1.0}persName")
    assert len(senders) > 1
