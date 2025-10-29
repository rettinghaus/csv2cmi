import pytest
from unittest.mock import patch, Mock
from xml.etree import ElementTree
from io import BytesIO

from csv2cmi import CMI, is_datable_iso, is_datable_w3c


@pytest.fixture
def cmi_object():
    return CMI()


def test_is_datable_iso():
    assert is_datable_iso("2024-01-01") is True
    assert is_datable_iso("2024-01") is True
    assert is_datable_iso("2024") is True
    assert is_datable_iso("2024-1-1") is False
    assert is_datable_iso("not-a-date") is False


def test_is_datable_w3c():
    assert is_datable_w3c("2024-01-01") is True
    assert is_datable_w3c("-0400-01-01") is True
    assert is_datable_w3c("--01-01") is True
    assert is_datable_w3c("--01") is True
    assert is_datable_w3c("---01") is True
    assert is_datable_w3c("not-a-date") is False


def test_create_date_valid(cmi_object: CMI):
    assert cmi_object.create_date("2016-04-01").attrib["when"] == "2016-04-01"
    assert cmi_object.create_date("1673-05").attrib["when"] == "1673-05"
    assert cmi_object.create_date("[..1760-12-03]").attrib["notAfter"] == "1760-12-03"
    assert cmi_object.create_date("[1760-12..]").attrib["notBefore"] == "1760-12"
    assert cmi_object.create_date("1979-10-12/").attrib["from"] == "1979-10-12"
    assert cmi_object.create_date("/1985-04-12").attrib["to"] == "1985-04-12"
    assert cmi_object.create_date("{-0400,-0390,-0370}") is not None
    assert cmi_object.create_date("1888-XX-XX").attrib["from"] == "1888"
    assert cmi_object.create_date("188X").attrib["from"] == "1880"
    assert cmi_object.create_date("?1900?").attrib["cert"] == "low"
    assert cmi_object.create_date(None) is None


def test_create_date_invalid(cmi_object: CMI):
    with pytest.raises(ValueError):
        cmi_object.create_date("not-a-date")


def test_create_place_name(cmi_object: CMI):
    tei_placename = cmi_object.create_place_name("Berlin")
    assert tei_placename.tag == "placeName"
    assert tei_placename.text == "Berlin"
    tei_placename_conjecture = cmi_object.create_place_name("[Berlin]", line_num=1)
    assert tei_placename_conjecture.attrib["evidence"] == "conjecture"
    assert tei_placename_conjecture.text == "Berlin"


def test_create_place_name_with_uri(cmi_object: CMI):
    tei_placename = cmi_object.create_place_name("Mokhdān", "https://www.geonames.org/123456")
    assert tei_placename.tag == "placeName"
    assert tei_placename.attrib["ref"] == "https://www.geonames.org/123456"
    assert tei_placename.text == "Mokhdān"
    tei_placename_invalid = cmi_object.create_place_name("Mokhdān", "not-a-uri")
    assert "ref" not in tei_placename_invalid.attrib


def test_generate_id_and_uuid(cmi_object: CMI):
    id1 = cmi_object.generate_id("test")
    id2 = cmi_object.generate_id("test")
    assert id1 != id2
    id3 = cmi_object.generate_id("")
    assert len(id3) > 8
    uuid1 = cmi_object.generate_uuid()
    uuid2 = cmi_object.generate_uuid()
    assert uuid1 != uuid2


@patch("urllib.request.urlopen")
def test_create_correspondent_with_gnd_id(mock_urlopen, cmi_object: CMI):
    # Mock the response from the GND RDF service
    gnd_rdf = b'<?xml version="1.0" encoding="UTF-8"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description rdf:about="https://d-nb.info/gnd/118540238"><rdf:type rdf:resource="http://d-nb.info/standards/elementset/gnd#DifferentiatedPerson"/></rdf:Description></rdf:RDF>'
    mock_urlopen.return_value = BytesIO(gnd_rdf)

    # Call the method with a GND ID
    letter = {"sender": "Goethe, Johann Wolfgang von", "senderID": "118540238"}
    correspondents = cmi_object.create_correspondent(letter, "sender", line_num=1)
    assert len(correspondents) == 1
    assert correspondents[0].tag == "persName"
    assert correspondents[0].attrib["ref"] == "https://d-nb.info/gnd/118540238"
    assert correspondents[0].text == "Goethe, Johann Wolfgang von"


@patch("urllib.request.urlopen")
def test_create_correspondent_with_viaf_id(mock_urlopen, cmi_object: CMI):
    # Mock the response from the VIAF RDF service
    viaf_rdf = b'<?xml version="1.0" encoding="UTF-8"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:schema="http://schema.org/"><rdf:Description rdf:about="http://viaf.org/viaf/24602065"><rdf:type rdf:resource="http://schema.org/Person"/></rdf:Description></rdf:RDF>'
    mock_urlopen.return_value = BytesIO(viaf_rdf)

    # Call the method with a VIAF ID
    letter = {"sender": "Goethe, Johann Wolfgang von", "senderID": "http://viaf.org/viaf/24602065"}
    correspondents = cmi_object.create_correspondent(letter, "sender", line_num=1)
    assert len(correspondents) == 1
    assert correspondents[0].tag == "persName"
    assert correspondents[0].attrib["ref"] == "http://viaf.org/viaf/24602065"
    assert correspondents[0].text == "Goethe, Johann Wolfgang von"


def test_create_correspondent_without_id(cmi_object: CMI):
    # Call the method without an ID
    letter = {"sender": "Goethe, Johann Wolfgang von"}
    correspondents = cmi_object.create_correspondent(letter, "sender", line_num=1)
    assert len(correspondents) == 1
    assert correspondents[0].tag == "persName"
    assert "ref" not in correspondents[0].attrib
    assert correspondents[0].text == "Goethe, Johann Wolfgang von"


def test_create_correspondent_with_conjecture(cmi_object: CMI):
    # Call the method with a conjectural name
    letter = {"sender": "[Goethe, Johann Wolfgang von]"}
    correspondents = cmi_object.create_correspondent(letter, "sender", line_num=1)
    assert len(correspondents) == 1
    assert correspondents[0].tag == "persName"
    assert correspondents[0].attrib["evidence"] == "conjecture"
    assert correspondents[0].text == "Goethe, Johann Wolfgang von"


def test_create_correspondent_with_delimiter(cmi_object: CMI):
    # Call the method with a delimiter
    letter = {"sender": "Sender1;Sender2", "senderID": "id1;id2"}
    correspondents = cmi_object.create_correspondent(letter, "sender", subdlm=";", line_num=1)
    assert len(correspondents) == 2
    assert correspondents[0].text == "Sender1"
    assert correspondents[1].text == "Sender2"
