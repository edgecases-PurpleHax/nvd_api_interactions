import os

import pytest
from requests_mock.mocker import Mocker

from api_interactions.cve import get_all_cves
from api_interactions.cve import get_cve_by_id


def get_test_file(file):
    path = os.path.join(os.path.dirname(__file__), f"testfiles/{file}")
    with open(path, "r") as infile:
        return infile.read()


def test_get_cve_by_id(requests_mock: Mocker):
    cve_id = "CVE-2021-3165"
    cve_data = get_test_file(f"{cve_id}.json")
    requests_mock.get(
        f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}",
        text=cve_data)

    result = get_cve_by_id(cve_id)

    assert requests_mock.called_once
    assert "cve@mitre.org" in result


@pytest.mark.xfail(reason="Not implemented")
def test_get_all_cves(requests_mock: Mocker, tmpdir):
    # todo: this is a placeholder test that currently is expected to fail.

    all_cves_response = get_test_file("all_cves.json")
    requests_mock.get("https://services.nvd.nist.gov/rest/json/cves/1.0",
                      text=all_cves_response)

    result = get_all_cves()

    assert requests_mock.called
