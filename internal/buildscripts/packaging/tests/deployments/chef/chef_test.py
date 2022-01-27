# Copyright Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import glob
import os
import string
import tempfile

from pathlib import Path

import pytest

from tests.helpers.util import (
    copy_file_into_container,
    copy_file_into_win_container,
    run_container_cmd,
    run_distro_container,
    service_is_running,
    service_is_running_win,
    wait_for,
    REPO_DIR,
    SERVICE_NAME,
    SERVICE_OWNER,
)

IMAGES_DIR = Path(__file__).parent.resolve() / "images"
DEB_DISTROS = [df.split(".")[-1] for df in glob.glob(str(IMAGES_DIR / "deb" / "Dockerfile.*"))]
RPM_DISTROS = [df.split(".")[-1] for df in glob.glob(str(IMAGES_DIR / "rpm" / "Dockerfile.*"))]
CONFIG_DIR = "/etc/otel/collector"
SPLUNK_CONFIG = f"{CONFIG_DIR}/agent_config.yaml"
SPLUNK_ENV_PATH = f"{CONFIG_DIR}/splunk-otel-collector.conf"
SPLUNK_ACCESS_TOKEN = "testing123"
SPLUNK_REALM = "test"
SPLUNK_INGEST_URL = f"https://ingest.{SPLUNK_REALM}.signalfx.com"
SPLUNK_API_URL = f"https://api.{SPLUNK_REALM}.signalfx.com"
SPLUNK_SERVICE_USER = "splunk-otel-collector"
SPLUNK_SERVICE_GROUP = "splunk-otel-collector"
SPLUNK_MEMORY_TOTAL_MIB = 512
SPLUNK_BUNDLE_DIR = "/usr/lib/splunk-otel-collector/agent-bundle"
SPLUNK_COLLECTD_DIR = f"{SPLUNK_BUNDLE_DIR}/run/collectd"
WIN_SPLUNK_CONFIG = "C:\\ProgramData\\Splunk\\OpenTelemetry Collector\\agent_config.yaml"
WIN_SPLUNK_BUNDLE_DIR = "C:\\Program Files\\Splunk\\OpenTelemetry Collector\\agent-bundle"
WIN_SPLUNK_COLLECTD_DIR = f"{WIN_SPLUNK_BUNDLE_DIR}\\run\\collectd"

# allow CHEF_VERSIONS env var with comma-separated chef versions for test parameterization
CHEF_VERSIONS = os.environ.get("CHEF_VERSIONS", "16.0.257,latest").split(",")

CHEF_CMD = "chef-client -z -o 'recipe[splunk-otel-collector::default]' -j {0}"

def run_chef_apply(container, configs, chef_version, CHEF_CMD):
    with tempfile.NamedTemporaryFile(mode="w+") as fd:
        print(json.dumps(configs))
        fd.write(json.dumps(configs))
        fd.flush()
        if chef_version == "latest" or int(chef_version.split(".")[0]) >= 15:
            CHEF_CMD += " --chef-license accept-silent"
        copy_file_into_container(container, fd.name, "/root/test_attrs.json")
    CHEF_CMD = CHEF_CMD.format("/root/test_attrs.json")
    run_container_cmd(container, CHEF_CMD)

def verify_env_file(container):
    run_container_cmd(container, f"grep '^SPLUNK_CONFIG={SPLUNK_CONFIG}$' {SPLUNK_ENV_PATH}")
    run_container_cmd(container, f"grep '^SPLUNK_ACCESS_TOKEN={SPLUNK_ACCESS_TOKEN}$' {SPLUNK_ENV_PATH}")
    run_container_cmd(container, f"grep '^SPLUNK_REALM={SPLUNK_REALM}$' {SPLUNK_ENV_PATH}")
    run_container_cmd(container, f"grep '^SPLUNK_API_URL={SPLUNK_API_URL}$' {SPLUNK_ENV_PATH}")
    run_container_cmd(container, f"grep '^SPLUNK_INGEST_URL={SPLUNK_INGEST_URL}$' {SPLUNK_ENV_PATH}")
    run_container_cmd(container, f"grep '^SPLUNK_TRACE_URL={SPLUNK_INGEST_URL}/v2/trace$' {SPLUNK_ENV_PATH}")
    run_container_cmd(container, f"grep '^SPLUNK_HEC_URL={SPLUNK_INGEST_URL}/v1/log$' {SPLUNK_ENV_PATH}")
    run_container_cmd(container, f"grep '^SPLUNK_HEC_TOKEN={SPLUNK_ACCESS_TOKEN}$' {SPLUNK_ENV_PATH}")
    run_container_cmd(container, f"grep '^SPLUNK_MEMORY_TOTAL_MIB={SPLUNK_MEMORY_TOTAL_MIB}$' {SPLUNK_ENV_PATH}")
    run_container_cmd(container, f"grep '^SPLUNK_BUNDLE_DIR={SPLUNK_BUNDLE_DIR}$' {SPLUNK_ENV_PATH}")
    run_container_cmd(container, f"grep '^SPLUNK_COLLECTD_DIR={SPLUNK_COLLECTD_DIR}$' {SPLUNK_ENV_PATH}")

@pytest.mark.installer
@pytest.mark.parametrize(
    "distro",
    [pytest.param(distro, marks=pytest.mark.deb) for distro in DEB_DISTROS]
    + [pytest.param(distro, marks=pytest.mark.rpm) for distro in RPM_DISTROS],
    )
@pytest.mark.parametrize("chef_version", CHEF_VERSIONS)
def test_chef_without_fluentd(distro, chef_version):
    if distro in DEB_DISTROS:
        dockerfile = IMAGES_DIR / "deb" / f"Dockerfile.{distro}"
    else:
        dockerfile = IMAGES_DIR / "rpm" / f"Dockerfile.{distro}"

    buildargs = {"CHEF_INSTALLER_ARGS": ""}
    if chef_version != "latest":
        buildargs["CHEF_INSTALLER_ARGS"] = f"-v {chef_version}"

    with run_distro_container(distro, dockerfile=dockerfile, path=REPO_DIR, buildargs=buildargs) as container:
        try:
            configs = {}
            configs["splunk-otel-collector"] = {}
            configs["splunk-otel-collector"]["splunk_access_token"] = SPLUNK_ACCESS_TOKEN
            configs["splunk-otel-collector"]["splunk_realm"] = SPLUNK_REALM
            configs["splunk-otel-collector"]["splunk_ingest_url"] = SPLUNK_INGEST_URL
            configs["splunk-otel-collector"]["splunk_api_url"] = SPLUNK_API_URL
            configs["splunk-otel-collector"]["splunk_service_user"] = SPLUNK_SERVICE_USER
            configs["splunk-otel-collector"]["splunk_service_group"] = SPLUNK_SERVICE_GROUP
            configs["splunk-otel-collector"]["with_fluentd"] = False
            configs["splunk-otel-collector"]["collector_version"] = 'latest'
            run_chef_apply(container, configs, chef_version, CHEF_CMD)
            verify_env_file(container)
            assert wait_for(lambda: service_is_running(container))
            assert container.exec_run("systemctl status td-agent").exit_code != 0
        finally:
            run_container_cmd(container, f"journalctl -u {SERVICE_NAME} --no-pager")

@pytest.mark.installer
@pytest.mark.parametrize(
    "distro",
    [pytest.param(distro, marks=pytest.mark.deb) for distro in DEB_DISTROS]
    + [pytest.param(distro, marks=pytest.mark.rpm) for distro in RPM_DISTROS],
    )
@pytest.mark.parametrize("chef_version", CHEF_VERSIONS)
def test_chef_with_fluentd(distro, chef_version):
    if distro in DEB_DISTROS:
        dockerfile = IMAGES_DIR / "deb" / f"Dockerfile.{distro}"
    else:
        dockerfile = IMAGES_DIR / "rpm" / f"Dockerfile.{distro}"

    if "opensuse" in distro:
        pytest.skip(f"FluentD is not supported on opensuse")

    buildargs = {"CHEF_INSTALLER_ARGS": ""}
    if chef_version != "latest":
        buildargs["CHEF_INSTALLER_ARGS"] = f"-v {chef_version}"

    with run_distro_container(distro, dockerfile=dockerfile, path=REPO_DIR, buildargs=buildargs) as container:
        try:
            for collector_version in ["0.34.0", "latest"]:
                configs = {}
                configs["splunk-otel-collector"] = {}
                configs["splunk-otel-collector"]["splunk_access_token"] = SPLUNK_ACCESS_TOKEN
                configs["splunk-otel-collector"]["splunk_realm"] = SPLUNK_REALM
                configs["splunk-otel-collector"]["splunk_ingest_url"] = SPLUNK_INGEST_URL
                configs["splunk-otel-collector"]["splunk_api_url"] = SPLUNK_API_URL
                configs["splunk-otel-collector"]["splunk_service_user"] = SPLUNK_SERVICE_USER
                configs["splunk-otel-collector"]["splunk_service_group"] = SPLUNK_SERVICE_GROUP
                configs["splunk-otel-collector"]["with_fluentd"] = True
                configs["splunk-otel-collector"]["collector_version"] = collector_version
                run_chef_apply(container, configs, chef_version, CHEF_CMD)
                verify_env_file(container)
                assert wait_for(lambda: service_is_running(container))
                if "opensuse" not in distro:
                    assert container.exec_run("systemctl status td-agent").exit_code == 0
        finally:
            run_container_cmd(container, f"journalctl -u {SERVICE_NAME} --no-pager")
            if "opensuse" not in distro:
                run_container_cmd(container, "journalctl -u td-agent --no-pager")
                if container.exec_run("test -f /var/log/td-agent/td-agent.log").exit_code == 0:
                    run_container_cmd(container, "cat /var/log/td-agent/td-agent.log")

def run_win_chef_apply(container, configs, chef_version, CHEF_CMD):
    attributes_path = r"C:\\chef\\cookbooks\\"
    source_file = "C:\\attributes.json"
    with open(source_file, "w") as fd:
        print(json.dumps(configs))
        fd.write(json.dumps(configs))
        fd.flush()
        if chef_version == "latest" or int(chef_version.split(".")[0]) >= 15:
            CHEF_CMD += " --chef-license accept-silent"
        copy_file_into_win_container(container, source_file, attributes_path)
    CHEF_CMD = "powershell " + CHEF_CMD.format(attributes_path + "attributes.json")
    run_container_cmd(container, CHEF_CMD)

def verify_win_env(container):
    registry = r"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
    run_container_cmd(container, f"powershell \"Get-ItemPropertyValue -PATH '{registry}' -name 'SPLUNK_CONFIG' | FINDSTR '{WIN_SPLUNK_CONFIG}'\"")
    run_container_cmd(container, f"powershell \"Get-ItemPropertyValue -PATH '{registry}' -name 'SPLUNK_ACCESS_TOKEN' | FINDSTR '{SPLUNK_ACCESS_TOKEN}'\"")
    run_container_cmd(container, f"powershell \"Get-ItemPropertyValue -PATH '{registry}' -name 'SPLUNK_REALM' | FINDSTR '{SPLUNK_REALM}'\"")
    run_container_cmd(container, f"powershell \"Get-ItemPropertyValue -PATH '{registry}' -name 'SPLUNK_API_URL' | FINDSTR '{SPLUNK_API_URL}'\"")
    run_container_cmd(container, f"powershell \"Get-ItemPropertyValue -PATH '{registry}' -name 'SPLUNK_INGEST_URL' | FINDSTR '{SPLUNK_INGEST_URL}'\"")
    run_container_cmd(container, f"powershell \"Get-ItemPropertyValue -PATH '{registry}' -name 'SPLUNK_TRACE_URL' | FINDSTR '{SPLUNK_INGEST_URL}/v2/trace'\"")
    run_container_cmd(container, f"powershell \"Get-ItemPropertyValue -PATH '{registry}' -name 'SPLUNK_HEC_URL' | FINDSTR '{SPLUNK_INGEST_URL}/v1/log'\"")
    run_container_cmd(container, f"powershell \"Get-ItemPropertyValue -PATH '{registry}' -name 'SPLUNK_HEC_TOKEN' | FINDSTR '{SPLUNK_ACCESS_TOKEN}'\"")
    run_container_cmd(container, f"powershell \"Get-ItemPropertyValue -PATH '{registry}' -name 'SPLUNK_MEMORY_TOTAL_MIB' | FINDSTR '{SPLUNK_MEMORY_TOTAL_MIB}'\"")
    run_container_cmd(container, f"powershell \"Get-ItemPropertyValue -PATH '{registry}' -name 'SPLUNK_BUNDLE_DIR' | FINDSTR '{WIN_SPLUNK_BUNDLE_DIR}'\"")
    run_container_cmd(container, f"powershell \"Get-ItemPropertyValue -PATH '{registry}' -name 'SPLUNK_COLLECTD_DIR' | FINDSTR '{WIN_SPLUNK_COLLECTD_DIR}'\"")

@pytest.mark.parametrize(
    "distro", 
    [pytest.param("windows-server-2016", marks=pytest.mark.windows_2016)]
    + [pytest.param("windows-server-2019", marks=pytest.mark.windows_2019)]
    + [pytest.param("windows-server-2022", marks=pytest.mark.windows_2022)]
    )
@pytest.mark.parametrize("chef_version", CHEF_VERSIONS)
def test_chef_without_fluentd_on_windows(distro, chef_version):
    dockerfile = IMAGES_DIR / "windows" / f"Dockerfile.{distro}"
    with run_distro_container(distro, dockerfile=dockerfile, path=REPO_DIR) as container:
        try:
            for collector_version in ["0.34.0", "latest"]:
                configs = {}
                configs["splunk-otel-collector"] = {}
                configs["splunk-otel-collector"]["splunk_access_token"] = SPLUNK_ACCESS_TOKEN
                configs["splunk-otel-collector"]["splunk_realm"] = SPLUNK_REALM
                configs["splunk-otel-collector"]["splunk_ingest_url"] = SPLUNK_INGEST_URL
                configs["splunk-otel-collector"]["splunk_api_url"] = SPLUNK_API_URL
                configs["splunk-otel-collector"]["splunk_service_user"] = SPLUNK_SERVICE_USER
                configs["splunk-otel-collector"]["splunk_service_group"] = SPLUNK_SERVICE_GROUP
                configs["splunk-otel-collector"]["with_fluentd"] = False
                configs["splunk-otel-collector"]["collector_version"] = collector_version
                run_win_chef_apply(container, configs, chef_version, CHEF_CMD)
                verify_win_env(container)
                assert wait_for(lambda: service_is_running_win(container))
        finally:
            run_container_cmd(container, f"powershell \"Get-EventLog -LogName Application -Source '{SERVICE_NAME}' | Select -ExpandProperty Message\"")

@pytest.mark.parametrize(
    "distro", 
    [pytest.param("windows-server-2016", marks=pytest.mark.windows_2016)]
    + [pytest.param("windows-server-2019", marks=pytest.mark.windows_2019)]
    + [pytest.param("windows-server-2022", marks=pytest.mark.windows_2022)]
    )
@pytest.mark.parametrize("chef_version", CHEF_VERSIONS)
def test_chef_with_fluentd_on_windows(distro, chef_version):
    dockerfile = IMAGES_DIR / "windows" / f"Dockerfile.{distro}"
    with run_distro_container(distro, dockerfile=dockerfile, path=REPO_DIR) as container:
        try:
            for collector_version in ["0.34.0", "latest"]:
                configs = {}
                configs["splunk-otel-collector"] = {}
                configs["splunk-otel-collector"]["splunk_access_token"] = SPLUNK_ACCESS_TOKEN
                configs["splunk-otel-collector"]["splunk_realm"] = SPLUNK_REALM
                configs["splunk-otel-collector"]["splunk_ingest_url"] = SPLUNK_INGEST_URL
                configs["splunk-otel-collector"]["splunk_api_url"] = SPLUNK_API_URL
                configs["splunk-otel-collector"]["splunk_service_user"] = SPLUNK_SERVICE_USER
                configs["splunk-otel-collector"]["splunk_service_group"] = SPLUNK_SERVICE_GROUP
                configs["splunk-otel-collector"]["with_fluentd"] = True
                configs["splunk-otel-collector"]["collector_version"] = collector_version
                run_win_chef_apply(container, configs, chef_version, CHEF_CMD)
                verify_win_env(container)
                assert wait_for(lambda: service_is_running_win(container))
                assert wait_for(lambda: service_is_running_win(container, "fluentdwinsvc"))
        finally:
            run_container_cmd(container, f"powershell \"Get-EventLog -LogName Application -Source '{SERVICE_NAME}' | Select -ExpandProperty Message\"")
            if container.exec_run("powershell \"Test-Path -Path C:\\opt\\td-agent\\td-agent.log | FINDSTR True\"").exit_code == 0:
                run_container_cmd(container, "powershell \"Get-Content -Path C:\\opt\\td-agent\\td-agent.log\"")
