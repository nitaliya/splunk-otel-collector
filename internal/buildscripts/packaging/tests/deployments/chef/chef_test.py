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
import subprocess
import shutil
import string
import tempfile
import sys
import winreg

from pathlib import Path

import pytest

from tests.helpers.util import (
    copy_file_into_container,
    run_container_cmd,
    run_distro_container,
    service_is_running,
    wait_for,
    has_choco,
    run_win_command,
    REPO_DIR,
    SERVICE_NAME,
    SERVICE_OWNER,
    WIN_REPO_ROOT_DIR,
)

WIN_CHEF_BIN_DIR = r"C:\opscode\chef\bin"
WIN_GEM_BIN_DIR = r"C:\opscode\chef\embedded\bin"
WIN_CHEF_COOKBOOKS_DIR = r"C:\chef\cookbooks"
WIN_COOKBOOK_SRC_DIR = os.path.join(WIN_REPO_ROOT_DIR, "deployments", "chef")
WIN_COOKBOOK_DEST_DIR = os.path.join(WIN_CHEF_COOKBOOKS_DIR, "splunk-otel-collector")
RUBYZIP_VERSION = "1.3.0"

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
WIN_SPLUNK_CONFIG = "C:\ProgramData\Splunk\OpenTelemetry Collector\agent_config.yaml"
WIN_SPLUNK_BUNDLE_DIR = "C:\Program Files\Splunk\OpenTelemetry Collector\agent-bundle'"

# allow CHEF_VERSIONS env var with comma-separated chef versions for test parameterization
# CHEF_VERSIONS = os.environ.get("CHEF_VERSIONS", "16.0.257,latest").split(",")
CHEF_VERSIONS = os.environ.get("CHEF_VERSIONS", "latest").split(",")

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

def run_win_chef_apply(configs, chef_version, CHEF_CMD):
    attributes_path = r"C:\chef\cookbooks\attributes.json"
    with open(attributes_path, "w+", encoding="utf-8") as fd:
        print(json.dumps(configs))
        fd.write(json.dumps(configs))
        fd.flush()
        if chef_version == "latest" or int(chef_version.split(".")[0]) >= 15:
            CHEF_CMD = CHEF_CMD.format(attributes_path) + " --chef-license accept-silent"
        else:
            CHEF_CMD = CHEF_CMD.format(attributes_path)
        print('running "%s" ...' % CHEF_CMD)
        proc = subprocess.run(
            CHEF_CMD,
            cwd=r"C:\chef\cookbooks",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            close_fds=False,
            check=False,
        )
        output = proc.stdout.decode("utf-8")
        assert proc.returncode == 0, output
        print(output)

def verify_win_reg(access_key, name, value):
    value_ , regtype = winreg.QueryValueEx(access_key, name)
    assert value_ == value

def verify_win_env():
    access_registry = winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE)
    access_key = winreg.OpenKey(access_registry, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")

    verify_win_reg(access_key, "SPLUNK_CONFIG", WIN_SPLUNK_CONFIG)
    verify_win_reg(access_key, "SPLUNK_ACCESS_TOKEN", SPLUNK_ACCESS_TOKEN)
    verify_win_reg(access_key, "SPLUNK_REALM", SPLUNK_REALM)
    verify_win_reg(access_key, "SPLUNK_API_URL", SPLUNK_API_URL)
    verify_win_reg(access_key, "SPLUNK_INGEST_URL", SPLUNK_INGEST_URL)
    verify_win_reg(access_key, "SPLUNK_TRACE_URL", "{SPLUNK_INGEST_URL}/v2/trace")
    verify_win_reg(access_key, "SPLUNK_HEC_URL", "{SPLUNK_INGEST_URL}/v1/log")
    verify_win_reg(access_key, "SPLUNK_HEC_TOKEN", SPLUNK_ACCESS_TOKEN)
    verify_win_reg(access_key, "SPLUNK_MEMORY_TOTAL_MIB", SPLUNK_MEMORY_TOTAL_MIB)
    verify_win_reg(access_key, "SPLUNK_BUNDLE_DIR", WIN_SPLUNK_BUNDLE_DIR)
    verify_win_reg(access_key, "SPLUNK_COLLECTD_DIR", SPLUNK_COLLECTD_DIR)

def run_win_chef_setup(chef_version):
    assert has_choco(), "choco not installed!"
    if run_win_command("chef-client --version", []).returncode == 0:
        run_win_command("choco uninstall -y -f chef-client")
    if chef_version == "latest":
        run_win_command(f"choco upgrade -y -f chef-client")
    else:
        run_win_command(f"choco upgrade -y -f chef-client --version {chef_version}")
    if WIN_CHEF_BIN_DIR not in os.environ.get("PATH"):
        os.environ["PATH"] = WIN_CHEF_BIN_DIR + ";" + os.environ.get("PATH")
    if WIN_GEM_BIN_DIR not in os.environ.get("PATH"):
        os.environ["PATH"] = WIN_GEM_BIN_DIR + ";" + os.environ.get("PATH")
    os.makedirs(WIN_CHEF_COOKBOOKS_DIR, exist_ok=True)
    if os.path.isdir(WIN_COOKBOOK_DEST_DIR):
        shutil.rmtree(WIN_COOKBOOK_DEST_DIR)
    shutil.copytree(WIN_COOKBOOK_SRC_DIR, WIN_COOKBOOK_DEST_DIR)
    run_win_command(f'powershell -command "gem install rubyzip -q -v "{RUBYZIP_VERSION}""')

@pytest.mark.windows_only
@pytest.mark.skipif(sys.platform != "win32", reason="only runs on windows")
@pytest.mark.parametrize("chef_version", CHEF_VERSIONS)
def test_chef_with_fluentd_on_windows(chef_version):
    run_win_chef_setup(chef_version)
    try:
        # for collector_version in ["0.34.0", "latest"]:
        for collector_version in ["latest"]:
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
            run_win_chef_apply(configs, chef_version, CHEF_CMD)
            verify_win_env()
    finally:
        print("Done")
