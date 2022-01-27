#
# Cookbook:: splunk-otel-collector
# Recipe:: fluentd_deb_repo
#
# Copyright:: 2021, The Authors, All Rights Reserved.

package %w(build-essential libcap-ng0 libcap-ng-dev pkg-config)

td_agent_major_version = node['splunk-otel-collector']['fluentd_version'].split('.')[0]
codename = node['lsb']['codename']
distro = node['platform']

apt_repository 'treasure-data' do
  uri "#{node['splunk-otel-collector']['fluentd_base_url']}/#{td_agent_major_version}/#{distro}/#{codename}"
  arch 'amd64'
  distribution codename
  components ['contrib']
  key "#{node['splunk-otel-collector']['fluentd_base_url']}/GPG-KEY-td-agent"
  action :add
end