apt-get update && apt-get dist-upgrade -y
apt-get install -y --force-yes libz-dev

repository=$(mktemp -d)
git_clone repository=${GIT_REPOSITORY} branch=${GIT_BRANCH} commit=${GIT_COMMIT} directory=${repository}

install_python version=${python_version}

pyver="py${python_version%.*-ovh*}"
project_name=$(cd ${repository}; env SETUPTOOLS_USE_DISTUTILS=stdlib ${python_path}/bin/python setup.py --name 2>/dev/null)
project_version=$(git --git-dir="${repository}/.git" describe --abbrev=0)
package_name=${project_name}-${project_version}-${WORKFLOW_BUILD_TYPE}${WORKFLOW_RUN_NUMBER}-${pyver}
virtualenv_path=/opt/${package_name}
pypi_snapshot="20230831-21h42m08s"

export PKG_CONFIG_PATH=${python_path}/lib/pkgconfig

create_virtualenv python_path=${python_path} \
                  virtualenv_path=${virtualenv_path}

pip_install virtualenv_path=${virtualenv_path} \
            python_path=${python_path} \
            pypi_snapshot=${pypi_snapshot} \
            software_uri=${repository} \
            pre_requirements="
                numpy
                pika" \
            post_requirements="
                ceilometermiddleware
                keystonemiddleware
                git+ssh://git@stash.ovh.net:7999/cloudstoragepcs/swift-http-override@master#egg=swift_http_override
                git+ssh://git@stash.ovh.net:7999/cloudstoragepcs/swift-image-processing@master#egg=swift_image_processing
                git+ssh://git@stash.ovh.net:7999/cloudstoragepcs/swift-quotas@master#egg=quotas
                git+ssh://git@stash.ovh.net:7999/cloudstoragepcs/swift-traffic-shaping@master#egg=swift_traffic_shaping
                git+ssh://git@stash.ovh.net:7999/cloudstoragepcs/swift-account-enabled@master#egg=swift_account_enabled
                git+ssh://git@stash.ovh.net:7999/cloudstoragepcs/swift-fake-archive@master#egg=swift_fake_archive
                git+ssh://git@stash.ovh.net:7999/cloudstoragepcs/swift-endpoint-filter@master#egg=swift_endpoint_filter
                git+ssh://git@stash.ovh.net:7999/cloudstoragepcs/swift-headers4ceilometer@master#egg=swift_headers4ceilometer
                git+ssh://git@stash.ovh.net:7999/cloudstoragepcs/swift-sysmeta-region-id@master#egg=swift_sysmeta_region_id
                git+ssh://git@stash.ovh.net:7999/cloudstoragepcs/swift-etagquoter@master#egg=swift_etagquoter
                git+ssh://git@stash.ovh.net:7999/cloudstoragepcs/swift-headers-cleanup@master#egg=swift_headers_cleanup
                git+ssh://git@stash.ovh.net:7999/cloudstoragepcs/swift-logger-ltsv@master#egg=swift_logger_ltsv
                git+ssh://git@stash.ovh.net:7999/cloudstoragepcs/swift-deprecator@master#egg=swift_deprecator"


# Needed to help dpkg-shlibdeps find private libraries
export LD_LIBRARY_PATH=${python_path}/lib:${virtualenv_path}/lib/python${python_version%.*-ovh*}/site-packages/numpy.libs

# Build swift debian package
build_debian_package source_directory=${virtualenv_path} \
                     name=${package_name} \
                     architecture=amd64 \
                     version="1.0-$(lsb_release --short --codename)" \
                     priority=standard \
                     section=python

# Run test after building production package (running test install extra packages)
cd ${repository}
pip_install virtualenv_path=${virtualenv_path} \
            python_path=${python_path} \
            pypi_snapshot=${pypi_snapshot} \
            pre_requirements="${repository}/test-requirements.txt"

test_results_fname="test_${pyver:0:3}_results.xml"
test_coverage_fname="test_${pyver:0:3}_coverage.xml"
cat > pytest.ini <<EOF
[pytest]
testpaths = test/unit
addopts =  --cov-report xml:${test_coverage_fname} --cov --junitxml=${test_results_fname}
junit_suite_name = swift
junit_family = xunit2

EOF

test_cmd="pytest"

# By default stop workflow if some test failed
stop_on_error=1

(
    mkdir -p /var/cache/swift/
    # Because Swift tests call python binary. Remove after version 2.22+
    export PATH=${virtualenv_path}/bin:$PATH
    python_test virtualenv_path=${virtualenv_path} \
                software_path=${repository} \
                test_cmd="${test_cmd}" \
                test_results_fname="${test_results_fname}" \
                test_coverage_fname="${test_coverage_fname}" \
                stop_on_error=$stop_on_error
)

# Upload deb file in artifact (only if all test success)
artifact upload path=${debfile} tag=${WORKFLOW_RUN_NUMBER}:$(lsb_release --short --codename)
