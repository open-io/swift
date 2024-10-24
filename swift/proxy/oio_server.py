# Copyright (c) 2016-2023 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import multiprocessing
import swift.common.utils
import swift.proxy.server
from swift.common import request_helpers, storage_policy
from swift.common.ring import FakeRing
from swift.common.storage_policy import OIO_POLICIES
from swift.proxy.controllers.oio.account import AccountController
from swift.proxy.controllers.oio.container import ContainerController
from swift.proxy.controllers.oio.obj import ObjectControllerRouter
from swift.proxy.server import Application as SwiftApplication
from swift.common.utils import config_auto_int_value, config_true_value, \
    parse_auto_storage_policies

from oio import ObjectStorageApi


RING_ARGS = [
    {'replicas': 1}
]


swift.proxy.server.POLICIES = OIO_POLICIES
swift.proxy.server.AccountController = AccountController
swift.proxy.server.ContainerController = ContainerController
swift.proxy.server.ObjectControllerRouter = ObjectControllerRouter

request_helpers.SegmentedIterable = request_helpers.SafeSegmentedIterable

swift.common.utils.validate_hash_conf = lambda: None


class Application(SwiftApplication):
    def __init__(self, conf, logger=None, account_ring=None,
                 container_ring=None, storage=None):
        for policy, ring_arg in zip(OIO_POLICIES, RING_ARGS):
            if ring_arg is not None:
                policy.object_ring = FakeRing(**ring_arg)

        SwiftApplication.__init__(self, conf, logger=logger,
                                  account_ring=account_ring,
                                  container_ring=container_ring)
        if conf is None:
            conf = {}
        sds_conf = {k[4:]: v
                    for k, v in conf.items()
                    if k.startswith("sds_")}

        if 'disallowed_sections' not in conf:
            # object_versioning.is_valid_version_id is a function
            self.disallowed_sections.append(
                'object_versioning.is_valid_version_id')

        self.auto_storage_policies = parse_auto_storage_policies(
            conf.get('auto_storage_policies'))

        policies = []
        if 'oio_storage_policies' in conf:
            for i, pol in enumerate(conf['oio_storage_policies'].split(',')):
                policies.append(
                    storage_policy.StoragePolicy(i, pol, is_default=i == 0))
        else:
            policies.append(storage_policy.StoragePolicy(0, 'SINGLE', True))

        self.POLICIES = storage_policy.StoragePolicyCollection(policies)

        # Mandatory, raises KeyError
        sds_namespace = sds_conf['namespace']
        sds_conf.pop('namespace')  # removed to avoid unpacking conflict
        # Loaded by ObjectStorageApi if None
        sds_proxy_url = sds_conf.pop('proxy_url', None)
        # Fix boolean parameter
        sds_conf['autocreate'] = config_true_value(
            sds_conf.get('autocreate', 'true'))
        # Fix parameter key, cast from str to int
        sds_conf['refresh_delay'] = config_auto_int_value(
            sds_conf.pop('endpoint_refresh_delay', None), 60)

        # NOTE(FVE): passing self.logger is different from passing just logger.
        # If logger is None, self.logger will be properly instantiated by the
        # constructor of the parent class.
        self.storage = storage or \
            ObjectStorageApi(sds_namespace, endpoint=sds_proxy_url,
                             logger=self.logger, **sds_conf)
        self.delete_slo_parts = \
            config_true_value(conf.get('delete_slo_parts', True))
        self.check_state = \
            config_true_value(conf.get('check_state', False))


def global_conf_callback(preloaded_app_conf, global_conf):
    """
    Callback for swift.common.wsgi.run_wsgi during the global_conf
    creation so that we can add our shared memory manager.

    :param preloaded_app_conf: The preloaded conf for the WSGI app.
                               This conf instance will go away, so
                               just read from it, don't write.
    :param global_conf: The global conf that will eventually be
                        passed to the app_factory function later.
                        This conf is created before the worker
                        subprocesses are forked, so can be useful to
                        set up semaphores, shared memory, etc.
    """
    global_conf['oioswift_counters'] = {
        'current_requests': multiprocessing.Value('i', 0),
    }


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    account_ring = FakeRing()
    container_ring = FakeRing()
    app = Application(conf, account_ring=account_ring,
                      container_ring=container_ring)
    app.check_config()
    return app
