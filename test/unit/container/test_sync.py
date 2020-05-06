
# Copyright (c) 2010-2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import unittest
from textwrap import dedent

import mock
import errno
from swift.common.utils import Timestamp, readconf
from test.debug_logger import debug_logger
from swift.container import sync
from swift.common.db import DatabaseConnectionError
from swift.common import utils
from swift.common.wsgi import ConfigString
from swift.common.exceptions import ClientException
from swift.common.storage_policy import StoragePolicy
import test
from test.unit import patch_policies, with_tempdir
import json
import pika
from pika.exceptions import AMQPError
from eventlet import kill


class FakeRing(object):

    def __init__(self):
        self.devs = [{'ip': '10.0.0.%s' % x, 'port': 1000 + x, 'device': 'sda'}
                     for x in range(3)]

    def get_nodes(self, account, container=None, obj=None):
        return 1, list(self.devs)


class FakeContainerBroker(object):

    def __init__(self, path, metadata=None, info=None, deleted=False,
                 items_since=None):
        self.db_file = path
        self.db_dir = os.path.dirname(path)
        self.metadata = metadata if metadata else {}
        self.info = info if info else {}
        self.deleted = deleted
        self.items_since = items_since if items_since else []
        self.sync_point1 = -1
        self.sync_point2 = -1

    def get_max_row(self):
        return 1

    def get_info(self):
        return self.info

    def is_deleted(self):
        return self.deleted

    def get_items_since(self, sync_point, limit):
        if sync_point < 0:
            sync_point = 0
        return self.items_since[sync_point:sync_point + limit]

    def set_x_container_sync_points(self, sync_point1, sync_point2):
        self.sync_point1 = sync_point1
        self.sync_point2 = sync_point2


@patch_policies([StoragePolicy(0, 'zero', True, object_ring=FakeRing())])
class TestContainerSync(unittest.TestCase):

    def setUp(self):
        self.logger = debug_logger('test-container-sync')
        utils.HASH_PATH_SUFFIX = b'endcap'
        utils.HASH_PATH_PREFIX = b'endcap'

    def test_FileLikeIter(self):
        # Retained test to show new FileLikeIter acts just like the removed
        # _Iter2FileLikeObject did.
        flo = sync.FileLikeIter(iter([b'123', b'4567', b'89', b'0']))
        expect = b'1234567890'

        got = flo.read(2)
        self.assertTrue(len(got) <= 2)
        self.assertEqual(got, expect[:len(got)])
        expect = expect[len(got):]

        got = flo.read(5)
        self.assertTrue(len(got) <= 5)
        self.assertEqual(got, expect[:len(got)])
        expect = expect[len(got):]

        self.assertEqual(flo.read(), expect)
        self.assertEqual(flo.read(), b'')
        self.assertEqual(flo.read(2), b'')

        flo = sync.FileLikeIter(iter([b'123', b'4567', b'89', b'0']))
        self.assertEqual(flo.read(), b'1234567890')
        self.assertEqual(flo.read(), b'')
        self.assertEqual(flo.read(2), b'')

    def assertLogMessage(self, msg_level, expected, skip=0):
        for line in self.logger.get_lines_for_level(msg_level)[skip:]:
            msg = 'expected %r not in %r' % (expected, line)
            self.assertTrue(expected in line, msg)

    @with_tempdir
    def test_init(self, tempdir):
        ic_conf_path = os.path.join(tempdir, 'internal-client.conf')
        cring = FakeRing()

        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync({}, container_ring=cring)
        self.assertTrue(cs.container_ring is cring)

        # specified but not exists will not start
        conf = {'internal_client_conf_path': ic_conf_path}
        self.assertRaises(SystemExit, sync.ContainerSync, conf,
                          container_ring=cring, logger=self.logger)

        # not specified will use default conf
        with mock.patch('swift.container.sync.InternalClient') as mock_ic:
            cs = sync.ContainerSync({}, container_ring=cring,
                                    logger=self.logger)
        self.assertTrue(cs.container_ring is cring)
        self.assertTrue(mock_ic.called)
        conf_path, name, retry = mock_ic.call_args[0]
        self.assertTrue(isinstance(conf_path, ConfigString))
        self.assertEqual(conf_path.contents.getvalue(),
                         dedent(sync.ic_conf_body))
        self.assertLogMessage('warning', 'internal_client_conf_path')
        self.assertLogMessage('warning', 'internal-client.conf-sample')

        # correct
        contents = dedent(sync.ic_conf_body)
        with open(ic_conf_path, 'w') as f:
            f.write(contents)
        with mock.patch('swift.container.sync.InternalClient') as mock_ic:
            cs = sync.ContainerSync(conf, container_ring=cring)
        self.assertTrue(cs.container_ring is cring)
        self.assertTrue(mock_ic.called)
        conf_path, name, retry = mock_ic.call_args[0]
        self.assertEqual(conf_path, ic_conf_path)

        sample_conf_filename = os.path.join(
            os.path.dirname(test.__file__),
            '../etc/internal-client.conf-sample')
        actual_conf = readconf(ConfigString(contents))
        expected_conf = readconf(sample_conf_filename)
        actual_conf.pop('__file__')
        expected_conf.pop('__file__')
        self.assertEqual(expected_conf, actual_conf)

    def test_init_internal_client_log_name(self):
        def _do_test_init_ic_log_name(conf, exp_internal_client_log_name):
            with mock.patch(
                    'swift.container.sync.InternalClient') \
                    as mock_ic:
                sync.ContainerSync(conf, container_ring='dummy object')
            mock_ic.assert_called_once_with(
                'conf-path',
                'Swift Container Sync', 3,
                global_conf={'log_name': exp_internal_client_log_name},
                use_replication_network=True)

        _do_test_init_ic_log_name({'internal_client_conf_path': 'conf-path'},
                                  'container-sync-ic')
        _do_test_init_ic_log_name({'internal_client_conf_path': 'conf-path',
                                   'log_name': 'my-container-sync'},
                                  'my-container-sync-ic')

    def test_run_forever(self):
        # This runs runs_forever with fakes to succeed for two loops, the first
        # causing a report but no interval sleep, the second no report but an
        # interval sleep.
        time_calls = [0]
        sleep_calls = []

        def fake_time():
            time_calls[0] += 1
            returns = [1,     # Initialized reported time
                       1,     # Start time
                       3602,  # Is it report time (yes)
                       3602,  # Report time
                       3602,  # Elapsed time for "under interval" (no)
                       3602,  # Start time
                       3603,  # Is it report time (no)
                       3603]  # Elapsed time for "under interval" (yes)
            if time_calls[0] == len(returns) + 1:
                raise Exception('we are now done')
            return returns[time_calls[0] - 1]

        def fake_sleep(amount):
            sleep_calls.append(amount)

        gen_func = ('swift.container.sync_store.'
                    'ContainerSyncStore.synced_containers_generator')
        with mock.patch('swift.container.sync.InternalClient'), \
                mock.patch('swift.container.sync.time', fake_time), \
                mock.patch('swift.container.sync.sleep', fake_sleep), \
                mock.patch(gen_func) as fake_generator, \
                mock.patch('swift.container.sync.ContainerBroker',
                           lambda p, logger: FakeContainerBroker(p, info={
                               'account': 'a', 'container': 'c',
                               'storage_policy_index': 0})):
            fake_generator.side_effect = [iter(['container.db']),
                                          iter(['container.db'])]
            cs = sync.ContainerSync({}, container_ring=FakeRing())
            try:
                cs.run_forever()
            except Exception as err:
                if str(err) != 'we are now done':
                    raise

            self.assertEqual(time_calls, [9])
            self.assertEqual(len(sleep_calls), 2)
            self.assertLessEqual(sleep_calls[0], cs.interval)
            self.assertEqual(cs.interval - 1, sleep_calls[1])
            self.assertEqual(2, fake_generator.call_count)
            self.assertEqual(cs.reported, 3602)

    def test_run_once(self):
        # This runs runs_once with fakes twice, the first causing an interim
        # report, the second with no interim report.
        time_calls = [0]

        def fake_time():
            time_calls[0] += 1
            returns = [1,     # Initialized reported time
                       1,     # Start time
                       3602,  # Is it report time (yes)
                       3602,  # Report time
                       3602,  # End report time
                       3602,  # For elapsed
                       3602,  # Start time
                       3603,  # Is it report time (no)
                       3604,  # End report time
                       3605]  # For elapsed
            if time_calls[0] == len(returns) + 1:
                raise Exception('we are now done')
            return returns[time_calls[0] - 1]

        gen_func = ('swift.container.sync_store.'
                    'ContainerSyncStore.synced_containers_generator')
        with mock.patch('swift.container.sync.InternalClient'), \
                mock.patch('swift.container.sync.time', fake_time), \
                mock.patch(gen_func) as fake_generator, \
                mock.patch('swift.container.sync.ContainerBroker',
                           lambda p, logger: FakeContainerBroker(p, info={
                               'account': 'a', 'container': 'c',
                               'storage_policy_index': 0})):
            fake_generator.side_effect = [iter(['container.db']),
                                          iter(['container.db'])]
            cs = sync.ContainerSync({}, container_ring=FakeRing())
            try:
                cs.run_once()
                self.assertEqual(time_calls, [6])
                self.assertEqual(1, fake_generator.call_count)
                self.assertEqual(cs.reported, 3602)
                cs.run_once()
            except Exception as err:
                if str(err) != 'we are now done':
                    raise

            self.assertEqual(time_calls, [10])
            self.assertEqual(2, fake_generator.call_count)
            self.assertEqual(cs.reported, 3604)

    def test_container_sync_not_db(self):
        cring = FakeRing()
        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync({}, container_ring=cring)
        self.assertEqual(cs.container_failures, 0)

    def test_container_sync_missing_db(self):
        cring = FakeRing()
        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync({}, container_ring=cring)

        broker = 'swift.container.backend.ContainerBroker'
        store = 'swift.container.sync_store.ContainerSyncStore'

        # In this test we call the container_sync instance several
        # times with a missing db in various combinations.
        # Since we use the same ContainerSync instance for all tests
        # its failures counter increases by one with each call.

        # Test the case where get_info returns DatabaseConnectionError
        # with DB does not exist, and we succeed in deleting it.
        with mock.patch(broker + '.get_info') as fake_get_info:
            with mock.patch(store + '.remove_synced_container') as fake_remove:
                fake_get_info.side_effect = DatabaseConnectionError(
                    'a',
                    "DB doesn't exist")
                cs.container_sync('isa.db')
                self.assertEqual(cs.container_failures, 1)
                self.assertEqual(cs.container_skips, 0)
                self.assertEqual(1, fake_remove.call_count)
                self.assertEqual('isa.db', fake_remove.call_args[0][0].db_file)

        # Test the case where get_info returns DatabaseConnectionError
        # with DB does not exist, and we fail to delete it.
        with mock.patch(broker + '.get_info') as fake_get_info:
            with mock.patch(store + '.remove_synced_container') as fake_remove:
                fake_get_info.side_effect = DatabaseConnectionError(
                    'a',
                    "DB doesn't exist")
                fake_remove.side_effect = OSError('1')
                cs.container_sync('isa.db')
                self.assertEqual(cs.container_failures, 2)
                self.assertEqual(cs.container_skips, 0)
                self.assertEqual(1, fake_remove.call_count)
                self.assertEqual('isa.db', fake_remove.call_args[0][0].db_file)

        # Test the case where get_info returns DatabaseConnectionError
        # with DB does not exist, and it returns an error != ENOENT.
        with mock.patch(broker + '.get_info') as fake_get_info:
            with mock.patch(store + '.remove_synced_container') as fake_remove:
                fake_get_info.side_effect = DatabaseConnectionError(
                    'a',
                    "DB doesn't exist")
                fake_remove.side_effect = OSError(errno.EPERM, 'a')
                cs.container_sync('isa.db')
                self.assertEqual(cs.container_failures, 3)
                self.assertEqual(cs.container_skips, 0)
                self.assertEqual(1, fake_remove.call_count)
                self.assertEqual('isa.db', fake_remove.call_args[0][0].db_file)

        # Test the case where get_info returns DatabaseConnectionError
        # error different than DB does not exist
        with mock.patch(broker + '.get_info') as fake_get_info:
            with mock.patch(store + '.remove_synced_container') as fake_remove:
                fake_get_info.side_effect = DatabaseConnectionError('a', 'a')
                cs.container_sync('isa.db')
                self.assertEqual(cs.container_failures, 4)
                self.assertEqual(cs.container_skips, 0)
                self.assertEqual(0, fake_remove.call_count)

    def test_container_sync_not_my_db(self):
        # Db could be there due to handoff replication so test that we ignore
        # those.
        cring = FakeRing()
        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync({
                'bind_ip': '10.0.0.0',
            }, container_ring=cring)
            # Plumbing test for bind_ip and whataremyips()
            self.assertEqual(['10.0.0.0'], cs._myips)
        orig_ContainerBroker = sync.ContainerBroker
        try:
            sync.ContainerBroker = lambda p, logger: FakeContainerBroker(
                p, info={'account': 'a', 'container': 'c',
                         'storage_policy_index': 0})
            cs._myips = ['127.0.0.1']   # No match
            cs._myport = 1              # No match
            cs.container_sync('isa.db')
            self.assertEqual(cs.container_failures, 0)

            cs._myips = ['10.0.0.0']    # Match
            cs._myport = 1              # No match
            cs.container_sync('isa.db')
            self.assertEqual(cs.container_failures, 0)

            cs._myips = ['127.0.0.1']   # No match
            cs._myport = 1000           # Match
            cs.container_sync('isa.db')
            self.assertEqual(cs.container_failures, 0)

            cs._myips = ['10.0.0.0']    # Match
            cs._myport = 1000           # Match
            # This complete match will cause the 1 container failure since the
            # broker's info doesn't contain sync point keys
            cs.container_sync('isa.db')
            self.assertEqual(cs.container_failures, 1)
        finally:
            sync.ContainerBroker = orig_ContainerBroker

    def test_container_sync_deleted(self):
        cring = FakeRing()
        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync({}, container_ring=cring)
        orig_ContainerBroker = sync.ContainerBroker
        try:
            sync.ContainerBroker = lambda p, logger: FakeContainerBroker(
                p, info={'account': 'a', 'container': 'c',
                         'storage_policy_index': 0}, deleted=False)
            cs._myips = ['10.0.0.0']    # Match
            cs._myport = 1000           # Match
            # This complete match will cause the 1 container failure since the
            # broker's info doesn't contain sync point keys
            cs.container_sync('isa.db')
            self.assertEqual(cs.container_failures, 1)

            sync.ContainerBroker = lambda p, logger: FakeContainerBroker(
                p, info={'account': 'a', 'container': 'c',
                         'storage_policy_index': 0}, deleted=True)
            # This complete match will not cause any more container failures
            # since the broker indicates deletion
            cs.container_sync('isa.db')
            self.assertEqual(cs.container_failures, 1)
        finally:
            sync.ContainerBroker = orig_ContainerBroker

    def test_container_sync_no_to_or_key(self):
        cring = FakeRing()
        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync({}, container_ring=cring)
        orig_ContainerBroker = sync.ContainerBroker
        try:
            sync.ContainerBroker = lambda p, logger: FakeContainerBroker(
                p, info={'account': 'a', 'container': 'c',
                         'storage_policy_index': 0,
                         'x_container_sync_point1': -1,
                         'x_container_sync_point2': -1})
            cs._myips = ['10.0.0.0']    # Match
            cs._myport = 1000           # Match
            # This complete match will be skipped since the broker's metadata
            # has no x-container-sync-to or x-container-sync-key
            cs.container_sync('isa.db')
            self.assertEqual(cs.container_failures, 0)
            self.assertEqual(cs.container_skips, 1)

            sync.ContainerBroker = lambda p, logger: FakeContainerBroker(
                p, info={'account': 'a', 'container': 'c',
                         'storage_policy_index': 0,
                         'x_container_sync_point1': -1,
                         'x_container_sync_point2': -1},
                metadata={'x-container-sync-to': ('http://127.0.0.1/a/c', 1)})
            cs._myips = ['10.0.0.0']    # Match
            cs._myport = 1000           # Match
            # This complete match will be skipped since the broker's metadata
            # has no x-container-sync-key
            cs.container_sync('isa.db')
            self.assertEqual(cs.container_failures, 0)
            self.assertEqual(cs.container_skips, 2)

            sync.ContainerBroker = lambda p, logger: FakeContainerBroker(
                p, info={'account': 'a', 'container': 'c',
                         'storage_policy_index': 0,
                         'x_container_sync_point1': -1,
                         'x_container_sync_point2': -1},
                metadata={'x-container-sync-key': ('key', 1)})
            cs._myips = ['10.0.0.0']    # Match
            cs._myport = 1000           # Match
            # This complete match will be skipped since the broker's metadata
            # has no x-container-sync-to
            cs.container_sync('isa.db')
            self.assertEqual(cs.container_failures, 0)
            self.assertEqual(cs.container_skips, 3)

            sync.ContainerBroker = lambda p, logger: FakeContainerBroker(
                p, info={'account': 'a', 'container': 'c',
                         'storage_policy_index': 0,
                         'x_container_sync_point1': -1,
                         'x_container_sync_point2': -1},
                metadata={'x-container-sync-to': ('http://127.0.0.1/a/c', 1),
                          'x-container-sync-key': ('key', 1)})
            cs._myips = ['10.0.0.0']    # Match
            cs._myport = 1000           # Match
            cs.allowed_sync_hosts = []
            # This complete match will cause a container failure since the
            # sync-to won't validate as allowed.
            cs.container_sync('isa.db')
            self.assertEqual(cs.container_failures, 1)
            self.assertEqual(cs.container_skips, 3)

            sync.ContainerBroker = lambda p, logger: FakeContainerBroker(
                p, info={'account': 'a', 'container': 'c',
                         'storage_policy_index': 0,
                         'x_container_sync_point1': -1,
                         'x_container_sync_point2': -1},
                metadata={'x-container-sync-to': ('http://127.0.0.1/a/c', 1),
                          'x-container-sync-key': ('key', 1)})
            cs._myips = ['10.0.0.0']    # Match
            cs._myport = 1000           # Match
            cs.allowed_sync_hosts = ['127.0.0.1']
            # This complete match will succeed completely since the broker
            # get_items_since will return no new rows.
            cs.container_sync('isa.db')
            self.assertEqual(cs.container_failures, 1)
            self.assertEqual(cs.container_skips, 3)
        finally:
            sync.ContainerBroker = orig_ContainerBroker

    def test_container_stop_at(self):
        cring = FakeRing()
        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync({}, container_ring=cring)
        orig_ContainerBroker = sync.ContainerBroker
        orig_time = sync.time
        try:
            sync.ContainerBroker = lambda p, logger: FakeContainerBroker(
                p, info={'account': 'a', 'container': 'c',
                         'storage_policy_index': 0,
                         'x_container_sync_point1': -1,
                         'x_container_sync_point2': -1},
                metadata={'x-container-sync-to': ('http://127.0.0.1/a/c', 1),
                          'x-container-sync-key': ('key', 1)},
                items_since=['erroneous data'])
            cs._myips = ['10.0.0.0']    # Match
            cs._myport = 1000           # Match
            cs.allowed_sync_hosts = ['127.0.0.1']
            # This sync will fail since the items_since data is bad.
            cs.container_sync('isa.db')
            self.assertEqual(cs.container_failures, 1)
            self.assertEqual(cs.container_skips, 0)

            # Set up fake times to make the sync short-circuit as having taken
            # too long
            fake_times = [
                1.0,        # Compute the time to move on
                100000.0,   # Compute if it's time to move on from first loop
                100000.0]   # Compute if it's time to move on from second loop

            def fake_time():
                return fake_times.pop(0)

            sync.time = fake_time
            # This same sync won't fail since it will look like it took so long
            # as to be time to move on (before it ever actually tries to do
            # anything).
            cs.container_sync('isa.db')
            self.assertEqual(cs.container_failures, 1)
            self.assertEqual(cs.container_skips, 0)
        finally:
            sync.ContainerBroker = orig_ContainerBroker
            sync.time = orig_time

    def test_container_first_loop(self):
        cring = FakeRing()
        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync({}, container_ring=cring)

        def fake_hash_path(account, container, obj, raw_digest=False):
            # Ensures that no rows match for full syncing, ordinal is 0 and
            # all hashes are 0
            return '\x00' * 16
        fcb = FakeContainerBroker(
            'path',
            info={'account': 'a', 'container': 'c',
                  'storage_policy_index': 0,
                  'x_container_sync_point1': 2,
                  'x_container_sync_point2': -1},
            metadata={'x-container-sync-to': ('http://127.0.0.1/a/c', 1),
                      'x-container-sync-key': ('key', 1)},
            items_since=[{'ROWID': 1, 'name': 'o'}])
        with mock.patch('swift.container.sync.ContainerBroker',
                        lambda p, logger: fcb), \
                mock.patch('swift.container.sync.hash_path', fake_hash_path):
            cs._myips = ['10.0.0.0']    # Match
            cs._myport = 1000           # Match
            cs.allowed_sync_hosts = ['127.0.0.1']
            cs.container_sync('isa.db')
            # Succeeds because no rows match
            self.assertEqual(cs.container_failures, 1)
            self.assertEqual(cs.container_skips, 0)
            self.assertIsNone(fcb.sync_point1)
            self.assertEqual(fcb.sync_point2, -1)

        def fake_hash_path(account, container, obj, raw_digest=False):
            # Ensures that all rows match for full syncing, ordinal is 0
            # and all hashes are 1
            return '\x01' * 16
        fcb = FakeContainerBroker('path', info={'account': 'a',
                                                'container': 'c',
                                                'storage_policy_index': 0,
                                                'x_container_sync_point1': 1,
                                                'x_container_sync_point2': 1},
                                  metadata={'x-container-sync-to':
                                            ('http://127.0.0.1/a/c', 1),
                                            'x-container-sync-key':
                                            ('key', 1)},
                                  items_since=[{'ROWID': 1, 'name': 'o'}])
        with mock.patch('swift.container.sync.ContainerBroker',
                        lambda p, logger: fcb), \
                mock.patch('swift.container.sync.hash_path', fake_hash_path):
            cs._myips = ['10.0.0.0']    # Match
            cs._myport = 1000           # Match
            cs.allowed_sync_hosts = ['127.0.0.1']
            cs.container_sync('isa.db')
            # Succeeds because the two sync points haven't deviated yet
            self.assertEqual(cs.container_failures, 1)
            self.assertEqual(cs.container_skips, 0)
            self.assertEqual(fcb.sync_point1, -1)
            self.assertEqual(fcb.sync_point2, -1)

        fcb = FakeContainerBroker(
            'path',
            info={'account': 'a', 'container': 'c',
                  'storage_policy_index': 0,
                  'x_container_sync_point1': 2,
                  'x_container_sync_point2': -1},
            metadata={'x-container-sync-to': ('http://127.0.0.1/a/c', 1),
                      'x-container-sync-key': ('key', 1)},
            items_since=[{'ROWID': 1, 'name': 'o'}])
        with mock.patch('swift.container.sync.ContainerBroker',
                        lambda p, logger: fcb):
            cs._myips = ['10.0.0.0']    # Match
            cs._myport = 1000           # Match
            cs.allowed_sync_hosts = ['127.0.0.1']
            cs.container_sync('isa.db')
            # Fails because container_sync_row will fail since the row has no
            # 'deleted' key
            self.assertEqual(cs.container_failures, 2)
            self.assertEqual(cs.container_skips, 0)
            self.assertIsNone(fcb.sync_point1)
            self.assertEqual(fcb.sync_point2, -1)

        def fake_delete_object(*args, **kwargs):
            raise ClientException
        fcb = FakeContainerBroker(
            'path',
            info={'account': 'a', 'container': 'c',
                  'storage_policy_index': 0,
                  'x_container_sync_point1': 2,
                  'x_container_sync_point2': -1},
            metadata={'x-container-sync-to': ('http://127.0.0.1/a/c', 1),
                      'x-container-sync-key': ('key', 1)},
            items_since=[{'ROWID': 1, 'name': 'o', 'created_at': '1.2',
                          'deleted': True}])
        with mock.patch('swift.container.sync.ContainerBroker',
                        lambda p, logger: fcb), \
                mock.patch('swift.container.sync.delete_object',
                           fake_delete_object):
            cs._myips = ['10.0.0.0']    # Match
            cs._myport = 1000           # Match
            cs.allowed_sync_hosts = ['127.0.0.1']
            cs.container_sync('isa.db')
            # Fails because delete_object fails
            self.assertEqual(cs.container_failures, 3)
            self.assertEqual(cs.container_skips, 0)
            self.assertIsNone(fcb.sync_point1)
            self.assertEqual(fcb.sync_point2, -1)

        fcb = FakeContainerBroker(
            'path',
            info={'account': 'a', 'container': 'c',
                  'storage_policy_index': 0,
                  'x_container_sync_point1': 2,
                  'x_container_sync_point2': -1},
            metadata={'x-container-sync-to': ('http://127.0.0.1/a/c', 1),
                      'x-container-sync-key': ('key', 1)},
            items_since=[{'ROWID': 1, 'name': 'o', 'created_at': '1.2',
                          'deleted': True}])
        with mock.patch('swift.container.sync.ContainerBroker',
                        lambda p, logger: fcb), \
                mock.patch('swift.container.sync.delete_object',
                           lambda *x, **y: None):
            cs._myips = ['10.0.0.0']    # Match
            cs._myport = 1000           # Match
            cs.allowed_sync_hosts = ['127.0.0.1']
            cs.container_sync('isa.db')
            # Succeeds because delete_object succeeds
            self.assertEqual(cs.container_failures, 3)
            self.assertEqual(cs.container_skips, 0)
            self.assertIsNone(fcb.sync_point1)
            self.assertEqual(fcb.sync_point2, 1)

    def test_container_second_loop(self):
        cring = FakeRing()
        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync({}, container_ring=cring,
                                    logger=self.logger)
        orig_ContainerBroker = sync.ContainerBroker
        orig_hash_path = sync.hash_path
        orig_delete_object = sync.delete_object
        try:
            # We'll ensure the first loop is always skipped by keeping the two
            # sync points equal

            def fake_hash_path(account, container, obj, raw_digest=False):
                # Ensures that no rows match for second loop, ordinal is 0 and
                # all hashes are 1
                return b'\x01' * 16

            sync.hash_path = fake_hash_path
            fcb = FakeContainerBroker(
                'path',
                info={'account': 'a', 'container': 'c',
                      'storage_policy_index': 0,
                      'x_container_sync_point1': -1,
                      'x_container_sync_point2': -1},
                metadata={'x-container-sync-to': ('http://127.0.0.1/a/c', 1),
                          'x-container-sync-key': ('key', 1)},
                items_since=[{'ROWID': 1, 'name': 'o'}])
            sync.ContainerBroker = lambda p, logger: fcb
            cs._myips = ['10.0.0.0']    # Match
            cs._myport = 1000           # Match
            cs.allowed_sync_hosts = ['127.0.0.1']
            cs.container_sync('isa.db')
            # Succeeds because no rows match
            self.assertEqual(cs.container_failures, 0)
            self.assertEqual(cs.container_skips, 0)
            self.assertEqual(fcb.sync_point1, 1)
            self.assertIsNone(fcb.sync_point2)

            def fake_hash_path(account, container, obj, raw_digest=False):
                # Ensures that all rows match for second loop, ordinal is 0 and
                # all hashes are 0
                return b'\x00' * 16

            def fake_delete_object(*args, **kwargs):
                pass

            sync.hash_path = fake_hash_path
            sync.delete_object = fake_delete_object
            fcb = FakeContainerBroker(
                'path',
                info={'account': 'a', 'container': 'c',
                      'storage_policy_index': 0,
                      'x_container_sync_point1': -1,
                      'x_container_sync_point2': -1},
                metadata={'x-container-sync-to': ('http://127.0.0.1/a/c', 1),
                          'x-container-sync-key': ('key', 1)},
                items_since=[{'ROWID': 1, 'name': 'o'}])
            sync.ContainerBroker = lambda p, logger: fcb
            cs._myips = ['10.0.0.0']    # Match
            cs._myport = 1000           # Match
            cs.allowed_sync_hosts = ['127.0.0.1']
            cs.container_sync('isa.db')
            # Fails because row is missing 'deleted' key
            # Nevertheless the fault is skipped
            self.assertEqual(cs.container_failures, 1)
            self.assertEqual(cs.container_skips, 0)
            self.assertEqual(fcb.sync_point1, 1)
            self.assertIsNone(fcb.sync_point2)

            fcb = FakeContainerBroker(
                'path',
                info={'account': 'a', 'container': 'c',
                      'storage_policy_index': 0,
                      'x_container_sync_point1': -1,
                      'x_container_sync_point2': -1},
                metadata={'x-container-sync-to': ('http://127.0.0.1/a/c', 1),
                          'x-container-sync-key': ('key', 1)},
                items_since=[{'ROWID': 1, 'name': 'o', 'created_at': '1.2',
                              'deleted': True}])
            sync.ContainerBroker = lambda p, logger: fcb
            cs._myips = ['10.0.0.0']    # Match
            cs._myport = 1000           # Match
            cs.allowed_sync_hosts = ['127.0.0.1']
            cs.container_sync('isa.db')
            # Succeeds because row now has 'deleted' key and delete_object
            # succeeds
            self.assertEqual(cs.container_failures, 1)
            self.assertEqual(cs.container_skips, 0)
            self.assertEqual(fcb.sync_point1, 1)
            self.assertIsNone(fcb.sync_point2)
        finally:
            sync.ContainerBroker = orig_ContainerBroker
            sync.hash_path = orig_hash_path
            sync.delete_object = orig_delete_object

    def test_container_report(self):
        container_stats = {'puts': 0,
                           'deletes': 0,
                           'bytes': 0}

        def fake_container_sync_row(self, row, sync_to,
                                    user_key, broker, info, realm, realm_key):
            if 'deleted' in row:
                container_stats['deletes'] += 1
                return True

            container_stats['puts'] += 1
            container_stats['bytes'] += row['size']
            return True

        def fake_hash_path(account, container, obj, raw_digest=False):
            # Ensures that no rows match for second loop, ordinal is 0 and
            # all hashes are 1
            return '\x01' * 16

        fcb = FakeContainerBroker(
            'path',
            info={'account': 'a', 'container': 'c',
                  'storage_policy_index': 0,
                  'x_container_sync_point1': 5,
                  'x_container_sync_point2': -1},
            metadata={'x-container-sync-to': ('http://127.0.0.1/a/c', 1),
                      'x-container-sync-key': ('key', 1)},
            items_since=[{'ROWID': 1, 'name': 'o1', 'size': 0,
                          'deleted': True},
                         {'ROWID': 2, 'name': 'o2', 'size': 1010},
                         {'ROWID': 3, 'name': 'o3', 'size': 0,
                          'deleted': True},
                         {'ROWID': 4, 'name': 'o4', 'size': 90},
                         {'ROWID': 5, 'name': 'o5', 'size': 0}])

        with mock.patch('swift.container.sync.InternalClient'), \
                mock.patch('swift.container.sync.hash_path',
                           fake_hash_path), \
                mock.patch('swift.container.sync.ContainerBroker',
                           lambda p, logger: fcb):
            cring = FakeRing()
            cs = sync.ContainerSync({}, container_ring=cring,
                                    logger=self.logger)
            cs.container_stats = container_stats
            cs._myips = ['10.0.0.0']    # Match
            cs._myport = 1000           # Match
            cs.allowed_sync_hosts = ['127.0.0.1']
            with mock.patch.object(cs, 'container_sync_row',
                                   fake_container_sync_row):
                cs.container_sync('isa.db')
            # Succeeds because no rows match
            log_line = cs.logger.get_lines_for_level('info')[0]
            lines = log_line.split(',')
            self.assertEqual('total_rows: 1', lines.pop().strip())
            self.assertEqual('sync_point2: None', lines.pop().strip())
            self.assertEqual('sync_point1: 5', lines.pop().strip())
            self.assertEqual('bytes: 0', lines.pop().strip())
            self.assertEqual('deletes: 0', lines.pop().strip())
            self.assertEqual('posts: 0', lines.pop().strip())
            self.assertEqual('puts: 0', lines.pop().strip())

    def test_container_sync_row_delete(self):
        self._test_container_sync_row_delete(None, None)

    def test_container_sync_row_delete_using_realms(self):
        self._test_container_sync_row_delete('US', 'realm_key')

    def _test_container_sync_row_delete(self, realm, realm_key):
        orig_uuid = sync.uuid
        orig_delete_object = sync.delete_object
        try:
            class FakeUUID(object):
                class uuid4(object):
                    hex = 'abcdef'

            sync.uuid = FakeUUID
            ts_data = Timestamp(1.1)

            def fake_delete_object(path, name=None, headers=None, proxy=None,
                                   logger=None, timeout=None):
                self.assertEqual(path, 'http://sync/to/path')
                self.assertEqual(name, 'object')
                if realm:
                    self.assertEqual(headers, {
                        'x-container-sync-auth':
                        'US abcdef a2401ecb1256f469494a0abcb0eb62ffa73eca63',
                        'x-timestamp': ts_data.internal})
                else:
                    self.assertEqual(
                        headers,
                        {'x-container-sync-key': 'key',
                         'x-timestamp': ts_data.internal})
                self.assertEqual(proxy, 'http://proxy')
                self.assertEqual(timeout, 5.0)
                self.assertEqual(logger, self.logger)

            sync.delete_object = fake_delete_object

            with mock.patch('swift.container.sync.InternalClient'):
                cs = sync.ContainerSync({}, container_ring=FakeRing(),
                                        logger=self.logger)
            cs.http_proxies = ['http://proxy']
            # Success.
            # simulate a row with tombstone at 1.1 and later ctype, meta times
            created_at = ts_data.internal + '+1388+1388'  # last modified = 1.2
            self.assertTrue(cs.container_sync_row(
                {'deleted': True,
                 'name': 'object',
                 'created_at': created_at,
                 'size': '1000'}, 'http://sync/to/path',
                'key', FakeContainerBroker('broker'),
                {'account': 'a', 'container': 'c', 'storage_policy_index': 0},
                realm, realm_key))
            self.assertEqual(cs.container_deletes, 1)

            exc = []

            def fake_delete_object(*args, **kwargs):
                exc.append(Exception('test exception'))
                raise exc[-1]

            sync.delete_object = fake_delete_object
            # Failure because of delete_object exception
            self.assertFalse(cs.container_sync_row(
                {'deleted': True,
                 'name': 'object',
                 'created_at': '1.2'}, 'http://sync/to/path',
                'key', FakeContainerBroker('broker'),
                {'account': 'a', 'container': 'c', 'storage_policy_index': 0},
                realm, realm_key))
            self.assertEqual(cs.container_deletes, 1)
            self.assertEqual(len(exc), 1)
            self.assertEqual(str(exc[-1]), 'test exception')

            def fake_delete_object(*args, **kwargs):
                exc.append(ClientException('test client exception'))
                raise exc[-1]

            sync.delete_object = fake_delete_object
            # Failure because of delete_object exception
            self.assertFalse(cs.container_sync_row(
                {'deleted': True,
                 'name': 'object',
                 'created_at': '1.2'}, 'http://sync/to/path',
                'key', FakeContainerBroker('broker'),
                {'account': 'a', 'container': 'c', 'storage_policy_index': 0},
                realm, realm_key))
            self.assertEqual(cs.container_deletes, 1)
            self.assertEqual(len(exc), 2)
            self.assertEqual(str(exc[-1]), 'test client exception')

            def fake_delete_object(*args, **kwargs):
                exc.append(ClientException('test client exception',
                                           http_status=404))
                raise exc[-1]

            sync.delete_object = fake_delete_object
            # Success because the object wasn't even found
            self.assertTrue(cs.container_sync_row(
                {'deleted': True,
                 'name': 'object',
                 'created_at': '1.2'}, 'http://sync/to/path',
                'key', FakeContainerBroker('broker'),
                {'account': 'a', 'container': 'c', 'storage_policy_index': 0},
                realm, realm_key))
            self.assertEqual(cs.container_deletes, 2)
            self.assertEqual(len(exc), 3)
            self.assertEqual(str(exc[-1]), 'test client exception: 404')

            def fake_delete_object(*args, **kwargs):
                exc.append(ClientException('test client exception',
                                           http_status=409))
                raise exc[-1]

            sync.delete_object = fake_delete_object
            # Success because our tombstone is out of date
            self.assertTrue(cs.container_sync_row(
                {'deleted': True,
                 'name': 'object',
                 'created_at': '1.2'}, 'http://sync/to/path',
                'key', FakeContainerBroker('broker'),
                {'account': 'a', 'container': 'c', 'storage_policy_index': 0},
                realm, realm_key))
            self.assertEqual(cs.container_deletes, 3)
            self.assertEqual(len(exc), 4)
            self.assertEqual(str(exc[-1]), 'test client exception: 409')
        finally:
            sync.uuid = orig_uuid
            sync.delete_object = orig_delete_object

    def test_container_sync_row_put(self):
        self._test_container_sync_row_put(None, None)

    def test_container_sync_row_put_using_realms(self):
        self._test_container_sync_row_put('US', 'realm_key')

    def _test_container_sync_row_put(self, realm, realm_key):
        orig_uuid = sync.uuid
        orig_put_object = sync.put_object
        orig_head_object = sync.head_object

        try:
            class FakeUUID(object):
                class uuid4(object):
                    hex = 'abcdef'

            sync.uuid = FakeUUID
            ts_data = Timestamp(1.1)
            timestamp = Timestamp(1.2)
            put_object_calls = []

            def fake_put_object(*args, **kwargs):
                put_object_calls.append((args, kwargs))

            def check_put_object(extra_headers, sync_to, name=None,
                                 headers=None, contents=None, proxy=None,
                                 logger=None, timeout=None):
                self.assertEqual(sync_to, 'http://sync/to/path')
                self.assertEqual(name, 'object')
                expected_headers = {
                    'x-timestamp': timestamp.internal,
                    'etag': 'etagvalue',
                    'other-header': 'other header value',
                    'content-type': 'text/plain'}
                if realm:
                    expected_headers.update({
                        'x-container-sync-auth':
                        'US abcdef a5fb3cf950738e6e3b364190e246bd7dd21dad3c'})
                else:
                    expected_headers.update({
                        'x-container-sync-key': 'key'})
                expected_headers.update(extra_headers)
                self.assertDictEqual(expected_headers, headers)
                self.assertEqual(contents.read(), b'contents')
                self.assertEqual(proxy, 'http://proxy')
                self.assertEqual(timeout, 5.0)
                self.assertEqual(logger, self.logger)

            sync.put_object = fake_put_object
            expected_put_count = 0
            excepted_failure_count = 0

            with mock.patch('swift.container.sync.InternalClient'):
                cs = sync.ContainerSync({}, container_ring=FakeRing(),
                                        logger=self.logger)
            cs.http_proxies = ['http://proxy']

            def fake_get_object(acct, con, obj, headers, acceptable_statuses,
                                params=None):
                self.assertEqual({'symlink': 'get'}, params)
                self.assertEqual(headers['X-Backend-Storage-Policy-Index'],
                                 '0')
                return (200,
                        {'other-header': 'other header value',
                         'etag': '"etagvalue"',
                         'x-timestamp': timestamp.internal,
                         'content-type': 'text/plain; swift_bytes=123'},
                        iter([b'contents']))

            cs.swift.get_object = fake_get_object
            # Success as everything says it worked.
            # simulate a row with data at 1.1 and later ctype, meta times
            created_at = ts_data.internal + '+1388+1388'  # last modified = 1.2

            def fake_object_in_rcontainer(row, sync_to, user_key,
                                          broker, realm, realm_key):
                return False

            orig_object_in_rcontainer = cs._object_in_remote_container
            cs._object_in_remote_container = fake_object_in_rcontainer

            self.assertTrue(cs.container_sync_row(
                {'deleted': False,
                 'name': 'object',
                 'created_at': created_at,
                 'size': 50}, 'http://sync/to/path',
                'key', FakeContainerBroker('broker'),
                {'account': 'a', 'container': 'c', 'storage_policy_index': 0},
                realm, realm_key))
            self.assertEqual(1, len(put_object_calls))
            check_put_object({'etag': 'etagvalue'},
                             *put_object_calls[0][0], **put_object_calls[0][1])
            expected_put_count += 1
            self.assertEqual(cs.container_puts, expected_put_count)

            def fake_get_object(acct, con, obj, headers, acceptable_statuses,
                                params=None):
                self.assertEqual({'symlink': 'get'}, params)
                self.assertEqual(headers['X-Newest'], True)
                self.assertEqual(headers['X-Backend-Storage-Policy-Index'],
                                 '0')
                return (200,
                        {'date': 'date value',
                         'last-modified': 'last modified value',
                         'x-timestamp': timestamp.internal,
                         'other-header': 'other header value',
                         'etag': '"etagvalue"',
                         'content-type': 'text/plain; swift_bytes=123'},
                        iter([b'contents']))

            cs.swift.get_object = fake_get_object

            # Success as everything says it worked, also checks 'date' and
            # 'last-modified' headers are removed and that 'etag' header is
            # stripped of double quotes.
            put_object_calls = []
            self.assertTrue(cs.container_sync_row(
                {'deleted': False,
                 'name': 'object',
                 'created_at': timestamp.internal,
                 'size': 60}, 'http://sync/to/path',
                'key', FakeContainerBroker('broker'),
                {'account': 'a', 'container': 'c', 'storage_policy_index': 0},
                realm, realm_key))
            self.assertEqual(1, len(put_object_calls))
            check_put_object({'etag': 'etagvalue'},
                             *put_object_calls[0][0], **put_object_calls[0][1])
            expected_put_count += 1
            self.assertEqual(cs.container_puts, expected_put_count)

            # Success as everything says it worked, also check that PUT
            # timestamp equals GET timestamp when it is newer than created_at
            # value.
            put_object_calls = []
            self.assertTrue(cs.container_sync_row(
                {'deleted': False,
                 'name': 'object',
                 'created_at': '1.1',
                 'size': 60}, 'http://sync/to/path',
                'key', FakeContainerBroker('broker'),
                {'account': 'a', 'container': 'c', 'storage_policy_index': 0},
                realm, realm_key))
            self.assertEqual(1, len(put_object_calls))
            check_put_object({'etag': 'etagvalue'},
                             *put_object_calls[0][0], **put_object_calls[0][1])
            expected_put_count += 1
            self.assertEqual(cs.container_puts, expected_put_count)

            def fake_get_object(acct, con, obj, headers, acceptable_statuses,
                                params=None):
                self.assertEqual({'symlink': 'get'}, params)
                self.assertEqual(headers['X-Newest'], True)
                self.assertEqual(headers['X-Backend-Storage-Policy-Index'],
                                 '0')
                return (200,
                        {'date': 'date value',
                         'last-modified': 'last modified value',
                         'x-timestamp': timestamp.internal,
                         'other-header': 'other header value',
                         'etag': '"etagvalue"',
                         'x-static-large-object': 'true',
                         'content-type': 'text/plain; swift_bytes=123'},
                        iter([b'contents']))

            cs.swift.get_object = fake_get_object

            # Success as everything says it worked, also check that etag
            # header removed in case of SLO
            put_object_calls = []
            self.assertTrue(cs.container_sync_row(
                {'deleted': False,
                 'name': 'object',
                 'created_at': '1.1',
                 'size': 60}, 'http://sync/to/path',
                'key', FakeContainerBroker('broker'),
                {'account': 'a', 'container': 'c', 'storage_policy_index': 0},
                realm, realm_key))
            self.assertEqual(1, len(put_object_calls))
            check_put_object({'x-static-large-object': 'true'},
                             *put_object_calls[0][0], **put_object_calls[0][1])
            expected_put_count += 1
            self.assertEqual(cs.container_puts, expected_put_count)

            exc = []

            def fake_get_object(acct, con, obj, headers, acceptable_statuses,
                                params=None):
                self.assertEqual({'symlink': 'get'}, params)
                self.assertEqual(headers['X-Newest'], True)
                self.assertEqual(headers['X-Backend-Storage-Policy-Index'],
                                 '0')
                exc.append(Exception('test exception'))
                raise exc[-1]

            cs.swift.get_object = fake_get_object
            # Fail due to completely unexpected exception
            self.assertFalse(cs.container_sync_row(
                {'deleted': False,
                 'name': 'object',
                 'created_at': timestamp.internal,
                 'size': 70}, 'http://sync/to/path',
                'key', FakeContainerBroker('broker'),
                {'account': 'a', 'container': 'c', 'storage_policy_index': 0},
                realm, realm_key))
            self.assertEqual(cs.container_puts, expected_put_count)
            excepted_failure_count += 1
            self.assertEqual(len(exc), 1)
            self.assertEqual(str(exc[-1]), 'test exception')

            exc = []

            def fake_get_object(acct, con, obj, headers, acceptable_statuses,
                                params=None):
                self.assertEqual({'symlink': 'get'}, params)
                self.assertEqual(headers['X-Newest'], True)
                self.assertEqual(headers['X-Backend-Storage-Policy-Index'],
                                 '0')

                exc.append(ClientException('test client exception'))
                raise exc[-1]

            cs.swift.get_object = fake_get_object
            # Fail due to all direct_get_object calls failing
            self.assertFalse(cs.container_sync_row(
                {'deleted': False,
                 'name': 'object',
                 'created_at': timestamp.internal,
                 'size': 80}, 'http://sync/to/path',
                'key', FakeContainerBroker('broker'),
                {'account': 'a', 'container': 'c', 'storage_policy_index': 0},
                realm, realm_key))
            self.assertEqual(cs.container_puts, expected_put_count)
            excepted_failure_count += 1
            self.assertEqual(len(exc), 1)
            self.assertEqual(str(exc[-1]), 'test client exception')

            def fake_get_object(acct, con, obj, headers, acceptable_statuses,
                                params=None):
                self.assertEqual({'symlink': 'get'}, params)
                self.assertEqual(headers['X-Newest'], True)
                self.assertEqual(headers['X-Backend-Storage-Policy-Index'],
                                 '0')
                return (200, {'other-header': 'other header value',
                              'x-timestamp': timestamp.internal,
                              'etag': '"etagvalue"'},
                        iter([b'contents']))

            def fake_put_object(*args, **kwargs):
                raise ClientException('test client exception', http_status=401)

            cs.swift.get_object = fake_get_object
            sync.put_object = fake_put_object
            # Fail due to 401
            self.assertFalse(cs.container_sync_row(
                {'deleted': False,
                 'name': 'object',
                 'created_at': timestamp.internal,
                 'size': 90}, 'http://sync/to/path',
                'key', FakeContainerBroker('broker'),
                {'account': 'a', 'container': 'c', 'storage_policy_index': 0},
                realm, realm_key))
            self.assertEqual(cs.container_puts, expected_put_count)
            excepted_failure_count += 1
            self.assertEqual(cs.container_failures, excepted_failure_count)
            self.assertLogMessage('info', 'Unauth')

            def fake_put_object(*args, **kwargs):
                raise ClientException('test client exception', http_status=404)

            sync.put_object = fake_put_object
            # Fail due to 404
            self.assertFalse(cs.container_sync_row(
                {'deleted': False,
                 'name': 'object',
                 'created_at': timestamp.internal,
                 'size': 50}, 'http://sync/to/path',
                'key', FakeContainerBroker('broker'),
                {'account': 'a', 'container': 'c', 'storage_policy_index': 0},
                realm, realm_key))
            self.assertEqual(cs.container_puts, expected_put_count)
            excepted_failure_count += 1
            self.assertEqual(cs.container_failures, excepted_failure_count)
            self.assertLogMessage('info', 'Not found', 1)

            def fake_put_object(*args, **kwargs):
                raise ClientException('test client exception', http_status=503)

            sync.put_object = fake_put_object
            # Fail due to 503
            self.assertFalse(cs.container_sync_row(
                {'deleted': False,
                 'name': 'object',
                 'created_at': timestamp.internal,
                 'size': 50}, 'http://sync/to/path',
                'key', FakeContainerBroker('broker'),
                {'account': 'a', 'container': 'c', 'storage_policy_index': 0},
                realm, realm_key))
            self.assertEqual(cs.container_puts, expected_put_count)
            excepted_failure_count += 1
            self.assertEqual(cs.container_failures, excepted_failure_count)
            self.assertLogMessage('error', 'ERROR Syncing')

            # Test the following cases:
            # remote has the same date and a put doesn't take place
            # remote has more up to date copy and a put doesn't take place
            # head_object returns ClientException(404) and a put takes place
            # head_object returns other ClientException put doesn't take place
            # and we get failure
            # head_object returns other Exception put does not take place
            # and we get failure
            # remote returns old copy and a put takes place
            test_row = {'deleted': False,
                        'name': 'object',
                        'created_at': timestamp.internal,
                        'etag': '1111',
                        'size': 10}
            test_info = {'account': 'a',
                         'container': 'c',
                         'storage_policy_index': 0}

            actual_puts = []

            def fake_put_object(*args, **kwargs):
                actual_puts.append((args, kwargs))

            def fake_head_object(*args, **kwargs):
                return ({'x-timestamp': '1.2'}, '')

            sync.put_object = fake_put_object
            sync.head_object = fake_head_object
            cs._object_in_remote_container = orig_object_in_rcontainer
            self.assertTrue(cs.container_sync_row(
                test_row, 'http://sync/to/path',
                'key', FakeContainerBroker('broker'),
                test_info,
                realm, realm_key))
            # No additional put has taken place
            self.assertEqual(len(actual_puts), 0)
            # No additional errors
            self.assertEqual(cs.container_failures, excepted_failure_count)

            def fake_head_object(*args, **kwargs):
                return ({'x-timestamp': '1.3'}, '')

            sync.head_object = fake_head_object
            self.assertTrue(cs.container_sync_row(
                test_row, 'http://sync/to/path',
                'key', FakeContainerBroker('broker'),
                test_info,
                realm, realm_key))
            # No additional put has taken place
            self.assertEqual(len(actual_puts), 0)
            # No additional errors
            self.assertEqual(cs.container_failures, excepted_failure_count)

            actual_puts = []

            def fake_head_object(*args, **kwargs):
                raise ClientException('test client exception', http_status=404)

            sync.head_object = fake_head_object
            self.assertTrue(cs.container_sync_row(
                test_row, 'http://sync/to/path',
                'key', FakeContainerBroker('broker'),
                test_info, realm, realm_key))
            # Additional put has taken place
            self.assertEqual(len(actual_puts), 1)
            # No additional errors
            self.assertEqual(cs.container_failures, excepted_failure_count)

            def fake_head_object(*args, **kwargs):
                raise ClientException('test client exception', http_status=401)

            sync.head_object = fake_head_object
            self.assertFalse(cs.container_sync_row(
                test_row, 'http://sync/to/path',
                'key', FakeContainerBroker('broker'),
                test_info, realm, realm_key))
            # No additional put has taken place, failures increased
            self.assertEqual(len(actual_puts), 1)
            excepted_failure_count += 1
            self.assertEqual(cs.container_failures, excepted_failure_count)

            def fake_head_object(*args, **kwargs):
                raise Exception()

            sync.head_object = fake_head_object
            self.assertFalse(cs.container_sync_row(
                             test_row,
                             'http://sync/to/path',
                             'key', FakeContainerBroker('broker'),
                             test_info, realm, realm_key))
            # No additional put has taken place, failures increased
            self.assertEqual(len(actual_puts), 1)
            excepted_failure_count += 1
            self.assertEqual(cs.container_failures, excepted_failure_count)

            def fake_head_object(*args, **kwargs):
                return ({'x-timestamp': '1.1'}, '')

            sync.head_object = fake_head_object
            self.assertTrue(cs.container_sync_row(
                test_row, 'http://sync/to/path',
                'key', FakeContainerBroker('broker'),
                test_info, realm, realm_key))
            # Additional put has taken place
            self.assertEqual(len(actual_puts), 2)
            # No additional errors
            self.assertEqual(cs.container_failures, excepted_failure_count)

        finally:
            sync.uuid = orig_uuid
            sync.put_object = orig_put_object
            sync.head_object = orig_head_object

    def test_select_http_proxy_None(self):

        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync(
                {'sync_proxy': ''}, container_ring=FakeRing())
        self.assertIsNone(cs.select_http_proxy())

    def test_select_http_proxy_one(self):

        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync(
                {'sync_proxy': 'http://one'}, container_ring=FakeRing())
        self.assertEqual(cs.select_http_proxy(), 'http://one')

    def test_select_http_proxy_multiple(self):

        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync(
                {'sync_proxy': 'http://one,http://two,http://three'},
                container_ring=FakeRing())
        self.assertEqual(
            set(cs.http_proxies),
            set(['http://one', 'http://two', 'http://three']))

    def test_producer_consumer_monkey_patching(self):
        cring = FakeRing()
        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync({'daemon_mode': 'classic'},
                                    container_ring=cring)
        cs.init_daemon_mode()
        self.assertNotEqual(cs.container_sync_row,
                            cs.container_sync_row_producer)
        self.assertNotIsInstance(cs.sync_store, sync.RabbitSyncStore)
        self.assertNotEqual(cs.container_sync, cs.container_sync_consumer)

        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync({'daemon_mode': 'producer'},
                                    container_ring=cring)
        cs.init_daemon_mode()
        self.assertEqual(cs.container_sync_row,
                         cs.container_sync_row_producer)
        self.assertNotIsInstance(cs.sync_store, sync.RabbitSyncStore)
        self.assertNotEqual(cs.container_sync, cs.container_sync_consumer)

        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync({'daemon_mode': 'consumer'},
                                    container_ring=cring)
        cs.init_daemon_mode()
        kill(cs.announcement_thread)
        self.assertNotEqual(cs.container_sync_row,
                            cs.container_sync_row_producer)
        self.assertIsInstance(cs.sync_store, sync.RabbitSyncStore)
        self.assertEqual(cs.container_sync, cs.container_sync_consumer)

        with mock.patch('swift.container.sync.InternalClient'):
            self.assertRaises(SystemExit,
                              sync.ContainerSync, {'daemon_mode': 'foo'},
                              container_ring=cring)

    def test_rabbit_connect(self):
        url = 'amqps://user:pass@some_host/some_vhost'
        expected_url_params = pika.URLParameters(url)

        # Success
        m_channel = mock.Mock()
        m_conn = mock.Mock(channel=mock.Mock(return_value=m_channel))
        m_BlockingConnection = mock.Mock(return_value=m_conn)
        m_logger = mock.Mock()
        with mock.patch('swift.container.sync.pika.BlockingConnection',
                        new=m_BlockingConnection):
            self.assertEqual(sync.rabbit_connect(url, m_logger),
                             (m_conn, m_channel))

        m_BlockingConnection.assert_called_once_with(expected_url_params)
        m_conn.channel.assert_called_once_with()

        # Channel failure
        m_conn = mock.Mock(channel=mock.Mock(side_effect=AMQPError))
        m_BlockingConnection = mock.Mock(return_value=m_conn)
        m_logger = mock.Mock()
        with mock.patch('swift.container.sync.pika.BlockingConnection',
                        new=m_BlockingConnection):
            self.assertRaises(AMQPError, sync.rabbit_connect, url, m_logger)

        m_BlockingConnection.assert_called_once_with(expected_url_params)
        m_conn.channel.assert_called_once_with()
        m_conn.close.assert_called_once_with()

    def test_rabbit_disconnect(self):
        # Valid conn/channel
        m_conn = mock.Mock(is_open=True)
        m_channel = mock.Mock(is_open=True)
        sync.rabbit_disconnect(m_conn, m_channel)
        self.assertEqual(m_channel.cancel.call_count, 1)
        self.assertEqual(m_conn.close.call_count, 1)

        # Valid conn/Closed channel
        m_conn = mock.Mock(is_open=True)
        m_channel = mock.Mock(is_open=False)
        sync.rabbit_disconnect(m_conn, m_channel)
        self.assertEqual(m_channel.cancel.call_count, 0)
        self.assertEqual(m_conn.close.call_count, 1)

        # Closed conn/Valid channel
        m_conn = mock.Mock(is_open=False)
        m_channel = mock.Mock(is_open=True)
        sync.rabbit_disconnect(m_conn, m_channel)
        self.assertEqual(m_channel.cancel.call_count, 1)
        self.assertEqual(m_conn.close.call_count, 0)

    def test_rabbit_sync_store(self):
        # Scenario: REMOTE1 and REMOTE3 have token while REMOTE2 does not
        remotes = {'<REMOTE1>': None, '<REMOTE2>': None, '<REMOTE3>': None}

        def fake_basic_get(remote):
            if remote == 'remote-<REMOTE1>':
                return (mock.Mock(delivery_tag='TAG1'), None, None)
            elif remote == 'remote-<REMOTE2>':
                return (None, None, None)
            elif remote == 'remote-<REMOTE3>':
                return (mock.Mock(delivery_tag='TAG3'), None, None)

        m_logger = mock.Mock()
        rss = sync.RabbitSyncStore('<RABBIT_URL>', remotes, m_logger)

        m_rabbit_conn = mock.Mock()
        m_rabbit_ch = mock.Mock(
            basic_get=mock.Mock(side_effect=fake_basic_get))
        with mock.patch('swift.container.sync.rabbit_connect',
                        return_value=(m_rabbit_conn, m_rabbit_ch)) \
                as m_rabbit_connect:
            res = list(rss.synced_containers_generator())

        # Assert it created a connection and set the right prefetch
        m_rabbit_connect.assert_called_once_with('<RABBIT_URL>', m_logger)
        m_rabbit_ch.basic_qos.assert_called_once_with(prefetch_count=1)

        # Assert it tried to fetch a token for each remote, yield and nack
        # those it got
        self.assertEqual(m_rabbit_ch.basic_get.call_count, 3)
        for args in [(('remote-<REMOTE1>',),),
                     (('remote-<REMOTE2>',),),
                     (('remote-<REMOTE3>',),)]:
            self.assertIn(args, m_rabbit_ch.basic_get.call_args_list)

        self.assertEqual(sorted(res), ['<REMOTE1>', '<REMOTE3>'])

        self.assertEqual(m_rabbit_ch.basic_nack.call_count, 2)
        for args in [({'delivery_tag': 'TAG1'},),
                     ({'delivery_tag': 'TAG3'},)]:
            self.assertIn(args, m_rabbit_ch.basic_nack.call_args_list)

    def test_rabbit_sync_store_exception(self):
        remotes = {'<REMOTE>': None}
        m_logger = mock.Mock()
        rss = sync.RabbitSyncStore('<RABBIT_URL>', remotes, m_logger)

        # AMQPError exception triggers disconnection
        m_rabbit_conn = mock.Mock()
        m_rabbit_ch = mock.Mock(
            basic_get=mock.Mock(side_effect=AMQPError))
        with mock.patch('swift.container.sync.rabbit_connect',
                        return_value=(m_rabbit_conn, m_rabbit_ch)) \
                as m_rabbit_connect, \
                mock.patch('swift.container.sync.rabbit_disconnect') \
                as m_rabbit_disconnect:
            list(rss.synced_containers_generator())

        # Assert it created a connection and disconnected on error
        m_rabbit_connect.assert_called_once_with('<RABBIT_URL>', m_logger)
        m_rabbit_disconnect.assert_called_once_with(m_rabbit_conn, m_rabbit_ch)

        # ...standard exception does not
        m_rabbit_conn = mock.Mock()
        m_rabbit_ch = mock.Mock(
            basic_get=mock.Mock(side_effect=Exception))
        with mock.patch('swift.container.sync.rabbit_connect',
                        return_value=(m_rabbit_conn, m_rabbit_ch)) \
                as m_rabbit_connect, \
                mock.patch('swift.container.sync.rabbit_disconnect') \
                as m_rabbit_disconnect:
            list(rss.synced_containers_generator())

        # Assert it reconnected
        m_rabbit_connect.assert_called_once_with('<RABBIT_URL>', m_logger)
        self.assertEqual(m_rabbit_disconnect.call_count, 0)

        # Assert it does not reconnect if it did not disconnect
        list(rss.synced_containers_generator())
        m_rabbit_connect.assert_called_once_with('<RABBIT_URL>', m_logger)

    def test_rabbit_connect_disconnect_wrappers(self):
        cring = FakeRing()
        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync({'daemon_mode': 'producer'},
                                    container_ring=cring)
        cs.init_daemon_mode()

        m_rabbit_conn = mock.Mock()
        m_rabbit_ch = mock.Mock()
        with mock.patch('swift.container.sync.rabbit_connect',
                        return_value=(m_rabbit_conn, m_rabbit_ch)) \
                as m_rabbit_connect, \
                mock.patch('swift.container.sync.rabbit_disconnect') \
                as m_rabbit_disconnect:

            # Check initial connection
            cs.rabbit_connect()
            self.assertEqual(m_rabbit_connect.call_count, 1)
            self.assertEqual(m_rabbit_disconnect.call_count, 0)
            self.assertEqual(cs.rabbit_conn, m_rabbit_conn)
            self.assertEqual(cs.rabbit_ch, m_rabbit_ch)

            # No reconnection needed
            cs.rabbit_connect()
            self.assertEqual(m_rabbit_connect.call_count, 1)
            self.assertEqual(m_rabbit_disconnect.call_count, 0)
            self.assertEqual(cs.rabbit_conn, m_rabbit_conn)
            self.assertEqual(cs.rabbit_ch, m_rabbit_ch)

            # Disconnect
            cs.rabbit_disconnect()
            self.assertEqual(m_rabbit_connect.call_count, 1)
            self.assertEqual(m_rabbit_disconnect.call_count, 1)
            self.assertIsNone(cs.rabbit_conn)
            self.assertIsNone(cs.rabbit_ch)

            # Reconnection needed, but it fails
            m_rabbit_connect.side_effect = AMQPError
            cs.rabbit_connect()
            self.assertEqual(m_rabbit_connect.call_count, 2)
            self.assertEqual(m_rabbit_disconnect.call_count, 2)
            self.assertIsNone(cs.rabbit_conn)
            self.assertIsNone(cs.rabbit_ch)

            # Reconnection succeed
            m_rabbit_connect.side_effect = None
            cs.rabbit_connect()
            self.assertEqual(m_rabbit_connect.call_count, 3)
            self.assertEqual(m_rabbit_disconnect.call_count, 2)
            self.assertEqual(cs.rabbit_conn, m_rabbit_conn)
            self.assertEqual(cs.rabbit_ch, m_rabbit_ch)

    def test_container_announcement(self):
        cring = FakeRing()
        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync({'daemon_mode': 'producer',
                                     'rabbit_url': '<RABBIT_URL>',
                                     'rabbit_announcement_exchange': '<XCHG>',
                                     'container_queue_length': 42,
                                     'remote_concurrency': 2},
                                    container_ring=cring)
        cs.logger = mock.Mock()
        cs.init_daemon_mode()

        sync_to = 'http://remote_cluster:80/v1/AUTH_dst/c'
        user_key = 'u53r_k3y'
        account, container = 'AUTH_src', 'c'
        realm = 'r34lm'
        realm_key = 'r34lm_k3y'

        # md5('remote_cluster')
        expected_remote = '97a8d1e6765c5f5cc8ed3768543d20ca'
        # hash_path('AUTH_src', 'c')
        expected_container = '5c3f7c76fb50ccd827c354cdfa3014f4'

        m_rabbit_conn = mock.Mock()
        m_rabbit_ch = mock.Mock()
        m_rabbit_ch.queue_declare.return_value.method.message_count = 0
        with mock.patch('swift.container.sync.rabbit_connect',
                        return_value=(m_rabbit_conn, m_rabbit_ch)) \
                as m_rabbit_connect:
            cs.container_announcement(sync_to, user_key,
                                      {'account': account,
                                       'container': container},
                                      realm, realm_key)

        # Assert it created a connection
        m_rabbit_connect.assert_called_once_with('<RABBIT_URL>', cs.logger)

        # Assert it created the announcements exchange
        m_rabbit_ch.exchange_declare.assert_called_once_with(
            exchange='<XCHG>', exchange_type='fanout', durable=True)

        # Assert it created the remote queue
        expected_args = ('remote-%s' % expected_remote, )
        expected_kwargs = {'durable': True}
        self.assertEqual(m_rabbit_ch.queue_declare.call_args_list[0],
                         (expected_args, expected_kwargs))
        # ...and added some tokens
        expected_kwargs = {'exchange': '',
                           'routing_key': 'remote-%s' % expected_remote,
                           'body': expected_remote,
                           'mandatory': True}
        self.assertEqual([(expected_kwargs, )] * 2,
                         m_rabbit_ch.basic_publish.call_args_list[0:2])

        # Assert it created the container queue
        expected_args = ('container-%s' % expected_container, )
        expected_kwargs = {'durable': True,
                           'arguments': {'x-max-length': 42,
                                         'x-overflow': 'reject-publish'}}
        self.assertEqual(m_rabbit_ch.queue_declare.call_args_list[1],
                         (expected_args, expected_kwargs))

        # Assert it published an announcement
        expected_body = json.dumps({'announcement_type': 'container',
                                    'remote': expected_remote,
                                    'container': expected_container,
                                    'sync_to': sync_to,
                                    'user_key': user_key,
                                    'realm': realm,
                                    'realm_key': realm_key})
        self.assertEqual(m_rabbit_ch.basic_publish.call_args_list[2],
                         ({'exchange': '<XCHG>',
                           'routing_key': 'fanout-ignored',
                           'body': expected_body, 'mandatory': True}, ))

        # Assert there is no extra calls
        # remote + container
        self.assertEqual(m_rabbit_ch.queue_declare.call_count, 2)
        # 2 remote tokens + 1 container announce
        self.assertEqual(m_rabbit_ch.basic_publish.call_count, 3)

    def test_container_sync_row_producer(self):
        cring = FakeRing()
        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync({'daemon_mode': 'producer',
                                     'rabbit_url': '<RABBIT_URL>',
                                     'container_queue_length': 42},
                                    container_ring=cring)
        cs.logger = mock.Mock()
        cs.init_daemon_mode()

        row = {'key1': 'value1'}
        sync_to = 'http://remote_cluster:80/v1/AUTH_dst/c'
        user_key = 'u53r_k3y'
        broker = '/some/broker/path.db'
        info = {'account': 'AUTH_src', 'container': 'c'}
        realm = 'r34lm'
        realm_key = 'r34lm_k3y'

        # hash_path('AUTH_src', 'c')
        expected_container = '5c3f7c76fb50ccd827c354cdfa3014f4'

        m_rabbit_conn = mock.Mock()
        m_rabbit_ch = mock.Mock()
        with mock.patch('swift.container.sync.rabbit_connect',
                        return_value=(m_rabbit_conn, m_rabbit_ch)) \
                as m_rabbit_connect:
            cs.container_sync_row(row, sync_to, user_key, broker, info,
                                  realm, realm_key)

        # Assert it created a connection
        m_rabbit_connect.assert_called_once_with('<RABBIT_URL>', cs.logger)

        # Assert it published a row
        expected_body = json.dumps({'row': row,
                                    'info': info,
                                    'broker': broker})
        m_rabbit_ch.basic_publish.assert_called_once_with(
            exchange='', routing_key='container-%s' % expected_container,
            body=expected_body, mandatory=True)

    def test_announcements_consumer(self):
        cring = FakeRing()
        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync({'daemon_mode': 'consumer',
                                     'rabbit_url': '<RABBIT_URL>',
                                     'rabbit_announcement_exchange': '<XCHG>',
                                     'rabbit_announcement_ttl': 5},
                                    container_ring=cring)
        cs.logger = mock.Mock()
        cs.init_daemon_mode()
        kill(cs.announcement_thread)

        global iteration
        iteration = 0

        def exit_condition():
            global iteration
            iteration += 1
            return iteration > 4

        m_rabbit_conn = mock.Mock()
        m_rabbit_ch = mock.Mock()
        m_rabbit_ch.queue_declare.return_value.method.queue = '<QUEUE>'
        # Senario:
        # - t=1: receive an announcement for container1/remote1
        #        => insertion
        # - t=2: receive an announcement for container2/remote2
        #        => insertion
        # - t=3: inactivity timeout
        #         => noop
        # - t=4: inactivity timeout
        #        => noop
        # - t=5: receive an announcement for container1/remote3 (update)
        #        => update the existing entry
        # - t=9: inactivity timeout
        #        => cleanup of remote1, remote2 and container2
        # => Expected output: remote3 and container1
        time_side_effect = [1, 2, 3, 4, 5, 9]
        m_rabbit_ch.consume.side_effect = [
            [(None, None, '{"announcement_type": "container", '
                          ' "remote": "<REMOTE1>", '
                          ' "container": "<CONTAINER1>"}'),
             (None, None, '{"announcement_type": "container", '
                          ' "remote": "<REMOTE2>", '
                          ' "container": "<CONTAINER2>"}')],
            [None, (None, None, None)],
            [(None, None, '{"announcement_type": "container", '
                          ' "remote": "<REMOTE3>", '
                          ' "container": "<CONTAINER1>"}')],
            [None],
        ]
        with mock.patch('swift.container.sync.rabbit_connect',
                        return_value=(m_rabbit_conn, m_rabbit_ch)) \
                as m_rabbit_connect, mock.patch('swift.container.sync.time',
                                                side_effect=time_side_effect):
            cs.announcements_consumer(exit_condition=exit_condition)

        # Assert it created a connection only once
        m_rabbit_connect.assert_called_once_with('<RABBIT_URL>', cs.logger)

        # Assert it created an exchange and a temporary queue only once
        m_rabbit_ch.exchange_declare.assert_called_once_with(
            exchange='<XCHG>', exchange_type='fanout', durable=True)
        m_rabbit_ch.queue_declare.assert_called_once_with('', exclusive=True,
                                                          auto_delete=True)
        m_rabbit_ch.queue_bind.assert_called_once_with('<QUEUE>', '<XCHG>')

        self.assertEqual(list(cs.remotes.keys()), ['<REMOTE3>'])
        self.assertEqual(cs.containers,
                         {'<CONTAINER1>': {'container': '<CONTAINER1>',
                                           'remote': '<REMOTE3>'}})

    def test_announcements_consumer_invalid_announcement(self):
        cring = FakeRing()
        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync({'daemon_mode': 'consumer',
                                     'rabbit_url': '<RABBIT_URL>',
                                     'rabbit_announcement_exchange': '<XCHG>',
                                     'rabbit_announcement_ttl': 5},
                                    container_ring=cring)
        cs.logger = mock.Mock()
        cs.init_daemon_mode()
        kill(cs.announcement_thread)

        global iteration
        iteration = 0

        def exit_condition():
            global iteration
            iteration += 1
            return iteration > 1

        m_rabbit_conn = mock.Mock()
        m_rabbit_ch = mock.Mock()
        m_rabbit_ch.consume.side_effect = [
            [(None, None, '{"announcement_type": "INVALID_ANNOUNCEMENT"}')],
        ]
        with mock.patch('swift.container.sync.rabbit_connect',
                        return_value=(m_rabbit_conn, m_rabbit_ch)):
            cs.announcements_consumer(exit_condition=exit_condition)

        # Assert it logged an exception (the real message would be in log as
        # logger.exception log a stack trace)
        cs.logger.exception.assert_called_once_with("ERROR Receiving "
                                                    "announcement failed")

    def test_container_sync_consumer(self):
        cring = FakeRing()
        with mock.patch('swift.container.sync.InternalClient'):
            cs = sync.ContainerSync({'daemon_mode': 'consumer',
                                     'rabbit_url': '<RABBIT_URL>',
                                     'remote_time_limit': 10},
                                    container_ring=cring)
        cs.logger = mock.Mock()
        cs.init_daemon_mode()
        kill(cs.announcement_thread)

        def _make_container(remote):
            return {'sync_to': '5ync_t0', 'user_key': 'u53r_k3y',
                    'realm': 'r34lm', 'realm_key': 'r34lm_k3y',
                    'remote': remote}

        def _make_msg(container, obj):
            return (mock.Mock(delivery_tag='%s/%s' % (container, obj)),
                    None, json.dumps({'row': '<ROW>', 'broker': container,
                                      'info': obj}))

        # Scenario: CONTAINER1 and CONTAINER3 matches the remote
        # It should consume in this order or something similar:
        # - <CONTAINER1>/obj1
        # - <CONTAINER3>/obj1
        # - <CONTAINER1>/obj2
        # - <CONTAINER3>/obj2
        # - <CONTAINER1>/obj3
        # - <CONTAINER1>/obj4
        # <CONTAINER1>/obj5 won't be treated because of the time limit reached
        # One of them will fail
        cs.containers = {'<CONTAINER1>': _make_container('<REMOTE1>'),
                         '<CONTAINER2>': _make_container('<REMOTE2>'),
                         '<CONTAINER3>': _make_container('<REMOTE1>')}

        container1_msg = [_make_msg('container1', 'obj1'),
                          _make_msg('container1', 'obj2'),
                          _make_msg('container1', 'obj3'),
                          _make_msg('container1', 'obj4'),
                          _make_msg('container1', 'obj5'),
                          None]
        container3_msg = [_make_msg('container3', 'obj1'),
                          _make_msg('container3', 'obj2'),
                          None]

        time_side_effect = [0, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 10]

        cs.container_sync_row = mock.Mock(side_effect=[True, True, False,
                                                       True, True, True])

        def fake_basic_get(container):
            if container == 'container-<CONTAINER1>':
                return container1_msg.pop(0)
            elif container == 'container-<CONTAINER3>':
                return container3_msg.pop(0)

        m_rabbit_conn = mock.Mock()
        m_rabbit_ch = mock.Mock()
        m_rabbit_ch.basic_get.side_effect = fake_basic_get
        with mock.patch('swift.container.sync.rabbit_connect',
                        return_value=(m_rabbit_conn, m_rabbit_ch)) \
                as m_rabbit_connect, mock.patch('swift.container.sync.time',
                                                side_effect=time_side_effect):
            cs.container_sync('<REMOTE1>')

        # Assert it created a connection
        m_rabbit_connect.assert_called_once_with('<RABBIT_URL>', cs.logger)

        # Assert the calls on container_sync_row
        self.assertEqual(m_rabbit_ch.basic_get.call_count, 7)  # One is None
        self.assertEqual(cs.container_sync_row.call_count, 6)
        # NOTE: We should assert that the ordering is fair, but's it's complex
        #       because of the shuffle in the tested method. So we don't :)

        # Assert we got 5 ack and 1 nack
        self.assertEqual(m_rabbit_ch.basic_ack.call_count, 5)
        self.assertEqual(m_rabbit_ch.basic_nack.call_count, 1)


if __name__ == '__main__':
    unittest.main()
