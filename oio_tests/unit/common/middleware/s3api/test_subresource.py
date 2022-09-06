# Copyright (c) 2014 OpenStack Foundation
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

import json
import os
import sys
import unittest

from swift.common.middleware.s3api.s3response import AccessDenied
from swift.common.middleware.s3api.subresource import User, \
    AuthenticatedUsers, AllUsers, \
    ACLPrivate, ACLPublicRead, ACLPublicReadWrite, ACLAuthenticatedRead, \
    ACLBucketOwnerRead, ACLBucketOwnerFullControl, Owner, ACL, encode_acl, \
    decode_acl
from swift.common.middleware.s3api.utils import sysmeta_header

# Hack PYTHONPATH so "test" is swift's test directory
sys.path.insert(1, os.path.abspath(os.path.join(__file__,
                                                '../../../../../..')))
from test.unit.common.middleware.s3api.test_subresource \
    import BaseTestS3ApiSubresource  # noqa: E402


class TestS3ApiSubresource(BaseTestS3ApiSubresource):

    __test__ = True

    def test_acl_canonical_user(self):
        grantee = User('test:tester')

        self.assertTrue('test' in grantee)
        self.assertTrue('test' in grantee)
        self.assertTrue('test2' not in grantee)
        self.assertTrue('test2' not in grantee)
        self.assertEqual(str(grantee), 'test')
        self.assertEqual(grantee.elem().find('./ID').text, 'test')

    def test_acl_authenticated_users(self):
        grantee = AuthenticatedUsers()

        self.assertTrue('test' in grantee)
        self.assertTrue('test' in grantee)
        self.assertTrue('test2' in grantee)
        self.assertTrue('test2' in grantee)
        uri = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
        self.assertEqual(grantee.elem().find('./URI').text, uri)

    def test_acl_all_users(self):
        grantee = AllUsers()

        self.assertTrue('test' in grantee)
        self.assertTrue('test' in grantee)
        self.assertTrue('test2' in grantee)
        self.assertTrue('test2' in grantee)
        self.assertTrue(None in grantee)  # Unauthenticated user
        uri = 'http://acs.amazonaws.com/groups/global/AllUsers'
        self.assertEqual(grantee.elem().find('./URI').text, uri)

    def check_permission(self, acl, user_id, permission):
        try:
            acl.check_permission(user_id, permission)
            return True
        except AccessDenied:
            return False

    def test_acl_private(self):
        acl = ACLPrivate(Owner(id='test:tester',
                               name='test:tester'),
                         s3_acl=self.s3_acl,
                         allow_no_owner=self.allow_no_owner)

        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2',
                                              'WRITE_ACP'))
        self.assertFalse(self.check_permission(acl, 'test2:tester', 'READ'))
        self.assertFalse(self.check_permission(acl, 'test2:tester', 'WRITE'))
        self.assertFalse(self.check_permission(acl, 'test2:tester',
                                               'READ_ACP'))
        self.assertFalse(self.check_permission(acl, 'test2:tester',
                                               'WRITE_ACP'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2', 'READ'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2', 'WRITE'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2',
                                               'READ_ACP'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2',
                                               'WRITE_ACP'))

    def test_acl_public_read(self):
        acl = ACLPublicRead(Owner(id='test:tester',
                                  name='test:tester'),
                            s3_acl=self.s3_acl,
                            allow_no_owner=self.allow_no_owner)

        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2',
                                              'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test2:tester', 'READ'))
        self.assertFalse(self.check_permission(acl, 'test2:tester', 'WRITE'))
        self.assertFalse(self.check_permission(acl, 'test2:tester',
                                               'READ_ACP'))
        self.assertFalse(self.check_permission(acl, 'test2:tester',
                                               'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test2:tester2', 'READ'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2', 'WRITE'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2',
                                               'READ_ACP'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2',
                                               'WRITE_ACP'))

    def test_acl_public_read_write(self):
        acl = ACLPublicReadWrite(Owner(id='test:tester',
                                       name='test:tester'),
                                 s3_acl=self.s3_acl,
                                 allow_no_owner=self.allow_no_owner)

        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2',
                                              'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test2:tester', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test2:tester', 'WRITE'))
        self.assertFalse(self.check_permission(acl, 'test2:tester',
                                               'READ_ACP'))
        self.assertFalse(self.check_permission(acl, 'test2:tester',
                                               'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test2:tester2', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test2:tester2', 'WRITE'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2',
                                               'READ_ACP'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2',
                                               'WRITE_ACP'))

    def test_acl_authenticated_read(self):
        acl = ACLAuthenticatedRead(Owner(id='test:tester',
                                         name='test:tester'),
                                   s3_acl=self.s3_acl,
                                   allow_no_owner=self.allow_no_owner)

        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2',
                                              'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test2:tester', 'READ'))
        self.assertFalse(self.check_permission(acl, 'test2:tester', 'WRITE'))
        self.assertFalse(self.check_permission(acl, 'test2:tester',
                                               'READ_ACP'))
        self.assertFalse(self.check_permission(acl, 'test2:tester',
                                               'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test2:tester2', 'READ'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2', 'WRITE'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2',
                                               'READ_ACP'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2',
                                               'WRITE_ACP'))

    def test_acl_bucket_owner_read(self):
        acl = ACLBucketOwnerRead(
            bucket_owner=Owner('test2:tester', 'test2:tester'),
            object_owner=Owner('test:tester', 'test:tester'),
            s3_acl=self.s3_acl,
            allow_no_owner=self.allow_no_owner)

        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2',
                                              'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test2:tester', 'READ'))
        self.assertFalse(self.check_permission(acl, 'test2:tester', 'WRITE'))
        self.assertFalse(self.check_permission(acl, 'test2:tester',
                                               'READ_ACP'))
        self.assertFalse(self.check_permission(acl, 'test2:tester',
                                               'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test2:tester2', 'READ'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2', 'WRITE'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2',
                                               'READ_ACP'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2',
                                               'WRITE_ACP'))

    def test_acl_bucket_owner_full_control(self):
        acl = ACLBucketOwnerFullControl(
            bucket_owner=Owner('test2:tester', 'test2:tester'),
            object_owner=Owner('test:tester', 'test:tester'),
            s3_acl=self.s3_acl,
            allow_no_owner=self.allow_no_owner)

        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2',
                                              'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test2:tester', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test2:tester', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test2:tester', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test2:tester',
                                              'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test2:tester2', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test2:tester2', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test2:tester2',
                                              'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test2:tester2',
                                              'WRITE_ACP'))

    def test_acl_from_elem(self):
        # check translation from element
        acl = ACLPrivate(Owner(id='test:tester',
                               name='test:tester'),
                         s3_acl=self.s3_acl,
                         allow_no_owner=self.allow_no_owner)
        elem = acl.elem()
        acl = ACL.from_elem(elem, self.s3_acl, self.allow_no_owner)
        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2',
                                              'WRITE_ACP'))
        self.assertFalse(self.check_permission(acl, 'test2:tester', 'READ'))
        self.assertFalse(self.check_permission(acl, 'test2:tester', 'WRITE'))
        self.assertFalse(self.check_permission(acl, 'test2:tester',
                                               'READ_ACP'))
        self.assertFalse(self.check_permission(acl, 'test2:tester',
                                               'WRITE_ACP'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2', 'READ'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2', 'WRITE'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2',
                                               'READ_ACP'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2',
                                               'WRITE_ACP'))

    def test_acl_from_elem_by_id_only(self):
        elem = ACLPrivate(Owner(id='test:tester',
                                name='test:tester'),
                          s3_acl=self.s3_acl,
                          allow_no_owner=self.allow_no_owner).elem()
        elem.find('./Owner').remove(elem.find('./Owner/DisplayName'))
        acl = ACL.from_elem(elem, self.s3_acl, self.allow_no_owner)
        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester', 'WRITE_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'WRITE'))
        self.assertTrue(self.check_permission(acl, 'test:tester2', 'READ_ACP'))
        self.assertTrue(self.check_permission(acl, 'test:tester2',
                                              'WRITE_ACP'))
        self.assertFalse(self.check_permission(acl, 'test2:tester', 'READ'))
        self.assertFalse(self.check_permission(acl, 'test2:tester', 'WRITE'))
        self.assertFalse(self.check_permission(acl, 'test2:tester',
                                               'READ_ACP'))
        self.assertFalse(self.check_permission(acl, 'test2:tester',
                                               'WRITE_ACP'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2', 'READ'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2', 'WRITE'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2',
                                               'READ_ACP'))
        self.assertFalse(self.check_permission(acl, 'test2:tester2',
                                               'WRITE_ACP'))

    def test_acl_elem(self):
        acl = ACLPrivate(Owner(id='test:tester',
                               name='test:tester'),
                         s3_acl=self.s3_acl,
                         allow_no_owner=self.allow_no_owner)
        elem = acl.elem()
        self.assertTrue(elem.find('./Owner') is not None)
        self.assertTrue(elem.find('./AccessControlList') is not None)
        grants = [e for e in elem.findall('./AccessControlList/Grant')]
        self.assertEqual(len(grants), 1)
        self.assertEqual(grants[0].find('./Grantee/ID').text, 'test')
        self.assertEqual(
            grants[0].find('./Grantee/DisplayName').text, 'test')

    def test_decode_acl_container(self):
        access_control_policy = \
            {'Owner': 'test:tester',
             'Grant': [{'Permission': 'FULL_CONTROL',
                        'Grantee': 'test:tester'}]}
        headers = {sysmeta_header('container', 'acl'):
                   json.dumps(access_control_policy)}
        acl = decode_acl('container', headers, self.allow_no_owner)

        self.assertEqual(type(acl), ACL)
        self.assertEqual(acl.owner.id, 'test')
        self.assertEqual(len(acl.grants), 1)
        self.assertEqual(str(acl.grants[0].grantee), 'test')
        self.assertEqual(acl.grants[0].permission, 'FULL_CONTROL')

    def test_decode_acl_object(self):
        access_control_policy = \
            {'Owner': 'test:tester',
             'Grant': [{'Permission': 'FULL_CONTROL',
                        'Grantee': 'test:tester'}]}
        headers = {sysmeta_header('object', 'acl'):
                   json.dumps(access_control_policy)}
        acl = decode_acl('object', headers, self.allow_no_owner)

        self.assertEqual(type(acl), ACL)
        self.assertEqual(acl.owner.id, 'test')
        self.assertEqual(len(acl.grants), 1)
        self.assertEqual(str(acl.grants[0].grantee), 'test')
        self.assertEqual(acl.grants[0].permission, 'FULL_CONTROL')

    def test_encode_acl_container(self):
        acl = ACLPrivate(Owner(id='test:tester',
                               name='test:tester'))
        acp = encode_acl('container', acl)
        header_value = json.loads(acp[sysmeta_header('container', 'acl')])

        self.assertTrue('Owner' in header_value)
        self.assertTrue('Grant' in header_value)
        self.assertEqual('test', header_value['Owner'])
        self.assertEqual(len(header_value['Grant']), 1)

    def test_encode_acl_object(self):
        acl = ACLPrivate(Owner(id='test:tester',
                               name='test:tester'))
        acp = encode_acl('object', acl)
        header_value = json.loads(acp[sysmeta_header('object', 'acl')])

        self.assertTrue('Owner' in header_value)
        self.assertTrue('Grant' in header_value)
        self.assertEqual('test', header_value['Owner'])
        self.assertEqual(len(header_value['Grant']), 1)

    def test_encode_acl_many_grants(self):
        headers = {}
        users = []
        for i in range(0, 99):
            users.append('id=test:tester%d' % i)
        users = ','.join(users)
        headers['x-amz-grant-read'] = users
        acl = ACL.from_headers(headers, Owner('test:tester', 'test:tester'))
        acp = encode_acl('container', acl)

        header_value = acp[sysmeta_header('container', 'acl')]
        header_value = json.loads(header_value)

        self.assertTrue('Owner' in header_value)
        self.assertTrue('Grant' in header_value)
        self.assertEqual('test', header_value['Owner'])
        self.assertEqual(len(header_value['Grant']), 99)

    def test_encode_decode_acl_container(self):
        acl = ACLPrivate(Owner(id='test:tester',
                               name='test:tester'))
        acp = encode_acl('container', acl)
        header_value = json.loads(acp[sysmeta_header('container', 'acl')])
        self.assertTrue('Owner' in header_value)
        self.assertTrue('Grant' in header_value)
        self.assertEqual('test', header_value['Owner'])
        self.assertEqual(len(header_value['Grant']), 1)

        acl = decode_acl('container', acp, self.allow_no_owner)
        self.assertEqual(type(acl), ACL)
        self.assertEqual(acl.owner.id, 'test')
        self.assertEqual(len(acl.grants), 1)
        self.assertEqual(str(acl.grants[0].grantee), 'test')
        self.assertEqual(acl.grants[0].permission, 'FULL_CONTROL')

    def test_encode_decode_acl_object(self):
        acl = ACLPrivate(Owner(id='test:tester',
                               name='test:tester'))
        acp = encode_acl('object', acl)
        header_value = json.loads(acp[sysmeta_header('object', 'acl')])
        self.assertTrue('Owner' in header_value)
        self.assertTrue('Grant' in header_value)
        self.assertEqual('test', header_value['Owner'])
        self.assertEqual(len(header_value['Grant']), 1)

        acl = decode_acl('object', acp, self.allow_no_owner)
        self.assertEqual(type(acl), ACL)
        self.assertEqual(acl.owner.id, 'test')
        self.assertEqual(len(acl.grants), 1)
        self.assertEqual(str(acl.grants[0].grantee), 'test')
        self.assertEqual(acl.grants[0].permission, 'FULL_CONTROL')


if __name__ == '__main__':
    unittest.main()
