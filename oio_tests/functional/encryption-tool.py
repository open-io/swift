#!/usr/bin/env python

import unittest
import tempfile
import subprocess
import json

from oio_tests.functional.common import (
    random_str,
    run_awscli_s3,
    run_awscli_s3api,
    run_openiocli,
    CliError,
)

TRANSIENT_CRYPTO_META_KEY = "x-object-transient-sysmeta-crypto-meta"
CRYPTO_ETAG_KEY = "x-object-sysmeta-crypto-etag"
CRYPTO_BODY_META_KEY = "x-object-sysmeta-crypto-body-meta"
CRYPTO_ETAG_MAC_KEY = "x-object-sysmeta-crypto-etag-mac"
CONTAINER_UPDATE_OVERRIDE_ETAG_KEY = "x-object-sysmeta-container-update-override-etag"
OBJECT_TRANSIENT_SYSMETA_CRYPTO_META_PREFIX = "x-object-transient-sysmeta-crypto-meta-"


class TestEncryptionTool(unittest.TestCase):
    def setUp(self):
        self.account = "AUTH_demo"
        self.bucket = random_str(10)
        data = run_awscli_s3api("create-bucket", bucket=self.bucket)
        self.assertEqual("/%s" % self.bucket, data["Location"])

    def tearDown(self):
        try:
            run_awscli_s3("rb", "--force", bucket=self.bucket)
        except CliError as exc:
            if "NoSuchBucket" not in str(exc):
                raise

    def test_object_re_encryption(self):
        object = random_str(10)
        body = random_str(10).encode()
        user_metadata = {
            "keyname1": random_str(10),
            "keyname2": random_str(10),
        }
        user_metadata_str = ""
        for k, v in user_metadata.items():
            user_metadata_str += k + "=" + v + ","
        user_metadata_str = user_metadata_str[:-1]
        with tempfile.NamedTemporaryFile() as file:
            file.write(body)
            file.flush()
            run_awscli_s3api(
                "put-object",
                "--body",
                file.name,
                "--metadata",
                user_metadata_str,
                bucket=self.bucket,
                key=object,
            )

        with tempfile.NamedTemporaryFile() as metadata_json_file, tempfile.NamedTemporaryFile() as encrypted_data_file, tempfile.NamedTemporaryFile() as iv_json_file:

            p = subprocess.Popen(["ls", "-altr", "./third_party/oio-sds/tools/"])
            p.communicate()
            print(p.stdout)
            # Metadata
            cmd = [
                "./third_party/oio-sds/tools/get-metadata.py",
                "--account",
                self.account,
                "--container",
                self.bucket,
                "--obj",
                object,
            ]
            print(*cmd)
            process_metadata = subprocess.Popen(cmd, stdout=metadata_json_file)
            process_metadata.communicate()
            metadata_json_file.seek(0)
            start_metadata = metadata_json_file.read()

            # Encrypted data
            run_openiocli(
                "object",
                "save",
                self.bucket,
                object,
                "--file",
                encrypted_data_file.name,
                account="AUTH_demo",
                json_format=False,
            )

            process1 = subprocess.Popen(
                ["cat", encrypted_data_file.name], stdout=subprocess.PIPE
            )

            # Decrypt data
            cmd = [
                "./third_party/oio-sds/tools/decrypter.py",
                "--account",
                self.account,
                "--container",
                self.bucket,
                "--obj",
                object,
                "--metadata",
                metadata_json_file.name,
                "--iv",
                iv_json_file.name,
            ]
            print(*cmd)
            process2 = subprocess.Popen(
                cmd, stdin=process1.stdout, stdout=subprocess.PIPE
            )
            decrypted_data, err = process2.communicate()
            metadata_json_file.seek(0)
            m = metadata_json_file.read()

            self.assertEqual(body, decrypted_data)

            meta = json.loads(m)
            for k, v in user_metadata.items():
                self.assertEqual(meta.get("properties").get("X-Object-Meta-" + k), v)

            # Re encrypt obj
            cmd = [
                "./third_party/oio-sds/tools/encrypter.py",
                "--account",
                self.account,
                "--container",
                self.bucket,
                "--obj",
                object,
                "--metadata",
                metadata_json_file.name,
                "--iv",
                iv_json_file.name,
            ]
            print(*cmd)
            process3 = subprocess.Popen(
                cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE
            )
            process3.stdin.write(decrypted_data)
            reecrypted_data, err = process3.communicate()

            # curl kms

            # New metadata
            cmd = [
                "./third_party/oio-sds/tools/get-metadata.py",
                "--account",
                self.account,
                "--container",
                self.bucket,
                "--obj",
                object,
            ]
            print(*cmd)
            subprocess.Popen(cmd, stdout=metadata_json_file)
            metadata_json_file.seek(0)
            reencrypted_metadata = metadata_json_file.read()

            properties = [
                TRANSIENT_CRYPTO_META_KEY,
                CRYPTO_ETAG_KEY,
                CRYPTO_BODY_META_KEY,
                CRYPTO_ETAG_MAC_KEY,
                CONTAINER_UPDATE_OVERRIDE_ETAG_KEY,
            ]
            user_metadata_keys = list(user_metadata.keys())
            for key in user_metadata_keys:
                properties.append(OBJECT_TRANSIENT_SYSMETA_CRYPTO_META_PREFIX + key)
            for property in properties:
                self.assertNotEqual(
                    json.loads(start_metadata).get("properties").get(property),
                    json.loads(reencrypted_metadata).get("properties").get(property),
                )
            other_metadata_keys = list(json.loads(start_metadata).keys())
            other_metadata_keys.remove("properties")
            for key in other_metadata_keys:
                self.assertEqual(
                    json.loads(start_metadata).get(key),
                    json.loads(reencrypted_metadata).get(key),
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
