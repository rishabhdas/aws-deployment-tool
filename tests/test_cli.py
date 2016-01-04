# -*- coding: utf-8 -*-

import os
import pytest

from click.testing import CliRunner
from synlay_aws_deployment_tool import cli

from Crypto.PublicKey import RSA

from hypothesis import given
import hypothesis.strategies as st

@pytest.fixture(params=[ (rsa_key_size, aes_key_size) for rsa_key_size in [1024, 2048, 4096]
                                                      for aes_key_size in [16, 24, 32]])
def context(request):
    return {
        'runner': CliRunner(),
        'rsa_key': RSA.generate(request.param[0]),
        'rsa_key_size': request.param[0],
        'aes_key_size': request.param[1]
    }

@given(message=st.text(min_size=1))
def test_encrypt_decrypt(context, message):
    rsaKey = context['rsa_key']
    assert cli.decrypt_helper(cli.encrypt_helper(message.encode('ascii', 'xmlcharrefreplace'),
                                                 rsaKey, context['aes_key_size']),
                              rsaKey) == message.encode('ascii', 'xmlcharrefreplace')

def test_create_new_encryption_keys(context):

    runner = context['runner']

    with runner.isolated_filesystem():
        result = runner.invoke(cli.cli, ['create_new_key_pair', '--project=TestApp',
                                         '--configuration-deployment-path=decrypted_test_file.txt',
                                         '--public-key-file=public_key.pem',
                                         '--encrypted-private-key-file=private_key.sec',
                                         '-ks=' + str(context['rsa_key_size'])])
        assert result.exit_code == 0

        assert os.path.isfile('public_key.pem')
        assert os.path.isfile('private_key.sec')

        key = None
        try:
            with open('public_key.pem', 'r') as f:
                key = RSA.importKey(f.read())
        except Exception as e:
            pytest.fail("Importing RSA public key failed")

        assert not key.has_private()
        assert key.can_encrypt()
        assert key.size() + 1 == context['rsa_key_size']

        with pytest.raises(ValueError):
            with open('private_key.sec', 'r') as f:
                RSA.importKey(f.read())

# def test_cli(runner):
#     result = runner.invoke(cli.main)
#     assert result.exit_code == 0
#     assert not result.exception
#     assert result.output.strip() == 'Hello, world.'


# def test_cli_with_option(runner):
#     result = runner.invoke(cli.main, ['--as-cowboy'])
#     assert not result.exception
#     assert result.exit_code == 0
#     assert result.output.strip() == 'Howdy, world.'


# def test_cli_with_arg(runner):
#     result = runner.invoke(cli.main, ['David'])
#     assert result.exit_code == 0
#     assert not result.exception
#     assert result.output.strip() == 'Hello, David.'
