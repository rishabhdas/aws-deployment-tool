# -*- coding: utf-8 -*-

import pytest
from click.testing import CliRunner
from synlay_aws_deployment_tool import cli


@pytest.fixture
def runner():
    return CliRunner()

# def test_cli(runner):
#     result = runner.invoke(cli.main)
#     assert True

def test_create_new_encryption_keys(runner):
    import os
    from Crypto.PublicKey import RSA

    with runner.isolated_filesystem():
        result = runner.invoke(cli.cli, ['create_new_key_pair', '--project=TestApp',
                                         '--configuration-deployment-path=decrypted_test_file.txt',
                                         '--public-key-file=public_key.pem',
                                         '--encrypted-private-key-file=private_key.sec', '-ks=1024'])
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
        assert key.size() + 1 == 1024

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
