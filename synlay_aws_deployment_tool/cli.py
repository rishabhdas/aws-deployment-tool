import click

# Import the SDK
import boto3
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

client = boto3.client('kms')

def create_key_pair(key_size):
    return RSA.generate(key_size)
    # return RSA.generate(4096)

def kms_encrypt_private_key(keypair):
    binPrivKey = keypair.exportKey('DER')

    # response = client.generate_data_key(
    #     KeyId='alias/test-key',
    #     EncryptionContext={
    #         'project': 'Synlay Cloud',
    #         'type': 'Test',
    #     },
    #     KeySpec='AES_256',
    # )
    EncryptResponse = client.encrypt(
        KeyId='alias/test-key',
        Plaintext=binPrivKey,
        EncryptionContext={
            'project': 'Synlay Cloud',
            'type': 'Test',
        }
    )
    return (EncryptResponse['CiphertextBlob'], EncryptResponse['KeyId'])

def kms_decrypt_private_key(ciphertext_blob):
    DecryptResponse = client.decrypt(
        CiphertextBlob=ciphertext_blob,
        EncryptionContext={
            'project': 'Synlay Cloud',
            'type': 'Test',
        }
    )
    return (DecryptResponse['Plaintext'], DecryptResponse['KeyId'])

def encrypt(message, keypair):
    binPubKey =  keypair.publickey().exportKey('DER')
    pubKeyObj =  RSA.importKey(binPubKey)

    cipher = PKCS1_OAEP.new(pubKeyObj)
    return cipher.encrypt(message)

def decrypt(ciphertext, keypair):
    binPrivKey = keypair.exportKey('DER')

    privKeyObj = RSA.importKey(binPrivKey)
    cipher = PKCS1_OAEP.new(privKeyObj)
    return cipher.decrypt(ciphertext)

def kms_decrypt(ciphertext_blob, chiper_text):
    (PrivateKey, KeyId) = kms_decrypt_private_key(ciphertext_blob)

    privKeyObj = RSA.importKey(PrivateKey)
    cipher = PKCS1_OAEP.new(privKeyObj)
    return cipher.decrypt(chiper_text)

# @click.command()
# @click.option('--as-cowboy', '-c', is_flag=True, help='Greet as a cowboy.')
# @click.argument('name', default='world', required=False)
# def main(name, as_cowboy):
#     """Synlay AWS Deployment Tool"""
#     greet = 'Howdy' if as_cowboy else 'Hello'
#     click.echo('{0}, {1}.'.format(greet, name))

@click.command()
@click.option('--create_new_key_pair', '-ckp', is_flag=True, default=False, help='Start AWS KMS encryption/decription test.')
@click.option('--key_size', '-ks', is_flag=False, default=1024, help='Start AWS KMS encryption/decription test.')
# @click.argument('aws_key', default='', required=True)
# @click.argument('aws_secret', default='', required=True)
# def main(aws_key, aws_secret):
def main(create_new_key_pair, key_size):
    """Synlay AWS Deployment Tool"""
    # if create_new_key_pair:
    KeyPair = create_key_pair(key_size)

    (CiphertextBlob, KeyId) = kms_encrypt_private_key(KeyPair)
    ChiperText = encrypt(b'Hello World!', KeyPair)

    # click.echo("Decrypted: %s" % KeyPair.exportKey('PEM'))
    # click.echo("Decrypted: %s" % KeyPair.publickey().exportKey('PEM'))

    click.echo("Decrypted: %s" % kms_decrypt(CiphertextBlob, ChiperText))

    # greet = 'Howdy' if as_cowboy else 'Hello'
    click.echo('{0}, {1}.'.format(KeyId, key_size))
