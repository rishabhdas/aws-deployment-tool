# coding: utf-8

import os
import click

# Import the SDK
import boto3
from boto3.s3.transfer import S3Transfer

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

try:
    kmsClient = boto3.client('kms')
except Exception, e:
    print("Error while trying to initialize aws client: '%s'" % e)
    exit()

class SynlayAWSEncryptionContext(object):
    def __init__(self, project, configurationDeploymentPath):
        self._project = project
        self._configurationDeploymentPath = configurationDeploymentPath

    def aws_encryption_context(self):
        return {
            'project': self._project,
            'configuration_deployment_path': self._configurationDeploymentPath,
        }

def create_key_pair(keySize):
    return RSA.generate(keySize)

def kms_encrypt_private_key(kmsClient, encryptionKeyPair, awsKmsKeyId, awsEncryptionContext):
    binPrivKey = encryptionKeyPair.exportKey('DER')
    EncryptResponse = kmsClient.encrypt(
        KeyId=awsKmsKeyId,
        Plaintext=binPrivKey,
        EncryptionContext=awsEncryptionContext
    )
    return EncryptResponse['CiphertextBlob']

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

# @click.command()
# @click.option('--create_new_key_pair', '-ckp', is_flag=True, default=False, help='Start AWS KMS encryption/decription test.')
# @click.option('--key_size', '-ks', is_flag=False, default=1024, help='Start AWS KMS encryption/decription test.')
# # @click.argument('aws_key', default='', required=True)
# # @click.argument('aws_secret', default='', required=True)
# # def main(aws_key, aws_secret):
# def main(create_new_key_pair, key_size):
#     """Synlay AWS Deployment Tool"""
#     # if create_new_key_pair:
#     KeyPair = create_key_pair(key_size)

#     (CiphertextBlob, KeyId) = kms_encrypt_private_key(KeyPair)
#     ChiperText = encrypt(b'Hello World!', KeyPair)

#     # click.echo("Decrypted: %s" % KeyPair.exportKey('PEM'))
#     # click.echo("Decrypted: %s" % KeyPair.publickey().exportKey('PEM'))

#     click.echo("Decrypted: %s" % kms_decrypt(CiphertextBlob, ChiperText))

#     # greet = 'Howdy' if as_cowboy else 'Hello'
#     click.echo('{0}, {1}.'.format(KeyId, key_size))

@click.group()
def cli():
    """Synlay AWS Deployment Tool

       Environment vars:
       AWS_ACCESS_KEY_ID - The access key for your AWS account.
       AWS_SECRET_ACCESS_KEY - The secret key for your AWS account.
       AWS_DEFAULT_REGION - The default region to use, e.g. us-east-1.
       AWS_PROFILE - The default credential and configuration profile to use, if any.
    """
    pass

@cli.command()
def encrypt(publicKey, fileToEncrypt, laterDeploymentContext):
    """Encrypt a given file with the public key."""
    click.echo('Initialized the database')

@cli.command()
def decrypt():
    click.echo('Dropped the database')

# aws_access_key_id, aws_secret_access_key and aws_region will be determined through the environment or extracted from ~/.aws/credentials
@cli.command()
@click.option('--aws-kms-key-id', 'awsKmsKeyId', envvar='SYNLAY_AWS_KMS_KEY_ID', required=True)
@click.option('--project', '-p', prompt='Enter the project name', help='Used as part of the encryption context of the AWS KMS service.', required=True)
@click.option('--key-size', '-ks', 'keySize', default=1024, type=click.IntRange(1024, 4096, clamp=True), help='Configure the key size.', required=True)
@click.option('--public-key-file', '-pkf', 'publicKeyFile', prompt='Public key file path and name', default='./public_key.pem', type=click.File(mode='w'), required=True, help='Path where the generated public key should be exported to.')
@click.option('--encrypted-private-key-file', '-epkf', 'encryptedPrivateKeyFile', prompt='Encrypted private key file path and name', default='./private_key.sec', type=click.File(mode='wb'), required=True, help='Path where the generated and encrypted private key should be exported to.')
@click.option('--configuration-deployment-path', '-cdp', 'configurationDeploymentPath', prompt='Enter the path where the future decrypted configuration file will be deployed', type=click.Path(resolve_path='True'), required=True, help='Path where final decrypted configuration file will be deployed. Parts of the path will be used to generate an ecnryption contex for the AWS KMS service.')
@click.pass_context
def create_new_key_pair(ctx, awsKmsKeyId, project, keySize, publicKeyFile, encryptedPrivateKeyFile, configurationDeploymentPath):
    """Create a new encryption RSA keypair, where the private keyfile will be encrypted using the AWS KMS service."""
    keyPair = create_key_pair(keySize)

    awsEncryptionContext = SynlayAWSEncryptionContext(project, configurationDeploymentPath).aws_encryption_context()
    ciphertextBlob = kms_encrypt_private_key(kmsClient, keyPair, awsKmsKeyId, awsEncryptionContext)

    publicKeyFile.write(keyPair.publickey().exportKey('PEM'))
    publicKeyFile.close()
    del keyPair
    encryptedPrivateKeyFile.write(ciphertextBlob)
    encryptedPrivateKeyFile.close()

    # if click.confirm('Do you wan\'t to upload the encrypted key file to S3?'):
    #     ctx.forward(upload_encrypted_private_key_to_s3, privateFile=encryptedPrivateKeyFile, s3Url=None)
    #     click.echo('Well done!')

@cli.command()
@click.option('--encrypted_private_key_file', 'privateFile', prompt='Encrypted private key file path and name', default='./private_key.sec', type=click.Path(exists=True, readable=True), required=True, help='Path where the generated private key file is located.')
@click.option('--bucket', prompt='S3 bucket to upload the encrypted file to', default='synlay-deployment-keys', required=True, help='Bucket where the encrypted private key file should be uploaded to.')
@click.option('--bucket_key_filename', 'bucketKeyFilename', help='Filename which should be used to save the file in the bucket.')
@click.option('--keep_private_file', '--k', 'keepPrivateFile', is_flag=True, default=False)
def upload_encrypted_private_key_to_s3(privateFile, bucket, bucketKeyFilename, keepPrivateFile):
    # client = boto3.client('s3', 'us-west-2')
    client = boto3.client('s3')
    transfer = S3Transfer(client)
    basename = os.path.basename(privateFile)
    bucketKeyFilename = bucketKeyFilename if not bucketKeyFilename is None else basename
    transfer.upload_file(privateFile, bucket, bucketKeyFilename, extra_args={'ServerSideEncryption': 'AES256'})
    if not keepPrivateFile:
        os.remove(basename)

def main():
    cli()
