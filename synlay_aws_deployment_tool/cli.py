# coding: utf-8

import os
import tempfile
import subprocess

# Import the SDK
import click
import boto3
from boto3.s3.transfer import S3Transfer
from botocore.exceptions import ClientError

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

@click.group()
@click.option('--debug', is_flag=True, default=False, help='Show the stacktrace when errors occur')
@click.pass_context
def cli(ctx, debug):
    """Synlay AWS Deployment Tool

       Common AWS specific configuration and credentials arguments will
       be determined through the environment or will be
       extracted from ~/.aws/credentials

       Possible environment variables:

       AWS_ACCESS_KEY_ID - The access key for your AWS account.
       AWS_SECRET_ACCESS_KEY - The secret key for your AWS account.
       AWS_DEFAULT_REGION - The default region to use, e.g. us-east-1.
       AWS_PROFILE - The default credential and configuration profile to use, if any.
       SYNLAY_AWS_KMS_KEY_ID - The AWS KMS key id to used to encrypt/decrypt data.
    """
    ctx.obj = SynlayErrorHandler(debug)

@cli.command()
@click.option('--public-key-file', '-pkf', 'publicKeyFile', prompt='Public key file path and name', default='./public_key.pem', type=click.File(mode='r'), required=True, help='Path where the generated public key is located.')
@click.option('--file-to-encrypt', '-fte', 'fileToEncrypt', prompt='File to encrypt', type=click.File(mode='r'), required=True)
@click.option('--encrypt-to-file', 'encryptToFile', prompt='File path and name where the chipher text should be saved', type=click.File(mode='wb'), required=True)
@click.option('--keep_original_file', '-k', 'keepOriginalFile', is_flag=True, default=False)
@click.pass_context
def encrypt(ctx, publicKeyFile, fileToEncrypt, encryptToFile, keepOriginalFile):
    """Encrypt a given 'fileToEncrypt' with the 'publicKeyFile' using the RSA encryption protocol
    according to PKCS#1 OAEP. The encrypted content will be exported to 'encryptToFile'."""

    try:
        publicKey = RSA.importKey(publicKeyFile.read())
        encryptToFile.write(encrypt_helper(fileToEncrypt.read(), publicKey))
        encryptToFile.close()
        if not keepOriginalFile:
            os.remove(fileToEncrypt.name)
    except Exception, e:
        ctx.obj.unkown_error(e, 'Some error occured while trying to encrypt a file: %s')

@cli.command()
@click.option('--aws-kms-key-id', 'awsKmsKeyId', envvar='SYNLAY_AWS_KMS_KEY_ID', required=True, help='The AWS KMS key id to used to encrypt/decrypt data, can also be specified through the \'SYNLAY_AWS_KMS_KEY_ID\' environment variable.')
@click.option('--project', '-p', prompt='Enter the project name', help='Used as part of the encryption context of the AWS KMS service.', required=True)
@click.option('--configuration-deployment-path', '-cdp', 'configurationDeploymentPath', type=click.File(mode='w'), required=True, help='Path where final decrypted data file will be exported to. Parts of the path will be used to generate an ecnryption contex for the AWS KMS service.')
@click.option('--key-bucket', 'keyBucket', default='synlay-deployment-keys', required=True, help='Bucket where the encrypted private key file can be downloaded from.')
@click.option('--key-bucket-filename', 'keyBucketFilename', required=True, help='Filename from the encryption key in the key bucket.')
@click.option('--data-bucket', 'dataBucket', default='synlay-deployment-data', required=True, help='Bucket where the encrypted data can be downloaded from.')
@click.option('--data-bucket-filename', 'dataBucketFilename', required=True, help='Filename from the encryption file in the data bucket.')
@click.pass_context
def decrypt(ctx, awsKmsKeyId, project, configurationDeploymentPath, keyBucket, keyBucketFilename, dataBucket, dataBucketFilename):
    """Decrypt s3://dataBucket/dataBucketFilename with a private key from s3://keyBucket/keyBucketFilename using
    the RSA encryption protocol according to PKCS#1 OAEP. The private key is suposed to be encrypted with the AWS KMS service
    and will be decrypted with the 'awsKmsKeyId' and 'project'/'configurationDeploymentPath' as
    the decryption context prior to the decryption of 'dataBucketFilename'."""

    kmsClient = create_kms_client(ctx)
    transfer = create_s3_transfer(ctx)

    tmpEncryptedPrivateKey = tempfile.NamedTemporaryFile()
    tmpEncryptedDataFile = tempfile.NamedTemporaryFile()
    try:
        transfer.download_file(keyBucket, keyBucketFilename, tmpEncryptedPrivateKey.name)
        awsEncryptionContext = SynlayAWSEncryptionContext(project, configurationDeploymentPath.name).aws_encryption_context()
        with open(tmpEncryptedPrivateKey.name, 'r') as f:
            key = kms_decrypt_private_key(kmsClient, f.read(), awsEncryptionContext)

        transfer.download_file(dataBucket, dataBucketFilename, tmpEncryptedDataFile.name)
        with open(tmpEncryptedDataFile.name, 'r') as f2:
            decryptedData = decrypt_helper(f2.read(), key)

        # immediately remove private key from memory
        del key
        configurationDeploymentPath.write(decryptedData)
        configurationDeploymentPath.close()
        # immediately remove decrypted data from memory
        del decryptedData
    except ClientError, ce:
        ctx.obj.aws_client_error(ce)
    except Exception, e:
        ctx.obj.unkown_error(e, 'Some unkown error occured while trying to decrypt a file from S3: %s')
    finally:
        # On unix systems try to delete securely with srm and ignore the exit code
        subprocess.call(["srm", "-f", tmpEncryptedPrivateKey.name, tmpEncryptedDataFile.name])

        if os.path.isfile(tmpEncryptedPrivateKey.name):
            os.remove(tmpEncryptedPrivateKey.name)
        if os.path.isfile(tmpEncryptedDataFile.name):
            os.remove(tmpEncryptedDataFile.name)

@cli.command()
@click.option('--aws-kms-key-id', 'awsKmsKeyId', envvar='SYNLAY_AWS_KMS_KEY_ID', required=True, help='The AWS KMS key id to used to encrypt/decrypt data, can also be specified through the \'SYNLAY_AWS_KMS_KEY_ID\' environment variable.')
@click.option('--project', '-p', prompt='Enter the project name', help='Used as part of the encryption context of the AWS KMS service.', required=True)
@click.option('--configuration-deployment-path', '-cdp', 'configurationDeploymentPath', prompt='Enter the path where the future decrypted configuration file will be deployed', type=click.Path(), required=True, help='Path where final decrypted configuration file will be deployed. Parts of the path will be used to generate an ecnryption contex for the AWS KMS service.')
@click.option('--key-size', '-ks', 'keySize', default=1024, type=click.IntRange(1024, 4096, clamp=True), help='Configure the key size.', required=True)
@click.option('--public-key-file', '-pkf', 'publicKeyFile', prompt='Public key file path and name', default='./public_key.pem', type=click.File(mode='w'), required=True, help='Path where the generated public key should be exported to.')
@click.option('--encrypted-private-key-file', '-epkf', 'encryptedPrivateKeyFile', prompt='Encrypted private key file path and name', default='./private_key.sec', type=click.File(mode='wb'), required=True, help='Path where the generated and encrypted private key should be exported to.')
@click.pass_context
def create_new_key_pair(ctx, awsKmsKeyId, project, configurationDeploymentPath, keySize, publicKeyFile, encryptedPrivateKeyFile):
    """Create a new encryption RSA keypair, where the private keyfile will be encrypted using the AWS KMS service."""
    
    kmsClient = create_kms_client(ctx)
    keyPair = create_key_pair(keySize)
    awsEncryptionContext = SynlayAWSEncryptionContext(project, configurationDeploymentPath).aws_encryption_context()

    try:
        ciphertextBlob = kms_encrypt_private_key(kmsClient, keyPair, awsKmsKeyId, awsEncryptionContext)

        publicKeyFile.write(keyPair.publickey().exportKey('PEM'))
        publicKeyFile.close()
        del keyPair
        encryptedPrivateKeyFile.write(ciphertextBlob)
        encryptedPrivateKeyFile.close()

        # if click.confirm('Do you wan\'t to upload the encrypted key file to S3?'):
        #     ctx.forward(upload_encrypted_private_key_to_s3, privateFile=encryptedPrivateKeyFile, s3Url=None)
        #     click.echo('Well done!')
    except ClientError, ce:
        ctx.obj.aws_client_error(ce)
    except Exception, e:
        ctx.obj.unkown_error(e, 'Some unkown error occured while trying to create a new RSA keypair: %s')

@cli.command()
@click.option('--file', prompt='File path and name', default='./private_key.sec', type=click.Path(exists=True, readable=True, resolve_path=True), required=True, help='Path where the file is located which should be uploaded to S3.')
@click.option('--bucket', prompt='S3 bucket name to upload the file to', default='synlay-deployment-keys', required=True, help='Bucket name where the file should be uploaded to.')
@click.option('--bucket_filename', 'bucketFilename', help='Filename which should be used to save the file in the bucket.')
@click.option('--keep_original_file', '--k', 'keepOriginalFile', is_flag=True, default=False)
@click.pass_context
def upload_file_to_s3(ctx, file, bucket, bucketFilename, keepOriginalFile):
    """Simple file upload to a S3 bucket with server side AWS256 encryption enabled."""
    transfer = create_s3_transfer(ctx)
    try:
        bucketFilename = bucketFilename if not bucketFilename is None else os.path.basename(file)
        transfer.upload_file(file, bucket, bucketFilename, extra_args={'ServerSideEncryption': 'AES256'})
        if not keepOriginalFile:
            # On unix systems try to delete securely with srm and ignore the exit code
            subprocess.call(["srm", "-f", file])
            if os.path.isfile(file):
                os.remove(file)
    except ClientError, ce:
        ctx.obj.aws_client_error(ce)
    except Exception, e:
        ctx.obj.unkown_error(e, 'Some unkown error occured while trying to upload a file to S3: %s')

def main():
    cli(obj=None)

# =========================================================
#                       Internals
# =========================================================

class SynlayErrorHandler(object):
    def __init__(self, debug):
        self.debug = debug

    def unkown_error(self, exception, customMessage, debug=True):
        self.log_error(customMessage % exception)
        if debug:
            self.maybe_debug_exception(exception)

    def aws_client_error(self, clientError):
        errorCode = clientError.response['Error']['Code']
        if errorCode == 'InvalidCiphertextException':
            self.log_error("Invalid encryption/decryption context setup")
        elif errorCode == 'AccessDeniedException':
            self.log_error('Access denied while trying to access an AWS service')
        else:
            self.unkown_error(clientError, 'Some unkown AWS service error occured: %s', debug=False)
        self.maybe_debug_exception(clientError)

    def log_error(self, message):
        click.echo(click.style(message, fg='red'))

    def maybe_debug_exception(self, exception):
        if self.debug:
            raise exception

class SynlayAWSEncryptionContext(object):
    def __init__(self, project, configurationDeploymentPath):
        self._project = project
        self._configurationDeploymentPath = configurationDeploymentPath

    def aws_encryption_context(self):
        return {
            'project': self._project,
            'configuration_deployment_path': self._configurationDeploymentPath,
        }

def create_kms_client(ctx):
    """Boto3 KMS client factory"""
    try:
        return boto3.client('kms')
    except Exception, e:
        ctx.obj.unkown_error(e, "Error while trying to initialize aws kms client: '%s'")
        exit()

def create_s3_transfer(ctx):
    """Boto3 S3 transfer factory"""
    try:
        client = boto3.client('s3')
        return S3Transfer(client)
    except Exception, e:
        ctx.obj.unkown_error(e, "Error while trying to initialize aws s3 transfer: '%s'")
        exit()

def create_key_pair(keySize):
    """Generate a RSA key pair with 'keySize'"""
    return RSA.generate(keySize)

def kms_encrypt_private_key(kmsClient, encryptionKeyPair, awsKmsKeyId, awsEncryptionContext):
    """Encrypt the private key from 'encryptionKeyPair' through the AWS KMS service
    with the key 'awsKmsKeyId' and the 'awsEncryptionContext'
    @return plain chiphertext blob"""
    binPrivKey = encryptionKeyPair.exportKey('DER')
    EncryptResponse = kmsClient.encrypt(
        KeyId=awsKmsKeyId,
        Plaintext=binPrivKey,
        EncryptionContext=awsEncryptionContext
    )
    return EncryptResponse['CiphertextBlob']

def kms_decrypt_private_key(kmsClient, ciphertextBlob, awsEncryptionContext):
    """Decrypt the private key defined as 'ciphertextBlob' through the AWS KMS service
    with the 'awsEncryptionContext'
    @return RSA key object"""
    DecryptResponse = kmsClient.decrypt(
        CiphertextBlob=ciphertextBlob,
        EncryptionContext=awsEncryptionContext
    )
    return RSA.importKey(DecryptResponse['Plaintext'])

def encrypt_helper(message, key):
    """Encrypt 'message' with the public key part from 'key' using
    the RSA encryption protocol according to PKCS#1 OAEP
    @return encrypted ciphertext blob
    """
    binPubKey = key.publickey().exportKey('DER')
    pubKeyObj = RSA.importKey(binPubKey)
    cipher = PKCS1_OAEP.new(pubKeyObj)
    return cipher.encrypt(message)

def decrypt_helper(ciphertext, key):
    """Decrypt 'ciphertext' with the private key part from 'key' using
    the RSA encryption protocol according to PKCS#1 OAEP
    @return decrypted text blob
    """
    binPrivKey = key.exportKey('DER')
    privKeyObj = RSA.importKey(binPrivKey)
    cipher = PKCS1_OAEP.new(privKeyObj)
    return cipher.decrypt(ciphertext)
