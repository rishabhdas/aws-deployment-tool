# -*- coding: utf-8 -*-

import sys
import os
import tempfile
import subprocess
import threading

# Import the SDK
import click
import boto3
from boto3.s3.transfer import S3Transfer
from botocore.exceptions import ClientError

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from Crypto.Cipher import AES
from Crypto import Random
import struct

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option('--debug', is_flag=True, default=False, help='Show the stacktrace when errors occur')
@click.pass_context
def cli(ctx, debug):
    """Synlay AWS Deployment Tool

       Common AWS specific configuration and credentials arguments will
       be determined through the environment or will be
       extracted from ~/.aws/credentials

       Possible environment variables:

       \b
       AWS_ACCESS_KEY_ID - The access key for your AWS account.
       AWS_SECRET_ACCESS_KEY - The secret key for your AWS account.
       AWS_DEFAULT_REGION - The default region to use, e.g. us-east-1.
       AWS_PROFILE - The default credential and configuration profile to use, if any.
       SYNLAY_AWS_KMS_KEY_ID - The AWS KMS key id to used to encrypt/decrypt data.
    """
    ctx.obj = SynlayErrorHandler(debug)


@cli.command(short_help='encrypt files using RSA encryption')
@click.option('--public-key-file', '-pkf', 'publicKeyFile', prompt='Public key file path and name', default='./public_key.pem', type=click.File(mode='r'), required=True, help='Path where the generated public key is located.')
@click.option('--file-to-encrypt', '-fte', 'fileToEncrypt', prompt='File to encrypt', type=click.File(mode='r'), required=True)
@click.option('--encrypt-to-file', 'encryptToFile', prompt='File path and name where the chipher text should be saved', type=click.File(mode='wb'), required=True)
@click.option('--aes-key-size', 'aesKeySize', prompt='AES key size in bytes - 16 (AES-128), 24 (AES-192), or 32 (AES-256)', type=click.Choice([16, 24, 32]), default=32)
@click.option('--keep_original_file', '-k', 'keepOriginalFile', is_flag=True, default=False)
@click.pass_context
def encrypt(ctx, publicKeyFile, fileToEncrypt, encryptToFile, aesKeySize, keepOriginalFile):
    """Symetric AES encryption of 'fileToEncrypt' with a randomly generated key
    of the size 'aesKeySize'. The randomly generated encription key will
    be encrypted with 'publicKeyFile' using the RSA encryption protocol
    according to PKCS#1 OAEP. The encrypted ciphertext blob will be exported
    to 'encryptToFile' and includes the initialization vector alongside with
    the AWS key cipher length and the encrypted AES key itself.
    """
    ctx.obj.log_status('Encrypting data file \'%s\' with public RSA key \'%s\' and saving it to \'%s\'...' % (fileToEncrypt.name, publicKeyFile.name, encryptToFile.name))
    try:
        publicKey = RSA.importKey(publicKeyFile.read())
        encryptToFile.write(encrypt_helper(fileToEncrypt.read(), publicKey, aesKeySize))
        encryptToFile.close()
        if not keepOriginalFile:
            ctx.obj.log_status('Removing the original data file \'%s\'...' % fileToEncrypt.name)
            # On unix systems try to delete securely with srm and ignore the exit code
            subprocess.call(["srm", "-f", fileToEncrypt.name])
            if os.path.isfile(fileToEncrypt.name):
                os.remove(fileToEncrypt.name)
    except Exception as e:
        ctx.obj.unkown_error(e, 'Some error occured while trying to encrypt a file: %s')
        sys.exit()


@cli.command(short_help='decrypt files from S3 using RSA encryption')
@click.option('--project', '-p', prompt='Enter the project name', help='Used as part of the encryption context of the AWS KMS service.', required=True)
@click.option('--configuration-deployment-path', '-cdp', 'configurationDeploymentPath', type=click.File(mode='w'), required=True, help='Path where final decrypted data file will be exported to. Parts of the path will be used to generate an ecnryption contex for the AWS KMS service.')
@click.option('--key-bucket', 'keyBucket', default='synlay-deployment-keys', required=True, help='Bucket where the encrypted private key file can be downloaded from.')
@click.option('--key-bucket-filename', 'keyBucketFilename', required=True, help='Filename from the encryption key in the key bucket.')
@click.option('--data-bucket', 'dataBucket', default='synlay-deployment-data', required=True, help='Bucket where the encrypted data can be downloaded from.')
@click.option('--data-bucket-filename', 'dataBucketFilename', required=True, help='Filename from the encryption file in the data bucket.')
@click.pass_context
def decrypt(ctx, project, configurationDeploymentPath, keyBucket, keyBucketFilename, dataBucket, dataBucketFilename):
    """Hybrid decryption of s3://dataBucket/dataBucketFilename, where the actual encrypted AES encryption key,
    which is also part of 'dataBucketFilename', will be decrypted with a private key
    from s3://keyBucket/keyBucketFilename using the RSA encryption protocol according to PKCS#1 OAEP. The private key is
    suposed to be encrypted with the AWS KMS service and will be decrypted with the 'awsKmsKeyId' and
    'project'/'configurationDeploymentPath' as the decryption context prior to the decryption of 'dataBucketFilename'.
    The actual decrypted blob will be saved under 'project'/'configurationDeploymentPath'.
    """
    kmsClient = create_kms_client(ctx)
    s3 = create_s3_resource(ctx)
    transfer = create_s3_transfer(ctx)

    tmpEncryptedPrivateKey = tempfile.NamedTemporaryFile(delete=True)
    tmpEncryptedDataFile = tempfile.NamedTemporaryFile(delete=True)
    try:
        ctx.obj.log_status('Downloading encrypted private key file from S3 \'s3://%s/%s\' to %s...' % (keyBucket, keyBucketFilename, tmpEncryptedPrivateKey.name))

        s3_transfer_progress_bar_helper('Downloading file', s3.Object(keyBucket, keyBucketFilename).content_length,
                                        lambda progressBar: transfer.download_file(keyBucket, keyBucketFilename,
                                                                                   tmpEncryptedPrivateKey.name, callback=progressBar))

        awsEncryptionContext = SynlayAWSEncryptionContext(project, configurationDeploymentPath.name).aws_encryption_context()
        ctx.obj.log_status('Decrypting private key file into memory...')
        with open(tmpEncryptedPrivateKey.name, 'r') as f:
            key = kms_decrypt_private_key(kmsClient, f.read(), awsEncryptionContext)

        ctx.obj.log_status('Downloading encrypted data file from S3 \'s3://%s/%s\' to %s...' % (dataBucket, dataBucketFilename, tmpEncryptedDataFile.name))

        s3_transfer_progress_bar_helper('Downloading file', s3.Object(dataBucket, dataBucketFilename).content_length,
                                        lambda progressBar: transfer.download_file(dataBucket, dataBucketFilename,
                                                                                   tmpEncryptedDataFile.name, callback=progressBar))
        ctx.obj.log_status('Decrypting temporary data file into memory...')
        with open(tmpEncryptedDataFile.name, 'r') as f2:
            decryptedData = decrypt_helper(f2.read(), key)

        # immediately remove private key from memory
        del key
        ctx.obj.log_status('Saving decrypted data in memory into the destination file path...')
        configurationDeploymentPath.write(decryptedData)
        configurationDeploymentPath.close()
        # immediately remove decrypted data from memory
        del decryptedData
    except ClientError as ce:
        ctx.obj.aws_client_error(ce)
        sys.exit()
    except Exception as e:
        ctx.obj.unkown_error(e, 'Some unkown error occured while trying to decrypt a file from S3: %s')
        sys.exit()
    finally:
        ctx.obj.log_status('Clean up temporary data files...')
        # Delete the temporary files
        tmpEncryptedPrivateKey.close()
        tmpEncryptedDataFile.close()


@cli.command(short_help='create new RSA encryption keypair')
@click.option('--aws-kms-key-id', 'awsKmsKeyId', envvar='SYNLAY_AWS_KMS_KEY_ID', required=True, help='The AWS KMS key id to used to encrypt/decrypt data, can also be specified through the \'SYNLAY_AWS_KMS_KEY_ID\' environment variable.')
@click.option('--project', '-p', prompt='Enter the project name', help='Used as part of the encryption context of the AWS KMS service.', required=True)
@click.option('--configuration-deployment-path', '-cdp', 'configurationDeploymentPath', prompt='Enter the path where the future decrypted configuration file will be deployed', type=click.Path(), required=True, help='Path where final decrypted configuration file will be deployed. Parts of the path will be used to generate an ecnryption contex for the AWS KMS service.')
@click.option('--key-size', '-ks', 'keySize', default=4096, type=click.IntRange(1024, 4096, clamp=True), help='Configure the key size.', required=True)
@click.option('--public-key-file', '-pkf', 'publicKeyFile', prompt='Public key file path and name', default='./public_key.pem', type=click.File(mode='w'), required=True, help='Path where the generated public key should be exported to.')
@click.option('--encrypted-private-key-file', '-epkf', 'encryptedPrivateKeyFile', prompt='Encrypted private key file path and name', default='./private_key.sec', type=click.File(mode='wb'), required=True, help='Path where the generated and encrypted private key should be exported to.')
@click.pass_context
def create_new_key_pair(ctx, awsKmsKeyId, project, configurationDeploymentPath, keySize, publicKeyFile, encryptedPrivateKeyFile):
    """Create a new encryption RSA keypair, where the private keyfile will be encrypted using the AWS KMS service."""

    ctx.obj.log_status('Creating RSA keypair...')
    kmsClient = create_kms_client(ctx)
    keyPair = create_key_pair(keySize)
    awsEncryptionContext = SynlayAWSEncryptionContext(project, configurationDeploymentPath).aws_encryption_context()

    try:
        ctx.obj.log_status('Encrypting private key using AWS KMS service...')
        ciphertextBlob = kms_encrypt_private_key(kmsClient, keyPair, awsKmsKeyId, awsEncryptionContext)

        ctx.obj.log_status('Saving public key \'%s\' to the filesystem...' % publicKeyFile.name)
        publicKeyFile.write(keyPair.publickey().exportKey('PEM'))
        publicKeyFile.close()
        del keyPair
        ctx.obj.log_status('Saving encrypted private key \'%s\' to the filesystem...' % encryptedPrivateKeyFile.name)
        encryptedPrivateKeyFile.write(ciphertextBlob)
        encryptedPrivateKeyFile.close()

        # if click.confirm('Do you wan\'t to upload the encrypted key file to S3?'):
        #     ctx.forward(upload_encrypted_private_key_to_s3, privateFile=encryptedPrivateKeyFile, s3Url=None)
        #     click.echo('Well done!')
    except ClientError as ce:
        ctx.obj.aws_client_error(ce)
        sys.exit()
    except Exception as e:
        ctx.obj.unkown_error(e, 'Some unkown error occured while trying to create a new RSA keypair: %s')
        sys.exit()


@cli.command(short_help='upload a file to S3')
@click.option('--file', prompt='File path and name', default='./private_key.sec', type=click.Path(exists=True, readable=True, resolve_path=True), required=True, help='Path where the file is located which should be uploaded to S3.')
@click.option('--bucket', prompt='S3 bucket name to upload the file to', default='synlay-deployment-keys', required=True, help='Bucket name where the file should be uploaded to.')
@click.option('--bucket_filename', 'bucketFilename', help='Filename which should be used to save the file in the bucket.', required=True)
@click.option('--keep_original_file', '--k', 'keepOriginalFile', is_flag=True, default=False)
@click.pass_context
def upload_file_to_s3(ctx, file, bucket, bucketFilename, keepOriginalFile):
    """Simple file upload to a S3 bucket with server side AWS256 encryption enabled."""
    ctx.obj.log_status('Upload file \'%s\' to S3 \'s3://%s/%s\'...' % (file, bucket, bucketFilename))
    transfer = create_s3_transfer(ctx)
    try:
        bucketFilename = bucketFilename if not bucketFilename is None else os.path.basename(file)

        s3_transfer_progress_bar_helper('Uploading file', os.path.getsize(file),
                                        lambda progressBar: transfer.upload_file(file, bucket, bucketFilename,
                                                                                 callback=progressBar,
                                                                                 extra_args={'ServerSideEncryption': 'AES256'}))
        if not keepOriginalFile:
            # On unix systems try to delete securely with srm and ignore the exit code
            subprocess.call(["srm", "-f", file])
            if os.path.isfile(file):
                os.remove(file)
    except ClientError as ce:
        ctx.obj.aws_client_error(ce)
        sys.exit()
    except Exception as e:
        ctx.obj.unkown_error(e, 'Some unkown error occured while trying to upload a file to S3: %s')
        sys.exit()


def main():
    cli(obj=None)

# =========================================================
#                       Internals
# =========================================================


class SynlayProgressPercentage(object):
    def __init__(self, progressBar):
        self.__progress_bar = progressBar
        self._lock = threading.Lock()

    def __call__(self, bytes_amount):
        with self._lock:
            self.__progress_bar.update(bytes_amount)


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

    def log_status(self, message):
        click.echo(click.style(message, fg='green'))

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
    except Exception as e:
        ctx.obj.unkown_error(e, "Error while trying to initialize aws kms client: '%s'")
        exit()


def create_s3_transfer(ctx):
    """Boto3 S3 transfer factory"""
    try:
        client = boto3.client('s3')
        return S3Transfer(client)
    except Exception as e:
        ctx.obj.unkown_error(e, "Error while trying to initialize aws s3 transfer: '%s'")
        exit()


def create_s3_resource(ctx):
    """Boto3 S3 resource factory"""
    try:
        return boto3.resource('s3')
    except Exception as e:
        ctx.obj.unkown_error(e, "Error while trying to initialize aws s3 resource: '%s'")
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


def encrypt_helper(message, key, aesKeySize):
    """Symetric AES encryption of 'message' with a randomly generated key
    of the size 'aesKeySize'. The randomly generated encription key will
    be encrypted with the public key part from 'key' using the RSA
    encryption protocol according to PKCS#1 OAEP.
    @return encrypted ciphertext blob including the initialization vector
            alongside with the 'aesKeyCipherLength' and the encrypted
            'aesKey';
            blob = <iv:AES.block_size> + <aesKeyCipherLength:4> +
                   <encryptedAesKey:aesKeyCipherLength>) + <encryptedMessage:var>
    """
    binPubKey = key.publickey().exportKey('DER')
    pubKeyObj = RSA.importKey(binPubKey)
    rsaCipher = PKCS1_OAEP.new(pubKeyObj)

    # create a new random byte sequence with aesKeySize byte used as an encryption key
    aesKey = Random.new().read(aesKeySize)
    iv = Random.new().read(AES.block_size)
    packedAesKeyCipherLength = struct.pack(">I", (key.publickey().size() + 1) / 8)
    aesCipher = AES.new(aesKey, AES.MODE_CFB, iv)

    return iv + packedAesKeyCipherLength + rsaCipher.encrypt(aesKey) + aesCipher.encrypt(message)


def decrypt_helper(cipherblob, key):
    """Decrypts the actual encrypted AES encryption key with the private
    key part from 'key' using the RSA encryption protocol according
    to PKCS#1 OAEP, which afterwards will be used to decrypt the actual
    message blob.
    @return The actual decrypted message blob
    """
    binPrivKey = key.exportKey('DER')
    privKeyObj = RSA.importKey(binPrivKey)
    rsaCipher = PKCS1_OAEP.new(privKeyObj)

    iv = cipherblob[:AES.block_size]
    packedAesKeyCipherLength = cipherblob[AES.block_size : AES.block_size + 4]
    (AesKeyCipherLength, ) = struct.unpack(">I", packedAesKeyCipherLength)
    encryptedAesKey = cipherblob[AES.block_size + 4 : AES.block_size + 4 + AesKeyCipherLength]
    encryptedMessage = cipherblob[AES.block_size + 4 + AesKeyCipherLength:]

    aesKey = rsaCipher.decrypt(encryptedAesKey)
    aesCipher = AES.new(aesKey, AES.MODE_CFB, iv)

    return aesCipher.decrypt(encryptedMessage)


def s3_transfer_progress_bar_helper(message, contentSize, transferFunc):
    with click.progressbar(label=message, length=contentSize) as progressBar:
        transferFunc(SynlayProgressPercentage(progressBar))
