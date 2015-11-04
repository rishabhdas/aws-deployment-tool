# coding: utf-8

import os

# Import the SDK
import click
import boto3
from boto3.s3.transfer import S3Transfer
from botocore.exceptions import ClientError

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

def kms_decrypt_private_key(kmsClient, ciphertextBlob, awsEncryptionContext):
    DecryptResponse = kmsClient.decrypt(
        CiphertextBlob=ciphertextBlob,
        EncryptionContext=awsEncryptionContext
    )
    # click.echo("Bla %s" % e.response['Error']['Code'])
    # botocore.exceptions.ClientError: An error occurred (InvalidCiphertextException) when calling the Decrypt operation: None
    # botocore.exceptions.ClientError: An error occurred (AccessDeniedException) when calling the Decrypt operation: The ciphertext references a key that either does not exist or you do not have access to.
    return RSA.importKey(DecryptResponse['Plaintext'])

def encrypt_helper(message, key):
    binPubKey = key.publickey().exportKey('DER')
    pubKeyObj = RSA.importKey(binPubKey)
    cipher = PKCS1_OAEP.new(pubKeyObj)
    return cipher.encrypt(message)

def decrypt_helper(ciphertext, key):
    binPrivKey = key.exportKey('DER')
    privKeyObj = RSA.importKey(binPrivKey)
    cipher = PKCS1_OAEP.new(privKeyObj)
    return cipher.decrypt(ciphertext)

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
@click.option('--public-key-file', '-pkf', 'publicKeyFile', prompt='Public key file path and name', default='./public_key.pem', type=click.File(mode='r'), required=True, help='Path where the generated public key is located.')
@click.option('--file-to-encrypt', '-fte', 'fileToEncrypt', prompt='File to encrypt', type=click.File(mode='r'), required=True)
@click.option('--encrypt-to-file', 'encryptToFile', prompt='File path and name where the chipher text should be saved', type=click.File(mode='wb'), required=True)
@click.option('--keep_original_file', '-k', 'keepOriginalFile', is_flag=True, default=False)
def encrypt(publicKeyFile, fileToEncrypt, encryptToFile, keepOriginalFile):
    """Encrypt a given file with a public key."""
    publicKey = RSA.importKey(publicKeyFile.read())
    encryptToFile.write(encrypt_helper(fileToEncrypt.read(), publicKey))
    encryptToFile.close()
    if not keepOriginalFile:
        os.remove(fileToEncrypt.name)

@cli.command()
@click.option('--aws-kms-key-id', 'awsKmsKeyId', envvar='SYNLAY_AWS_KMS_KEY_ID', required=True)
@click.option('--project', '-p', prompt='Enter the project name', help='Used as part of the encryption context of the AWS KMS service.', required=True)
@click.option('--configuration-deployment-path', '-cdp', 'configurationDeploymentPath', type=click.File(mode='w'), required=True, help='Path where final decrypted data file will be exported to. Parts of the path will be used to generate an ecnryption contex for the AWS KMS service.')
@click.option('--key-bucket', 'keyBucket', default='synlay-deployment-keys', required=True, help='Bucket where the encrypted private key file can be downloaded from.')
@click.option('--key-bucket-filename', 'keyBucketFilename', required=True, help='Filename from the encryption key in the key bucket.')
@click.option('--data-bucket', 'dataBucket', default='synlay-deployment-data', required=True, help='Bucket where the encrypted data can be downloaded from.')
@click.option('--data-bucket-filename', 'dataBucketFilename', required=True, help='Filename from the encryption file in the data bucket.')
def decrypt(awsKmsKeyId, project, configurationDeploymentPath, keyBucket, keyBucketFilename, dataBucket, dataBucketFilename):
    import tempfile
    import subprocess

    client = boto3.client('s3')
    transfer = S3Transfer(client)

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
    except Exception, e:
        raise e
    finally:
        # On unix systems try to delete securely with srm and ignore the exit code
        subprocess.call(["srm", "-f", tmpEncryptedPrivateKey.name, tmpEncryptedDataFile.name])

        if os.path.isfile(tmpEncryptedPrivateKey.name):
            os.remove(tmpEncryptedPrivateKey.name)
        if os.path.isfile(tmpEncryptedDataFile.name):
            os.remove(tmpEncryptedDataFile.name)

# aws_access_key_id, aws_secret_access_key and aws_region will be determined through the environment or extracted from ~/.aws/credentials
@cli.command()
@click.option('--aws-kms-key-id', 'awsKmsKeyId', envvar='SYNLAY_AWS_KMS_KEY_ID', required=True)
@click.option('--project', '-p', prompt='Enter the project name', help='Used as part of the encryption context of the AWS KMS service.', required=True)
@click.option('--configuration-deployment-path', '-cdp', 'configurationDeploymentPath', prompt='Enter the path where the future decrypted configuration file will be deployed', type=click.Path(), required=True, help='Path where final decrypted configuration file will be deployed. Parts of the path will be used to generate an ecnryption contex for the AWS KMS service.')
@click.option('--key-size', '-ks', 'keySize', default=1024, type=click.IntRange(1024, 4096, clamp=True), help='Configure the key size.', required=True)
@click.option('--public-key-file', '-pkf', 'publicKeyFile', prompt='Public key file path and name', default='./public_key.pem', type=click.File(mode='w'), required=True, help='Path where the generated public key should be exported to.')
@click.option('--encrypted-private-key-file', '-epkf', 'encryptedPrivateKeyFile', prompt='Encrypted private key file path and name', default='./private_key.sec', type=click.File(mode='wb'), required=True, help='Path where the generated and encrypted private key should be exported to.')
@click.pass_context
def create_new_key_pair(ctx, awsKmsKeyId, project, configurationDeploymentPath, keySize, publicKeyFile, encryptedPrivateKeyFile):
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
@click.option('--encrypted_private_key_file', 'privateFile', prompt='Encrypted private key file path and name', default='./private_key.sec', type=click.Path(exists=True, readable=True, resolve_path=True), required=True, help='Path where the generated private key file is located.')
@click.option('--bucket', prompt='S3 bucket to upload the encrypted file to', default='synlay-deployment-keys', required=True, help='Bucket where the encrypted private key file should be uploaded to.')
@click.option('--bucket_key_filename', 'bucketKeyFilename', help='Filename which should be used to save the file in the bucket.')
@click.option('--keep_original_file', '--k', 'keepOriginalFile', is_flag=True, default=False)
def upload_encrypted_private_key_to_s3(privateFile, bucket, bucketKeyFilename, keepOriginalFile):
    """Uploads the encrypted private key file to a S3 bucket."""

    import subprocess

    # client = boto3.client('s3', 'us-west-2')
    client = boto3.client('s3')
    transfer = S3Transfer(client)
    bucketKeyFilename = bucketKeyFilename if not bucketKeyFilename is None else os.path.basename(privateFile)
    transfer.upload_file(privateFile, bucket, bucketKeyFilename, extra_args={'ServerSideEncryption': 'AES256'})
    if not keepOriginalFile:
        # On unix systems try to delete securely with srm and ignore the exit code
        subprocess.call(["srm", "-f", privateFile])
        if os.path.isfile(privateFile):
            os.remove(privateFile)

def main():
    cli()
