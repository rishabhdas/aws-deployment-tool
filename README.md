# Synlay AWS Deployment Tool

Synlay AWS Deployment Tool


# Installation

If you don't use `pipsi`, you're missing out.
Here are [installation instructions](https://github.com/mitsuhiko/pipsi#readme):

    $ sudo port install virtualenv_select py27-virtualenv pip_select py27-pip
    $ sudo port select --set virtualenv virtualenv27
    $ sudo port select --set pip pip27
    $ sudo port select --set python python27
    $ curl https://raw.githubusercontent.com/mitsuhiko/pipsi/master/get-pipsi.py | python

Simply run:

    $ pipsi install .


# Usage

To use it:

    $ synlay-aws-deployment-tool --help

	Usage: synlay-aws-deployment-tool [OPTIONS] COMMAND [ARGS]...

	  Synlay AWS Deployment Tool

	  Common AWS specific configuration and credentials arguments will be
	  determined through the environment or will be extracted from
	  ~/.aws/credentials

	  Possible environment variables:

	  AWS_ACCESS_KEY_ID - The access key for your AWS account.
	  AWS_SECRET_ACCESS_KEY - The secret key for your AWS account.
	  AWS_DEFAULT_REGION - The default region to use, e.g. us-east-1.
	  AWS_PROFILE - The default credential and configuration profile to use, if
	  any. SYNLAY_AWS_KMS_KEY_ID - The AWS KMS key id to used to encrypt/decrypt
	  data.

	Options:
	  --debug  Show the stacktrace when errors occur
	  --help   Show this message and exit.

	Commands:
	  create_new_key_pair  Create a new encryption RSA keypair, where...
	  decrypt              Decrypt s3://dataBucket/dataBucketFilename...
	  encrypt              Encrypt a given 'fileToEncrypt' with the...
	  upload_file_to_s3    Simple file upload to a S3 bucket with server...

## Typical usage example

### 1. Create some project specific encryption keys

	AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_DEFAULT_REGION=eu-central-1 SYNLAY_AWS_KMS_KEY_ID=alias/test-key synlay-aws-deployment-tool create_new_key_pair --project=TestApp --configuration-deployment-path=./decrypted_test_file.txt --public-key-file=./public_key.pem --encrypted-private-key-file=./private_key.sec

### 2. Upload the encrypted private key file to the S3 bucket

	AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_DEFAULT_REGION=eu-central-1 synlay-aws-deployment-tool upload_file_to_s3 --file=./private_key.sec --bucket=deployment-keys --bucket_filename=test_app_private_key.sec

### 3. Encrypt a data file using the public key file

A typical use case for this step would be a new release of the app with a new configuration file.

	echo 'Hello world!' > ./Test.txt
	AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_DEFAULT_REGION=eu-central-1 synlay-aws-deployment-tool encrypt --public-key-file=public_key.pem --file-to-encrypt=./Test.txt --encrypt-to-file=./encrypted_test_file.txt

### 4. Upload the encrypted data file to the S3 bucket

	AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_DEFAULT_REGION=eu-central-1 synlay-aws-deployment-tool upload_file_to_s3 --file=./encrypted_test_file.txt --bucket=deployment-data --bucket_filename=encrypted_test_file.txt

### 5. Decrypt the data file and private key file from a S3 bucket

Typically done on the server side as a bootstrap process while deploying a new app/server instance.

	AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_DEFAULT_REGION=eu-central-1 synlay-aws-deployment-tool decrypt --project=TestApp --configuration-deployment-path=./decrypted_test_file.txt --key-bucket=deployment-keys --key-bucket-filename=test_app_private_key.sec --data-bucket=deployment-data --data-bucket-filename=encrypted_test_file.txt
