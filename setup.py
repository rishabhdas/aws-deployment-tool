"""
Synlay AWS Deployment Tool
"""
from setuptools import find_packages, setup

dependencies = [
    'click==5.1',
    'pycrypto>=2.6.1,<2.7.0',
    'boto3>=1.2.0,<1.3.0'
]

setup(
    name='synlay-aws-deployment-tool',
    version='0.1.0',
    url='https://github.com/synlay/aws-deployment-tool',
    license='MIT',
    author='David Robakowski',
    author_email='david.robakowski@synlay.com',
    description='Synlay AWS Deployment Tool',
    long_description=__doc__,
    packages=find_packages(exclude=['tests']),
    include_package_data=True,
    zip_safe=False,
    platforms='any',
    install_requires=dependencies,
    entry_points={
        'console_scripts': [
            'synlay-aws-deployment-tool = synlay_aws_deployment_tool.cli:main',
        ],
    },
    classifiers=[
        # As from http://pypi.python.org/pypi?%3Aaction=list_classifiers
        # 'Development Status :: 1 - Planning',
        # 'Development Status :: 2 - Pre-Alpha',
        # 'Development Status :: 3 - Alpha',
        'Development Status :: 4 - Beta',
        # 'Development Status :: 5 - Production/Stable',
        # 'Development Status :: 6 - Mature',
        # 'Development Status :: 7 - Inactive',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX',
        'Operating System :: MacOS',
        'Operating System :: Unix',
        'Operating System :: Windows',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        # TODO: ADT-3 - Refine codebase to work with Python 3
        # 'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
