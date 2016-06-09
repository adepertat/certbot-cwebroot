# -*- encoding: utf-8 -*-
import os
from setuptools import setup

version = '0.1.0'

install_requires = [
    'certbot',
    'zope.interface',
    'spur',
]

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name='certbot-cwebroot',
    version=version,
    author=u"Albéric de Pertat",
    author_email='alberic@depertat.net',
    description="Clustered Webroot plugin for Let's Encrypt client",
    license='Apache License 2.0',
    keywords = ['letsencrypt', 'cluster'],
    url='https://github.com/adepertat/certbot-cwebroot',
    download_url = 'https://github.com/adepertat/certbot-cwebroot/archive/'+version+'.tar.gz',
    long_description=read('README.md'),
    include_package_data=True,
    install_requires=install_requires,
    classifiers=[
    "Development Status :: 3 - Alpha",
    "Topic :: Utilities",
    "License :: OSI Approved :: Apache Software License",
    ],
    platforms='any',
    entry_points={
        'certbot.plugins': [
            'cwebroot = cwebroot:Authenticator',
        ],
    },
)

