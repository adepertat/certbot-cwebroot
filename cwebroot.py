""" Clustered webroot plugin."""
import argparse
import collections
import logging
import os

import six
import zope.component
import zope.interface

from acme import challenges

from certbot import interfaces
from certbot.plugins import common

import spur

logger = logging.getLogger(__name__)

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(common.Plugin):
    """Clustered Webroot Authenticator."""

    description = "Place files in webroot directory on multiple hosts"

    MORE_INFO = """\
Authenticator plugin that performs http-01 challenge by saving necessary
validation resources to appropriate paths on the file system on the specified
hosts. It expects that there is some other HTTP server configured to serve all
files under specified web root ({0}) on each host."""

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return self.MORE_INFO.format(self.conf("path"))

    @classmethod
    def add_parser_arguments(cls, add):
        add("path", "-w2", default="/var/www/html/letsencrypt",
            help="public_html / webroot path. This CANNOT be specified multiple "
                 "times to handle different domains: although this is heavily "
                 "inspired by the bundled `webroot` plugin, it does not (yet) "
                 "support all its features.")
        add("host", default=[], action='append',
            help="Remote hosts where the challenge file should be deployed. "
                 "This can be specified multiple times. The hosts are accessed "
                 "through SSH as the user running the `certbot` command. There "
                 "is no support for a password so please have your public SSH "
                 "key deployed on all the target hosts.")
        add("nolocal", default=False, action='store_true',
            help="Disable creating the challenge file locally.")

    def get_chall_pref(self, domain):  # pragma: no cover
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.HTTP01]

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.full_path = None
        self.performed = collections.defaultdict(set)

    def prepare(self):  # pylint: disable=missing-docstring
        pass

    def perform(self, achalls):  # pylint: disable=missing-docstring
        self._create_challenge_dirs()

        return [self._perform_single(achall) for achall in achalls]

    def _create_challenge_dirs(self):
        self.full_path = os.path.join(self.conf('path'), challenges.HTTP01.URI_ROOT_PATH)
        self.shells = [spur.SshShell(h, missing_host_key=spur.ssh.MissingHostKey.accept) for h in self.conf('host')]
        if not self.conf('nolocal'):
            self.shells.insert(0, spur.LocalShell())
        for s in self.shells:
            s.run(['mkdir', '--mode', '0755', '--parents', self.full_path])
            stat = s.run(['stat', '--format', '%U:%G', self.full_path])
            user_group = stat.output.strip()
            s.run(['chown', user_group, self.full_path])
                
    def _get_validation_path(self, root_path, achall):
        return os.path.join(root_path, achall.chall.encode("token"))

    def _perform_single(self, achall):
        response, validation = achall.response_and_validation()

        root_path = self.full_path
        validation_path = self._get_validation_path(root_path, achall)

        for s in self.shells:
            logger.debug("Attempting to save validation to {}:{}".format(s._hostname, validation_path))
            s.run(['sh', '-c', "echo '{}' > '{}'".format(validation, validation_path)])

        self.performed[root_path].add(achall)

        return response

    def cleanup(self, achalls):  # pylint: disable=missing-docstring
        for achall in achalls:
            root_path = self.full_path
            if root_path is not None:
                validation_path = self._get_validation_path(root_path, achall)
                for s in self.shells:
                    logger.debug("Removing {}:{}".format(s._hostname, validation_path))
                    s.run(['rm', validation_path])
                self.performed[root_path].remove(achall)

        for root_path, achalls in six.iteritems(self.performed):
            if not achalls:
                for s in self.shells:
                    try:
                        logger.debug("All challenges cleaned up, removing {}:{}".format(,
                                     s._hostname, root_path))
                        s.run(['rmdir', root_path])
                    except OSError as exc:
                        logger.info(
                            "Unable to clean up challenge directory {}:{}".format(
                            s._hostname, root_path))
                        logger.debug("Error was: %s", exc)


