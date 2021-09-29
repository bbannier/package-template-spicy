"""This module provides a zkg template for Spicy analyzers."""
from typing import List

import zeekpkg.template
import zeekpkg.uservar

TEMPLATE_API_VERSION = '1.0.0'


class Package(zeekpkg.template.Package):
    """Package implementation for Spicy analyzers."""

    def contentdir(self):
        """Specify location of package content."""
        return 'package'

    def needed_user_vars(self):
        """Specify required user variables."""
        return ['name', 'namespace']

    def validate(self, tmpl: zeekpkg.template.Template):
        """Check validity of parameters."""
        # TODO(bbannier): It would be nice to instead directly validate
        # variables as received by the user in `Template.apply_user_vars`. It
        # also seems weird that we need to both declare these variables as
        # `needed_user_vars` and then still check whether the template did
        # provide them.
        for parameter in ['name', 'namespace']:
            value = tmpl.lookup_param(parameter)
            if not value or len(value) == 0:
                raise zeekpkg.template.InputError('package requires a name')


class Template(zeekpkg.template.Template):
    """Template implementation for Spicy analyzers."""

    def define_user_vars(self):
        """Define user variables."""
        return [
            zeekpkg.uservar.UserVar(
                'namespace', desc='module name of the analyzer'),
            zeekpkg.uservar.UserVar(
                'name', desc='name of the analyzer'),
        ]

    def apply_user_vars(self, uvars: List[zeekpkg.uservar.UserVar]):
        """Extract user vars specified by the user."""
        for uvar in uvars:
            if uvar.name() == 'name':
                name = uvar.val()
                assert name

                self.define_param('name', name)

            # TODO(bbannier): It would be nice to derive this automatically
            # from `name`, but that throws uvar dependency tracking of the
            # rails.
            if uvar.name() == 'namespace':
                name = uvar.val()
                assert name

                self.define_param('namespace', name)

    def package(self):
        """Specify the package corresponding to this template."""
        return Package()
