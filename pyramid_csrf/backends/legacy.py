# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hmac

from zope.interface import implementer

from pyramid_csrf.interfaces import ICSRF, ICSRFFactory


@implementer(ICSRF)
class LegacySessionCSRF(object):

    def __init__(self, session):
        self.session = session

    def has_token(self):
        # Can't implement this in terms of the old API really, so we'll just
        # force has_token to say True, since it is only used as an optimization
        # and the token will be created lazily.
        return True

    def new_token(self):
        return self.session.new_csrf_token()

    def get_token(self):
        return self.session.get_csrf_token()

    def get_scoped_token(self, scope):
        # Here we want to do HMAC_sha512(unscoped_token, scope). This will make
        # it possible to have scope specific CSRF tokens which means that a
        # single scope token being leaked cannot be used for other scopes.
        unscoped = self.get_token().encode("utf8")
        scope = scope.encode("utf8")
        return hmac.new(unscoped, scope, "sha512").hexdigest()


@implementer(ICSRFFactory)
class LegacySessionCSRFFactory(object):

    def __call__(self, request):
        return LegacySessionCSRF(request.session)
