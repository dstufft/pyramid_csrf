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
from pyramid_csrf.utils import random_token


@implementer(ICSRF)
class SessionCSRF(object):

    def __init__(self, session, session_key):
        self.session = session
        self.session_key = session_key

    def has_token(self):
        return self.session_key in self.session

    def new_token(self):
        token = random_token()
        self.session[self.session_key] = token
        return token

    def get_token(self):
        token = self.session.get(self.session_key)
        if token is None:
            token = self.new_token()
        return token

    def get_scoped_token(self, scope):
        # Here we want to do HMAC_sha512(unscoped_token, scope). This will make
        # it possible to have scope specific CSRF tokens which means that a
        # single scope token being leaked cannot be used for other scopes.
        unscoped = self.get_token().encode("utf8")
        scope = scope.encode("utf8")
        return hmac.new(unscoped, scope, "sha512").hexdigest()


@implementer(ICSRFFactory)
class SessionCSRFFactory(object):

    def __init__(self, session_key="csrf.token"):
        self.session_key = session_key

    def __call__(self, request):
        return SessionCSRF(request.session, self.session_key)
