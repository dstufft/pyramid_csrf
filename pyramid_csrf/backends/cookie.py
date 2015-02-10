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
class CookieCSRF(object):

    def __init__(self, request, cookie_name, options):
        self.request = request
        self.request.add_response_callback(self._store_cookie)
        self.cookie_name = cookie_name
        self.options = options
        self.token = None

    def _store_cookie(self, request, response):
        response.set_cookie(self.cookie_name, self.token, **self.options)

    def has_token(self):
        return self.cookie_name in self.request.cookies

    def new_token(self):
        self.token = random_token()
        return self.token

    def get_token(self):
        if self.token is None:
            self.token = self.new_token()
        return self.token

    def get_scoped_token(self, scope):
        # Here we want to do HMAC_sha512(unscoped_token, scope). This will make
        # it possible to have scope specific CSRF tokens which means that a
        # single scope token being leaked cannot be used for other scopes.
        unscoped = self.get_token().encode("utf8")
        scope = scope.encode("utf8")
        return hmac.new(unscoped, scope, "sha512").hexdigest()


@implementer(ICSRFFactory)
class CookieCSRFFactory(object):

    def __init__(self, cookie_name="csrf.token", **options):
        self.cookie_name = cookie_name
        self.options = options

    def __call__(self, request):
        return CookieCSRF(request, self.cookie_name, self.options)
