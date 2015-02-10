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

import functools
import hmac
import urllib.parse

from pyramid.httpexceptions import HTTPForbidden, HTTPMethodNotAllowed


REASON_NO_ORIGIN = "Origin checking failed - no Origin or Referer."
REASON_BAD_ORIGIN = "Origin checking failed - {} does not match {}."
REASON_BAD_TOKEN = "CSRF token missing or incorrect."


class InvalidCSRF(HTTPForbidden):
    pass


def csrf_exempt(view):
    @functools.wraps(view)
    def wrapped(context, request):
        request._process_csrf = False
        return view(context, request)
    return wrapped


def csrf_protect(view_or_scope):
    scope = None
    if isinstance(view_or_scope, str):
        scope = view_or_scope

    def inner(view):
        @functools.wraps(view)
        def wrapped(context, request):
            request._process_csrf = True
            request._csrf_scope = scope
            return view(context, request)
        return wrapped

    if scope is None:
        return inner(view_or_scope)
    else:
        return inner


def check_csrf(request):
    # Assume that anything not defined as 'safe' by RFC2616 needs protection
    if request.method not in {"GET", "HEAD", "OPTIONS", "TRACE"}:
        # Determine if this request has set itself so that it should be
        # protected against CSRF. If it has not and it's gotten one of these
        # methods, then we want to raise an error stating that this resource
        # does not support this method.
        if not getattr(request, "_process_csrf", None):
            raise HTTPMethodNotAllowed

        if request.scheme == "https":
            # Determine the origin of this request
            origin = request.headers.get("Origin")
            if origin is None:
                origin = request.headers.get("Referer")

            # Fail if we were not able to locate an origin at all
            if not origin:
                raise InvalidCSRF(REASON_NO_ORIGIN)

            # Parse the origin and host for comparison
            originp = urllib.parse.urlparse(origin)
            hostp = urllib.parse.urlparse(request.host_url)

            # Actually check our Origin against our Current
            # Host URL.
            if ((originp.scheme, originp.hostname, originp.port)
                    != (hostp.scheme, hostp.hostname, hostp.port)):
                reason_origin = origin
                if origin != "null":
                    reason_origin = urllib.parse.urlunparse(
                        originp[:2] + ("", "", "", ""),
                    )

                reason = REASON_BAD_ORIGIN.format(
                    reason_origin, request.host_url,
                )

                raise InvalidCSRF(reason)

        session = getattr(request, "_session", request.session)

        # Get the provided CSRF token from the request.
        request_token = request.POST.get("csrf_token", "")
        if not request_token:
            request_token = request.headers.get("CSRFToken", "")

        # Get our CSRF token from the session, scoped or not
        # depending on if our @csrf_protect header was registered
        # with a scope or not.
        scope = request._csrf_scope
        if scope is None:
            csrf_token = session.get_csrf_token()
        else:
            csrf_token = session.get_scoped_csrf_token(scope)

        if not hmac.compare_digest(csrf_token, request_token):
            raise InvalidCSRF(REASON_BAD_TOKEN)
