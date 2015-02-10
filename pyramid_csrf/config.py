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

from pyramid.config.views import DefaultViewMapper
from pyramid.interfaces import IViewMapperFactory

from pyramid_csrf.backends.cookie import CookieCSRFFactory
from pyramid_csrf.csrf import check_csrf
from pyramid_csrf.interfaces import ICSRFFactory


def set_csrf_factory(config, factory):
    factory = config.maybe_dotted(factory)

    def register():
        config.registry.registerUtility(factory, ICSRFFactory)

    config.action(ICSRFFactory, register)


def csrf(request):
    factory = request.registry.queryUtility(ICSRFFactory)
    if factory is not None:
        factory = factory(request)
    return factory


def _add_vary_cookie(request, response):
    vary = set(response.vary if response.vary is not None else [])
    vary |= set(["Cookie"])
    response.vary = vary


def csrf_mapper_factory(mapper):
    class CSRFMapper(mapper):

        def __call__(self, view):
            view = super().__call__(view)

            @functools.wraps(view)
            def wrapped(context, request):
                # Assign our view to an innerview function so that we can
                # modify it inside of the wrapped function.
                innerview = view

                # Check to see if we have an ICSRFFactory registered, if we do
                # not then we'll assume that CSRF checking has been disabled.
                factory = request.registry.queryUtility(ICSRFFactory)
                if factory is None:
                    return innerview(context, request)

                # Check if we're processing CSRF for this request at all or
                # if it has been exempted from CSRF.
                if not getattr(request, "_process_csrf", True):
                    return innerview(context, request)

                # If we're processing CSRF for this request, then we want to
                # set a Vary: Cookie header on every response to ensure that
                # we don't cache the result of a CSRF check or a form with a
                # CSRF token in it.
                if getattr(request, "_process_csrf", False):
                    request.add_response_callback(_add_vary_cookie)

                # Actually check our CSRF
                check_csrf(request)

                return innerview(context, request)

            return wrapped
    return CSRFMapper


def includeme(config):
    # We need to commit what's happened so far so that we can get the current
    # default ViewMapper
    config.commit()

    # Register our directives and request methods.
    config.add_directive("set_csrf_factory", set_csrf_factory)
    config.add_request_method(csrf, name="csrf", reify=True)

    # We want to default to using the CookieCSRF
    config.set_csrf_factory(CookieCSRFFactory())

    # Get the current default ViewMapper, and create a subclass of it that
    # will wrap our view with CSRF checking.
    mapper = config.registry.queryUtility(IViewMapperFactory)
    if mapper is None:
        mapper = DefaultViewMapper
    config.set_view_mapper(csrf_mapper_factory(mapper))
