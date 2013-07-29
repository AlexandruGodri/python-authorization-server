from django.conf.urls import patterns, include, url
from data import *
 
urlpatterns = patterns('',
    url(r'^oauth/token/(?P<clientId>[A-Za-z0-9]*)/(?P<clientSecret>[A-Za-z0-9]*)$', RestToken.as_view()),
    url(r'^authorize/(?P<clientId>[A-Za-z0-9]*)/(?P<token>[A-Za-z0-9]*)/(?P<user>[A-Za-z0-9_-]*)/(?P<resource>[A-Za-z0-9_-]*)/(?P<permission>[A-Za-z0-9]*)$', RestAuthorize.as_view()),
    url(r'^resource/(?P<clientId>[A-Za-z0-9]*)/(?P<token>[A-Za-z0-9]*)$', RestResource.as_view()),
    url(r'^permission/(?P<clientId>[A-Za-z0-9]*)/(?P<token>[A-Za-z0-9]*)$', RestPermission.as_view()),
    url(r'^role/(?P<clientId>[A-Za-z0-9]*)/(?P<token>[A-Za-z0-9]*)$', RestRole.as_view()),
    url(r'^user/role/(?P<clientId>[A-Za-z0-9]*)/(?P<token>[A-Za-z0-9]*)$', RestUserRole.as_view()),
    url(r'^test/(?P<clientId>[A-Za-z0-9]*)/(?P<clientSecret>[A-Za-z0-9]*)/(?P<resource>[A-Za-z0-9]*)/(?P<permission>[A-Za-z0-9]*)$', Test.as_view())
)
