import re
import json
import datetime
import urllib2, urllib
from cookielib import CookieJar

#from cssselect import GenericTranslator, SelectorError
#from lxml.html import html5parser

#from cmc_api_requester.cmc_api_end_points import get_cmc_api_end_point


__BASE = datetime.datetime.fromtimestamp(0)
FORM_ENCODED_CONTENT_TYPE = "application/x-www-form-urlencoded"
JSON_CONTENT_TYPE = "application/json"
_CSRF_FIELD_NAME = '_csrf'


def extract_csrf_token_requests(html):
    for line in html.split("\n"):
        m = re.search('window\.csrfToken\s=\s"(.+)";', line)
        if m:
            return m.group(1)
    return None


class NoRedirectHTTPErrorProcessor(urllib2.HTTPErrorProcessor):

    def http_response(self, request, response):
        return response

    https_response = http_response


class CMCApiRequester(object):
    _logged_in = False
    _request_csrf_token = None

    def __init__(self, email, password):
        self.sso_login_url = 'https://www.dpa-news.de/b2b/login_deeplink.jsf'
        self.cmc_host = 'https://www.dpa-news.de/views/b2b/thema-details.jsf?nh=96e3j4.1&pm4j=%7B%22sec%22%3A%22DPA_NEWS%22%2C%22cat%22%3A%22wissen_dossier%22%2C%22navi.backPos%22%3A%22th51047513%22%2C%22moid%22%3A51047513%7D'
        self._opener = urllib2.build_opener(NoRedirectHTTPErrorProcessor, urllib2.HTTPCookieProcessor(CookieJar()))

        login_response = self.login(email, password)['response']

        self.follow_redirects(login_response)
        #html_data = self.get('get home page', get_cmc_api_end_point('home'))['data']
        #request_csrf_token = extract_csrf_token_requests(html_data)
        #self.request_csrf_token = request_csrf_token

    @property
    def opener(self):
        return self._opener

    def login(self, username, password):
        import ipdb;ipdb.set_trace()
        response = self.opener.open(self.sso_login_url)
        initial_html = response.read()
        #try:
        #    expression = GenericTranslator().css_to_xpath('html\:input[name="%s"]' % (_CSRF_FIELD_NAME))
        #except SelectorError:
        #    print('Invalid selector; fix it during development time')
        #    raise
        #document = html5parser.fromstring(initial_html)
        #csrfs = [e.get('value') for e in document.xpath(expression)]
        #csrf = ""
        #if len(csrfs) > 0:
        #    csrf = csrfs[0]
        post_data = dict()
        post_data["loginName"] = username
        post_data["password"] = password
        #post_data[_CSRF_FIELD_NAME] = csrf
        login_post_request = urllib2.Request(self.sso_login_url, urllib.urlencode(post_data))
        login_post_request.get_method = lambda: "POST"
        #response = self._request('attempt_login', login_post_request)['response']
        # Only if there is a network outage
        if not (response and (response.code == 302 or response.code == 200)):
            raise IOError("Could not login! " + str(response.code))
        # Only if there is some change in SSO, usually not expected
        #if not response.code == 302:
        #    print "Determined username/password error"
        #    raise ValueError('Login failed unexpectedly 302 not received!')
        new_location = response.info().getheader('Location')
        # Currently new location is not CMC if and only if username/password is wrong
        if not new_location == '/':
            print "Username/password failed", response.read()
            raise ValueError('Username/password failed!')

        #authenticate_url = self.cmc_host + get_cmc_api_end_point('authenticate')
        #print "Authenticate CMC", authenticate_url
        #request_response = self._request('authenticate_cmc', authenticate_url)
        self._logged_in = True
        #return {'response': request_response['response'], 'data': request_response['data']}

    def get(self, op_name, url):
        return self._request(op_name, urllib2.Request(self._process_url(url)))

    def put(self, op_name, url, data, content_type=JSON_CONTENT_TYPE):
        put_request = urllib2.Request(self._process_url(url), data=data)
        put_request.add_header('Content-Type', content_type)
        put_request.get_method = lambda: "PUT"
        return self._request(op_name, put_request)

    def post(self, op_name, url, data, content_type=JSON_CONTENT_TYPE):
        post_request = urllib2.Request(self._process_url(url), data=data)
        post_request.add_header('Content-Type', content_type)
        post_request.get_method = lambda: "POST"
        return self._request(op_name, post_request)

    def patch(self, op_name, url, data, content_type=JSON_CONTENT_TYPE):
        patch_request = urllib2.Request(self._process_url(url), data=data)
        patch_request.add_header('Content-Type', content_type)
        patch_request.get_method = lambda: "PATCH"
        return self._request(op_name, patch_request)

    def _process_url(self, url):
        effective_url = "%s%s" % (self.cmc_host, url) if str(url).startswith("/") else url
        print "Effective URL", effective_url
        return effective_url

    def _request(self, op_name, request):
        if self.request_csrf_token and isinstance(request, urllib2.Request):
            request.add_header('X-CSRF-TOKEN', self.request_csrf_token)
        try:
            lt_response = self.opener.open(request)
        except urllib2.HTTPError, h:
            lt_response = h
        data = None
        response_code = lt_response.code
        if response_code < 400:
            data = lt_response.read()

        try:
            data = json.loads(data)
        except (ValueError, TypeError):
            pass

        print '==> {} - {} '.format(op_name, response_code)
        return {'response': lt_response, 'data': data}

    def follow_redirects(self, response):
        if response.code == 302 or response.code == 301:
            new_location = response.info().getheader('Location')
            print "Follow to", new_location
            if not 'http' in new_location:
                return
            response = self._request('follow_redirect', new_location)['response']
            return self.follow_redirects(response)
        return response

    def logout(self):
        #response_data = self._request('logout', urllib2.Request(self._process_url(get_cmc_api_end_point('logout'))))
        #self.follow_redirects(response_data['response'])
        self._logged_in = False

    @property
    def request_csrf_token(self):
        return self._request_csrf_token

    @request_csrf_token.setter
    def request_csrf_token(self, req_csrf_token):
        self._request_csrf_token = req_csrf_token
