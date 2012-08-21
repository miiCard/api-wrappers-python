import json
import httplib2
import oauth2 as oauth
import urllib

class Claim(object):
    def __init__(self, verified):
        self.verified = verified

class Identity(Claim):
    def __init__(self, verified, source, user_id, profile_url):
        super(Identity, self).__init__(verified)

        self.source = source
        self.user_id = user_id
        self.profile_url = profile_url

    @staticmethod
    def FromDict(dict):
        return Identity(
                        dict.get('Verified', None),
                        dict.get('Source', None),
                        dict.get('UserId', None),
                        dict.get('ProfileUrl', None)
                        )

class EmailAddress(Claim):
    def __init__(self, verified, display_name, address, is_primary):
        super(EmailAddress, self).__init__(verified)

        self.display_name = display_name
        self.address = address
        self.is_primary = is_primary

    @staticmethod
    def FromDict(dict):
        return EmailAddress(
                            dict.get('Verified', None),
                            dict.get('DisplayName', None),
                            dict.get('Address', None),
                            dict.get('IsPrimary', None)
                            )

class PhoneNumber(Claim):
    def __init__(self, verified, display_name, country_code, national_number, is_mobile, is_primary):
        super(PhoneNumber, self).__init__(verified)
        
        self.display_name = display_name
        self.country_code = country_code
        self.national_number = national_number
        self.is_mobile = is_mobile
        self.is_primary = is_primary

    @staticmethod
    def FromDict(dict):
        return PhoneNumber(
                           dict.get('Verified', None),
                           dict.get('DisplayName', None),
                           dict.get('CountryCode', None),
                           dict.get('NationalNumber', None),
                           dict.get('IsMobile', None),
                           dict.get('IsPrimary', None)
                           )

class PostalAddress(Claim):
    def __init__(self, verified, house, line1, line2, city, region, code, country, is_primary):
        super(PostalAddress, self).__init__(verified)

        self.house = house
        self.line1 = line1
        self.line2 = line2
        self.city = city
        self.region = region
        self.code = code
        self.country = country
        self.is_primary = is_primary

    @staticmethod
    def FromDict(dict):
        return PostalAddress(
                             dict.get('Verified', None),
                             dict.get('House', None),
                             dict.get('Line1', None),
                             dict.get('Line2', None),
                             dict.get('City', None),
                             dict.get('Region', None),
                             dict.get('Code', None),
                             dict.get('Country', None),
                             dict.get('IsPrimary', None)
                             )

class WebProperty(Claim):
    def __init__(self, verified, display_name, identifier, type):
        super(WebProperty, self).__init__(verified)

        self.display_name = display_name
        self.identifier = identifier
        self.type = type

    @staticmethod
    def FromDict(dict):
        return WebProperty(
                           dict.get('Verified', None),
                           dict.get('DisplayName', None),
                           dict.get('Identifier', None),
                           dict.get('Type', None)
                           )

class WebPropertyType(object):
    domain = 0
    website = 1

class MiiUserProfile(object):
    def __init__(
                 self, 
                 username,
                 salutation,
                 first_name,
                 middle_name,
                 last_name,
                 previous_first_name,
                 previous_middle_name,
                 previous_last_name,
                 last_verified,
                 profile_url,
                 profile_short_url,
                 card_image_url,
                 email_addresses,
                 identities,
                 phone_numbers,
                 postal_addresses,
                 web_properties,
                 identity_assured,
                 has_public_profile,
                 public_profile
                 ):

        self.username = username
        self.salutation = salutation
        self.first_name = first_name
        self.middle_name = middle_name
        self.last_name = last_name
        self.previous_first_name = previous_first_name
        self.previous_middle_name = previous_middle_name
        self.previous_last_name = previous_last_name
        self.last_verified = last_verified
        self.profile_url = profile_url
        self.profile_short_url = profile_short_url
        self.card_image_url = card_image_url
        self.email_addresses = email_addresses
        self.identities = identities
        self.phone_numbers = phone_numbers
        self.postal_addresses = postal_addresses
        self.web_properties = web_properties
        self.identity_assured = identity_assured
        self.has_public_profile = has_public_profile
        self.public_profile = public_profile

    @staticmethod
    def FromDict(dict):
        emails = dict.get('EmailAddresses', None)
        phone_numbers = dict.get('PhoneNumbers', None)
        postal_addresses = dict.get('PostalAddresses', None)
        identities = dict.get('Identities', None)
        web_properties = dict.get('WebProperties', None)
        public_profile = dict.get('PublicProfile', None)

        if emails:
            emails_parsed = []
            for email in emails:
                emails_parsed.append(EmailAddress.FromDict(email))
        else:
            emails_parsed = None

        if phone_numbers:
            phone_numbers_parsed = []
            for phone_number in phone_numbers:
                phone_numbers_parsed.append(PhoneNumber.FromDict(phone_number))
        else:
           phone_numbers_parsed = None 

        if postal_addresses:
            postal_addresses_parsed = []
            for postal_address in postal_addresses:
                postal_addresses_parsed.append(PostalAddress.FromDict(postal_address))
        else:
            postal_addresses_parsed = None

        if identities:
            identities_parsed = []
            for identity in identities:
                identities_parsed.append(Identity.FromDict(identity))
        else:
            identities_parsed = None

        if web_properties:
            web_properties_parsed = []
            for web_property in web_properties:                 
                web_properties_parsed.append(WebProperty.FromDict(web_property))
        else:
            web_properties_parsed = None

        if public_profile:
            public_profile_parsed = MiiUserProfile.FromDict(public_profile)
        else:
            public_profile_parsed = None

        return MiiUserProfile(
                              dict.get('Username', None),
                              dict.get('Salutation', None),
                              dict.get('FirstName', None),
                              dict.get('MiddleName', None),
                              dict.get('LastName', None),
                              dict.get('PreviousFirstName', None),
                              dict.get('PreviousMiddleName', None),
                              dict.get('PreviousLastName', None),
                              dict.get('LastVerified', None),
                              dict.get('ProfileUrl', None),
                              dict.get('ProfileShortUrl', None),
                              dict.get('CardImageUrl', None),
                              emails_parsed,
                              identities_parsed,
                              phone_numbers_parsed,
                              postal_addresses_parsed,
                              web_properties_parsed,
                              dict.get('IdentityAssured', None),
                              dict.get('HasPublicProfile', None),
                              public_profile_parsed
                              )

class MiiApiCallStatus(object):
    success = 0
    failure = 1

class MiiApiErrorCode(object):
    success = 0
    access_revoked = 100,
    user_subscription_lapsed = 200,
    exception = 10000

class MiiApiResponse(object):
    def __init__(self, status, error_code, error_message, data,):
        self.status = status
        self.error_code = error_code
        self.error_message = error_message
        self.data = data

    @staticmethod
    def FromDict(dict, data_processor):
        payload_json = dict.get('Data')

        if payload_json and data_processor:
            payload = data_processor(payload_json)
        elif payload_json is not None:
            payload = payload_json
        else:
            payload = None

        return MiiApiResponse(
                              dict.get('Status', MiiApiCallStatus.success),
                              dict.get('ErrorCode', MiiApiErrorCode.success),
                              dict.get('ErrorMessage', None),
                              payload
                              )

class MiiCardOAuthServiceBase(object):
    def __init__(self, consumer_key, consumer_secret, access_token, access_token_secret):
        self.consumer_key = consumer_key;
        self.consumer_secret = consumer_secret;
        self.access_token = access_token;
        self.access_token_secret = access_token_secret;

class MiiCardOAuthClaimsService(MiiCardOAuthServiceBase):
    def __init__(self, consumer_key, consumer_secret, access_token, access_token_secret):
        super(MiiCardOAuthClaimsService, self).__init__(consumer_key, consumer_secret, access_token, access_token_secret)

    def get_claims(self):
        return self._make_request(
                                  MiiCardServiceUrls.get_method_url('GetClaims'),
                                  None,
                                  MiiUserProfile.FromDict
                                  )

    def is_social_account_assured(self, social_account_id, social_account_type):
        post_params = json.dumps({"socialAccountId": social_account_id, "socialAccountType": social_account_type})

        return self._make_request(
                                  MiiCardServiceUrls.get_method_url('IsSocialAccountAssured'),
                                  post_params,
                                  None
                                  )

    def is_user_assured(self):
        return self._make_request(
                                  MiiCardServiceUrls.get_method_url('IsUserAssured'),
                                  None,
                                  None
                                  )
    
    def assurance_image(self, type):
        post_params = json.dumps({"type": type})

        return self._make_request(
                                  MiiCardServiceUrls.get_method_url('AssuranceImage'),
                                  post_params,
                                  None,
                                  wrapped_response = False
                                  )

    def _make_request(self, url, post_data, payload_processor, wrapped_response = True):
        # http://parand.com/say/index.php/2010/06/13/using-python-oauth2-to-access-oauth-protected-resources/
        consumer = oauth.Consumer(self.consumer_key, self.consumer_secret)
        access_token = oauth.Token(self.access_token, self.access_token_secret)
        
        import httplib2
        httplib2.debuglevel = 1000

        client = OAuthClient(consumer, access_token)
        client.set_signature_method(oauth.SignatureMethod_HMAC_SHA1())

        new_headers = {'Content-Type': 'application/json'}
        if not post_data:
            new_headers['Content-Length'] = '0';

        response, content = client.request(url, method="POST", body=post_data, headers=new_headers)

        if wrapped_response:
            return MiiApiResponse.FromDict(json.loads(content), payload_processor)
        elif payload_processor:
            return payload_processor(content)
        else:
            return content

class MiiCardServiceUrls(object):
    oauth_endpoint = "https://sts.miicard.com/auth/OAuth.ashx"
    claims_svc = "https://sts.miicard.com/api/v1/Claims.svc/json"

    @staticmethod
    def get_method_url(method_name):
        return MiiCardServiceUrls.claims_svc + "/" + method_name

# Fixup for simplegeo OAuth bug
class OAuthClient(oauth.Client):
    def request(self, uri, method="GET", body='', headers=None,
        redirections=httplib2.DEFAULT_MAX_REDIRECTS, connection_type=None):
        DEFAULT_POST_CONTENT_TYPE = 'application/x-www-form-urlencoded'

        if not isinstance(headers, dict):
            headers = {}

        if method == "POST" and 'Content-Type' not in headers:
            headers['Content-Type'] = headers.get('Content-Type',
                DEFAULT_POST_CONTENT_TYPE)

        is_form_encoded = \
            headers.get('Content-Type') == 'application/x-www-form-urlencoded'

        if is_form_encoded and body:
            parameters = parse_qs(body)
        else:
            parameters = None

        req = OAuthRequest.from_consumer_and_token(self.consumer,
            token=self.token, http_method=method, http_url=uri,
            parameters=parameters, body=body, is_form_encoded=is_form_encoded)

        req.sign_request(self.method, self.consumer, self.token)

        schema, rest = urllib.splittype(uri)
        if rest.startswith('//'):
            hierpart = '//'
        else:
            hierpart = ''
        host, rest = urllib.splithost(rest)

        realm = schema + ':' + hierpart + host

        if is_form_encoded:
            body = req.to_postdata()
        elif method == "GET":
            uri = req.to_url()
        else:
            headers.update(req.to_header(realm=realm))

        return httplib2.Http.request(self, uri, method=method, body=body,
            headers=headers, redirections=redirections,
            connection_type=connection_type)

class OAuthRequest(oauth.Request):
    def sign_request(self, signature_method, consumer, token):
        """Set the signature parameter to the result of sign."""

        if 'oauth_consumer_key' not in self:
            self['oauth_consumer_key'] = consumer.key

        if token and 'oauth_token' not in self:
            self['oauth_token'] = token.key

        self['oauth_signature_method'] = signature_method.name
        self['oauth_signature'] = signature_method.sign(self, consumer, token)

    @classmethod
    def from_consumer_and_token(cls, consumer, token=None,
            http_method=oauth.HTTP_METHOD, http_url=None, parameters=None,
            body='', is_form_encoded=False):
        if not parameters:
            parameters = {}
 
        defaults = {
            'oauth_consumer_key': consumer.key,
            'oauth_timestamp': cls.make_timestamp(),
            'oauth_nonce': cls.make_nonce(),
            'oauth_version': cls.version,
        }
 
        defaults.update(parameters)
        parameters = defaults
 
        if token:
            parameters['oauth_token'] = token.key
            if token.verifier:
                parameters['oauth_verifier'] = token.verifier
 
        return OAuthRequest(http_method, http_url, parameters, body=body,
                       is_form_encoded=is_form_encoded)
