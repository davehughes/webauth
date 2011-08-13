import unittest
from webauth import *

class TestVerifierInternal(unittest.TestCase):

    def setUp(self):
        self.verifier = Verifier('localhost', 54321)

    def testBadTokenShortcircuiting(self):
        # ensure that a null token doesn't make it to the Verify service
        self.assertRaises(NotAuthenticatedError,
                          self.verifier.verify,
                          token=None, ip=None)

    def testRequestBuilding(self):
        v = self.verifier
        self.assertEqual(v.build_request('token', '127.0.0.1', True, True),
                         'token:127.0.0.1: : : :C:')
        self.assertEqual(v.build_request('token', '127.0.0.1', False, False),
                         'token:127.0.0.1:N: : : :')
        self.assertEqual(v.build_request('token', '127.0.0.1'),
                         'token:127.0.0.1:N: : : :')
        self.assertEqual(v.build_request('token', '127.0.0.1', True),
                         'token:127.0.0.1: : : : :')
        self.assertEqual(v.build_request('token', '127.0.0.1', False, True),
                         'token:127.0.0.1:N: : :C:')

    def testResponseErrorHandling(self):
        handle_response = self.verifier.handle_response
        
        # raise service error if it gives back an unparseable int for status
        nonIntStatus = 'foo:'
        self.assertRaises(AuthServiceError, handle_response, nonIntStatus)
                          
                          

        # raise service error if it gives back a nonsense status code
        for status in [-1, 8]:
            unrecognizedStatus = '%s:Generic error message:' % status
            self.assertRaises(AuthServiceError, 
                              handle_response, 
                              unrecognizedStatus)

        # ensure that expired or bad status codes raise the appropriate error
        for status in [1,7]:
            noAuthStatus = '%s:Generic error message:' % status
            self.assertRaises(NotAuthenticatedError,
                              handle_response,
                              noAuthStatus)

        # ensure that service error codes raise appropriate errors
        for status in [2, 3, 4, 5, 6]:
            svcErrorStatus = '%s:Generic error message:' % status
            self.assertRaises(AuthServiceError,
                              handle_response,
                              svcErrorStatus)
            
        # ensure that a good response doesn't cause an error
        handle_response('0:foo@bar:AUTHENONLY:')

    def testResponseSuccessHandling(self):
        handle_response = self.verifier.handle_response

        # Valid responses which should return the corresponding data objects
        response_to_obj_map = {
            # vanilla authentication-only response
            '0:foo@bar:AUTHENONLY:': {
                'principal': 'foo',
                'realm': 'bar'
                },

            # response from specifying callapp
            '0:foo@bar:AUTHENONLY:http://www.example.com/:': {
                'principal': 'foo',
                'realm': 'bar',
                'callapp': 'http://www.example.com/'
                },

            # response with fetchprofile=True
            '0:foo@bar:PRIMARY:Affil1:Dept1:Affil2:Dept2:': {
                'principal': 'foo',
                'realm': 'bar',
                'principal_type': 'PRIMARY',
                'affiliations': {
                    'Affil1': 'Dept1',
                    'Affil2': 'Dept2'
                    }
                }
            }

        for responsestring, resultobj in response_to_obj_map.iteritems():
            self.assertEqual(handle_response(responsestring), resultobj)

        # Invalid result strings which should trigger an AuthServiceError
        invalid_response_strings = [
            # bad principal@realm specifier
            '0:foo:AUTHENONLY:',
            ]

        for responsestring in invalid_response_strings:
            self.assertRaises(AuthServiceError, 
                              handle_response,
                              responsestring)

if __name__ == '__main__':
    unittest.main()
