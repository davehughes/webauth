'''
 See http://asu.edu/webauth/implement.htm for more details on implementation.
'''
import socket

class Verifier(object):
    '''
    Wraps a (host, port) pair and provides a verify method for ensuring
    authentication through the WebAuth service.
    '''

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def verify(self, token, ip, fetchprofile=False, include_callapp=False):
        '''
        Call Verify service, returning basic information about the requesting
        user (based on token and IP address) or raising the appropriate
        error if the user is not authenticated.
        '''

        # sanity check - shortcut inevitable failure
        if token == None:
            raise NotAuthenticatedError('No authenticator provided')

        # build request, call service, and handle response
        request = self.build_request(token, ip, fetchprofile, include_callapp)
        response = self.get_response(request)
        return self.handle_response(response)

    def build_request(self, token, ip, 
                      fetchprofile=False, 
                      include_callapp=False):
        '''
        Build a simple request string from the provided params.
        '''
        return '%s:%s:%s: : :%s:' % (token,
                                     ip,
                                     ' ' if fetchprofile else 'N',
                                     'C' if include_callapp else ' ')
    

    def get_response(self, request):
        '''
        Call the Verify service, writing the provided request string and
        returning the resulting response string.
        '''

        # connect to socket or die trying
        try:
            s = socket.create_connection((self.host, self.port))
        except socket.error, e:
            raise AuthClientError('Cannot connect to verify host: %s:%s' \
                                      % (self.host, self.port))

        # write request line to socket, then read and return the result line
        try:
            s.send(request)
            s.send('\n')
            return s.recv(4096)
        except socket.error, e:
            raise AuthClientError(e)
        finally:
            s.close()

    # see http://www.asu.edu/webauth/implement.html for result format details
    def handle_response(self, response):
        '''
        Given a raw response string returned from the Verify service, parse 
        into a dict structure or raise an error appropriate to the status code.
        '''
        response_values = response.split(':')

        # sanity check on values length
        if len(response_values) < 1:
            raise AuthServiceError('No status code provided')

        # parse the status code as an int
        try:
            status = int(response_values[0])
        except ValueError:
            raise AuthServiceError('Unrecognized status code: %s (%s)' \
                                       % (response_values[0], 
                                          response_values[1]))
        if status == 0:
            return self.parse_successful_response(response_values)
        elif status == 1:
            raise NotAuthenticatedError(response_values[1])
        elif status == 2:
            raise AuthServiceError(response_values[1])
        elif status == 3:
            raise AuthServiceError(response_values[1])
        elif status == 4:
            raise AuthServiceError(response_values[1])
        elif status == 5:
            raise AuthServiceError(response_values[1])
        elif status == 6:
            raise AuthServiceError(response_values[1])
        elif status == 7:
            raise NotAuthenticatedError(response_values[1])
        else:
            raise AuthServiceError('Unrecognized status code: %s (%s)' \
                                       % (status, response_values[1]))

    def parse_successful_response(self, response_values):
        '''
        Given a list of strings split on colons in one of the two
        following formats:
        
        0:principal@REALM:AUTHENONLY:CALLAPP
        0:principal@REALM:principalType:[affiliation:department]*
        
        return a dict containing the relevant information:
        
        >>> vals1 = ['0','foo@bar','AUTHENONLY','myapp']
        >>> parse_successful_response(vals1)
       
        -> {'principal': 'foo', 
            'realm': 'bar', 
            'callapp': 'myapp'}

        >>> vals2 = ['0','foo@bar','Primary','Faculty','Dept1','Student','Dept2']
        >>> parse_successful_response(vals2)

         -> {'principal': 'foo', 
             'realm': 'bar', 
             'principal_type': 'Primary',
             'affiliations': 
               {'Faculty': 'Dept1', 'Student': 'Dept2'}}
        '''

        result = {}
    
        # parse principal@realm (which is always specified)
        principal, at, realm = response_values[1].partition('@')
        if not principal or not realm:
            raise AuthServiceError('Invalid user string in response')
    
        result['principal'] = principal
        result['realm'] = realm

        if response_values[2] == 'AUTHENONLY':
            # retrieve and set callapp if it is returned
            callapp_val = ':'.join(response_values[3:]).strip(':')
            if len(callapp_val) != 0:
                result['callapp'] = callapp_val
        else:
            result['principal_type'] = response_values[2]
        
            # log a warning if a bad affiliation section is returned
            affilvals = response_values[3:]
            if not len(affilvals) % 2:
                raise AuthClientError('Invalid affiliations specified: %s' % affilvals)
            
            # create a dict of {affiliation_type -> organization} from a list
            # like ['affil1', 'org1', 'affil2', 'org2', ...]
            result['affiliations'] = dict(zip([val for idx, val 
                                               in enumerate(affilvals) 
                                               if not idx % 2],
                                              [val for idx, val 
                                               in enumerate(affilvals)
                                               if idx % 2]))
        return result

class NotAuthenticatedError(Exception):
    '''
    Represents a situation where the verify service indicates that the 
    provided authentication token is invalid and the requesting user will
    need to go through the weblogin page to reauthenticate.
    '''
    pass

class AuthServiceError(Exception):
    '''
    Error in the verify service that is not recoverable through any user action.
    Generally, this results from an unrecognized status code, a status code
    representing a system error, or a malformed response.
    '''
    pass

class AuthClientError(Exception):
    '''
    Error in the webauth client caused by a socket connection error.
    '''
    pass
