from .base import BaseProtocol, BaseHoneypot
from .libs import ldapasn1
from pyasn1.codec.ber import decoder

from datetime import datetime, timezone


class LdapProtocol(BaseProtocol):

    config = {
    }

    def __init__(self, config=None):
        if config:
            self.config = config
        self.protocol_name = "ldap"
        
    def connection_made(self, transport) -> None:
        self.transport = transport
        self.logger.log(self.protocol_name + "." + self.logger.CONNECTION, self.transport)

    def data_received(self, data):
        # process request
        self.logger.log(self.protocol_name + "." + self.logger.DATA, self.transport, data=data)
        
        responses = self.process_request(data)
        if responses:
            for response in responses:
                self.send_response(response)    

    def process_request(self, request):
        # parse LDAP message using impacket ldapasn1
        ldapMessage, _ = decoder.decode(request, asn1Spec=ldapasn1.LDAPMessage())

        # dispatch message
        (response_ops, message_id) = self.dispatch(ldapMessage)
        ldapResponses=[]

        if response_ops:
                for response_op in response_ops:
                        ldapResponse = ldapasn1.LDAPMessage()
                        ldapResponse['messageID'] = message_id
                        ldapResponse['protocolOp'].setComponentByType(response_op.getTagSet(), response_op)
                        ldapResponses.append(ldapResponse)
                return ldapResponses
        else:
                return None


    def dispatch(self, ldapMessage):
        message_id = ldapMessage['messageID']
        protocolOp = ldapMessage['protocolOp']
        name = protocolOp.getName()

        msgs=[]

        if name == 'bindRequest':
            msgs.append(self.bind_response(protocolOp))
        elif name == 'searchRequest':
            msgs.append(self.searchrequest_response(protocolOp))
            msgs.append(self.searchresult_done())
        elif name == 'unbindRequest':
            self.transport.close()
        elif name == 'abandonRequest':
            self.transport.close()
        else:
            self.transport.close()

        return (msgs, message_id)


    def bind_response(self, protocolOp):
        
        authentication = protocolOp['bindRequest']['authentication'].getName()
        msg = ldapasn1.BindResponse()

        if authentication == 'simple':
            username = str(protocolOp['bindRequest']['name'])
            password = str(protocolOp['bindRequest']['authentication']['simple'])

            if password == '':
                # anonymous bind, allow
                msg['resultCode'] = 0
                msg['matchedDN'] = ''
                msg['diagnosticMessage'] = ''
            else:
                # register user, disallow
                msg['resultCode'] = 49
                msg['matchedDN'] = ''
                msg['diagnosticMessage'] = '8009030C: LdapErr: DSID-0C090569, comment: AcceptSecurityContext error, data 2030, v4f7c'
            
            self.logger.log(self.protocol_name + "." + self.logger.LOGIN, self.transport, extra={'username':username, 'password':password})

        elif authentication == 'sasl':
            #TODO
            msg['resultCode'] = 49
            msg['matchedDN'] = ''
            msg['diagnosticMessage'] = '8009030C: LdapErr: DSID-0C090569, comment: AcceptSecurityContext error, data 2030, v4f7c'
            pass


        #import ipdb; ipdb.set_trace()
        return msg

    def searchrequest_response(self, protocolOp):
        scope = str(protocolOp['searchRequest']['scope'])
        msg = ldapasn1.SearchResultDone()

        self.logger.log(self.protocol_name + "." + self.logger.QUERY, self.transport, extra={
            'scope': scope, 
            'baseObject': protocolOp['searchRequest'].get('baseObject')
        })

        if scope == 'baseObject':
            # return informations about server
            # client can query many attributes without being authenticated
            # example : ldapsearch -H ldap://<ip> -s base -x serverName dnsHostName

            attributes = protocolOp['searchRequest']['attributes']
            attributes_search_values = []
            for attr in attributes:
                attributes_search_values.append(attr._value.decode())

            msg = self.searchresentry_response(attributes_search_values)

        else:
            msg['resultCode'] = 1
            msg['matchedDN'] = ''
            msg['diagnosticMessage'] = 'errorMessage: 000004DC: LdapErr: DSID-0C090C21, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4f7c'
        
        return msg

    def searchresentry_response(self, attributes_search_values):
        # default attribute list on Windows Server
        attributes_values = {
            'forestFunctionality': '2', # DS_BEHAVIOR_WIN2003
            'domainControllerFunctionality': '7', # DS_BEHAVIOR_WIN2016
            'supportedSASLMechanisms': [
                'GSSAPI', 'GSS-SPNEGO', 'EXTERNAL','DIGEST-MD5'
            ],
            'supportedLDAPVersion': '3',
            'supportedLDAPPolicies': [
                'MaxPoolThreads','MaxPercentDirSyncRequests','MaxDatagramRecv','MaxReceiveBuffer','InitRecvTimeout','MaxConnections','MaxConnIdleTime','MaxPageSize','MaxBatchReturnMessages','MaxQueryDuration','MaxDirSyncDuration','MaxTempTableSize','MaxResultSetSize','MinResultSets','MaxResultSetsPerConn','MaxNotificationPerConn','MaxValRange','MaxValRangeTransitive','ThreadMemoryLimit','SystemMemoryLimitPercent'
            ],
            'supportedControl': [
                '1.2.840.113556.1.4.319','1.2.840.113556.1.4.801','1.2.840.113556.1.4.473','1.2.840.113556.1.4.528','1.2.840.113556.1.4.417','1.2.840.113556.1.4.619','1.2.840.113556.1.4.841','1.2.840.113556.1.4.529','1.2.840.113556.1.4.805','1.2.840.113556.1.4.521','1.2.840.113556.1.4.970','1.2.840.113556.1.4.1338','1.2.840.113556.1.4.474','1.2.840.113556.1.4.1339','1.2.840.113556.1.4.1340','1.2.840.113556.1.4.1413','2.16.840.1.113730.3.4.9','2.16.840.1.113730.3.4.10','1.2.840.113556.1.4.1504','1.2.840.113556.1.4.1852','1.2.840.113556.1.4.802','1.2.840.113556.1.4.1907','1.2.840.113556.1.4.1948','1.2.840.113556.1.4.1974','1.2.840.113556.1.4.1341','1.2.840.113556.1.4.2026','1.2.840.113556.1.4.2064','1.2.840.113556.1.4.2065','1.2.840.113556.1.4.2066','1.2.840.113556.1.4.2090','1.2.840.113556.1.4.2205','1.2.840.113556.1.4.2204','1.2.840.113556.1.4.2206','1.2.840.113556.1.4.2211','1.2.840.113556.1.4.2239','1.2.840.113556.1.4.2255','1.2.840.113556.1.4.2256','1.2.840.113556.1.4.2309','1.2.840.113556.1.4.2330','1.2.840.113556.1.4.2354'
            ],
            'supportedCapabilities': [
                '1.2.840.113556.1.4.1851','1.2.840.113556.1.4.1670','1.2.840.113556.1.4.1791','1.2.840.113556.1.4.1935','1.2.840.113556.1.4.2080','1.2.840.113556.1.4.2237','1.2.840.113556.1.4.1880'
            ],
            'subschemaSubentry': 'CN=Aggregate,CN=Schema,CN=Configuration,CN={5C1BD4E7-198D-44B7-866D-D881083E2BDA}',
            'serverName' : 'CN=SERVER-01$name01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=MOP,DC=INTRA',
            'schemaNamingContext': 'CN=Schema,CN=Configuration,DC=MOP,DC=INTRA',
            'namingContexts': [
                'CN=Configuration,DC=MOP,DC=INTRA',
                'CN=Schema,CN=Configuration,DC=MOP,DC=INTRA'
            ],
            'isSynchronized': 'TRUE',
            'highestCommittedUSN': '12352',
            'dsServiceName': 'CN=NTDS Settings,CN=SERVER-01$name01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=MOP,DC=INTRA',
            'dnsHostName': 'SERVER-01.MOP.INTRA',
            'currentTime': datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S.0Z'),
            'configurationNamingContext': 'CN=Configuration,DC=MOP,DC=INTRA'
        }
        
        # Filter the dictionary based on search value
        if attributes_search_values == []:
            filtered_values = attributes_values
        else:
            filtered_values = {k: attributes_values[k] for k in attributes_search_values if k in attributes_values}


        # Create a list to hold PartialAttribute objects
        partial_attributes = []
        msg = ldapasn1.SearchResultEntry()
        msg['objectName']=''
        
        # loop on the configuration dictionary 
        for attribute_name, attribute_value in filtered_values.items():
            att = ldapasn1.PartialAttribute()
            att['type'] = attribute_name

            # Check if the attribute value is a set or a single value
            if isinstance(attribute_value, list):
                for i in range(len(attribute_value)):
                   att['vals'].setComponentByPosition(i, attribute_value[i])
            else:
                att['vals'].setComponentByPosition(0, attribute_value)

            partial_attributes.append(att)

        # Set the attributes in the SearchResultEntry message
        msg['attributes'] = ldapasn1.PartialAttributeList()
        for idx, attribute in enumerate(partial_attributes):
            msg['attributes'].setComponentByPosition(idx, attribute)
       
        return msg


    def searchresult_done(self):
        msg = ldapasn1.SearchResultDone()
        msg['resultCode'] = 0
        msg['matchedDN'] = ''
        msg['diagnosticMessage'] = ''
        return msg

    def send_response(self, response):
        try:
            resp = ldapasn1.encoder.encode(response)
            self.transport.write(resp)
        except:
            self.transport.close()
        

class LdapHoneypot(BaseHoneypot):
    """common class to all trapster instance"""

    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.handler = lambda: LdapProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config
