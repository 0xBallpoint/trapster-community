from trapster.modules.base import BaseProtocol, BaseHoneypot
from trapster.libs import ldapasn1
from trapster.libs.ntlm import build_ntlm_type2, wrap_spnego, extract_ntlm, parse_ntlm_type3

from pyasn1.codec.ber import decoder

from datetime import datetime, timezone
import random
import os


class LdapProtocol(BaseProtocol):

    # DSID and version tag vary per Windows Server version
    _dsid_map = {
        'Windows2008Domain':   ('DSID-0C09044E', 'v1db1'),
        'Windows2008R2Domain': ('DSID-0C0904DC', 'v2580'),
        'Windows2012Domain':   ('DSID-0C09052D', 'v2f4f'),
        'Windows2012R2Domain': ('DSID-0C090484', 'v3ff3'),
        'WinThreshold':        ('DSID-0C090569', 'v4f7c'),  # Server 2016/2019/2022
    }
    # Default user objects present in a freshly promoted AD domain controller.
    # and the domain controller itself
    _common_users = set({
        'administrator', 'guest', 'krbtgt',
    })

    def __init__(self, config=None):
        self.protocol_name = "ldap"
        self.config = config or {}

        # hostname: new global key, falls back to legacy 'server' key
        self._hostname = self.config.get('hostname') or self.config.get('server', 'DC01')
        self._common_users.update(set([self._hostname.lower()+'$']))

        # domain: new format is full FQDN (e.g. 'corp.local')
        # legacy format uses separate 'domain' + 'tld' keys (e.g. 'corp' + 'local')
        raw_domain = self.config.get('domain', 'corp.local')
        if '.' not in raw_domain:
            # legacy: domain is just the label, tld is separate
            raw_domain = f"{raw_domain}.{self.config.get('tld', 'local')}"
        self._dc_parts = raw_domain.split('.')  # ['corp', 'local']
        self._fqdn = raw_domain                 # 'corp.local'
        self._netbios_domain = self._dc_parts[0]


        level = self.config.get('level', 'WinThreshold')
        self._dsid, self._vtag = self._dsid_map.get(level, self._dsid_map['WinThreshold'])
        self._known_users = self._common_users

        self.functionality_level = self.get_functionality_level(self.config.get('level', 'WinThreshold'))
        self._highest_committed_usn = str(random.randint(40000, 200000))
        self._ntlm_challenge = None  # set when we issue a Type 2 challenge

    def _ldap_bind_error_nt_status_hex(self, bind_name: str, ntlm_identity: str = '') -> str:
        """Return LDAP bind subcode: bad DN (2030), unknown user (525), bad password (52e)."""
        candidate = (bind_name or '').strip()
        if not candidate and ntlm_identity:
            candidate = ntlm_identity.strip()
        if not candidate:
            return '2030'

        username = ''
        cand_lower = candidate.lower()
        base_dn = ','.join(f'dc={p}' for p in self._dc_parts)
        if '=' in candidate and ',' in candidate:
            # DN bind: must target this naming context, and carry a user-ish first RDN.
            if not (cand_lower.endswith(',' + base_dn) or cand_lower == base_dn):
                return '2030'
            first_rdn = candidate.split(',', 1)[0]
            if '=' not in first_rdn:
                return '2030'
            rdn_type, rdn_value = first_rdn.split('=', 1)
            if rdn_type.strip().lower() not in ('cn', 'uid', 'samaccountname', 'userprincipalname'):
                return '2030'
            username = rdn_value.strip().lower()
            if not username:
                return '2030'
        elif '@' in cand_lower:
            # UPN bind.
            user_part, domain_part = cand_lower.rsplit('@', 1)
            if domain_part != self._fqdn.lower() or not user_part:
                return '2030'
            username = user_part
        if '\\' in candidate:
            dom, _ = candidate.split('\\', 1)
            dom_lower = dom.lower()
            if dom_lower != self._netbios_domain.lower() and dom_lower != self._fqdn.lower():
                return '2030'
            username = candidate.split('\\', 1)[1].strip().lower()
            if not username:
                return '2030'
        if not username:
            # Plain account name: treat as naming-context valid but unknown unless common.
            username = cand_lower

        if username in self._known_users:
            return '52e'
        return '525'

    def _bind_diagnostic_message(self, bind_name: str, ntlm_identity: str = '') -> str:
        data = self._ldap_bind_error_nt_status_hex(bind_name, ntlm_identity)
        return (
            f'80090308: LdapErr: {self._dsid}, comment: AcceptSecurityContext error, data {data}, {self._vtag}'
        )

    def connection_made(self, transport) -> None:
        self.transport = transport
        self.logger.log(self.protocol_name + "." + self.logger.CONNECTION, self.transport)

    def data_received(self, data):
        # process request
        self.logger.log(self.protocol_name + "." + self.logger.DATA, self.transport, data=data)

        # A single TCP packet may contain multiple LDAP messages; process all of them
        remaining = data
        while remaining:
            try:
                responses, remaining = self.process_request(remaining)
            except Exception:
                break
            for response in responses:
                self.send_response(response)

    def process_request(self, request):
        # parse LDAP message; decoder returns (message, unconsumed_bytes)
        ldapMessage, remaining = decoder.decode(request, asn1Spec=ldapasn1.LDAPMessage())

        # dispatch message
        (response_ops, message_id) = self.dispatch(ldapMessage)
        ldapResponses = []

        if response_ops:
            for response_op in response_ops:
                ldapResponse = ldapasn1.LDAPMessage()
                ldapResponse['messageID'] = message_id
                ldapResponse['protocolOp'].setComponentByType(response_op.getTagSet(), response_op)
                ldapResponses.append(ldapResponse)

        return ldapResponses, bytes(remaining)


    def dispatch(self, ldapMessage):
        message_id = ldapMessage['messageID']
        protocolOp = ldapMessage['protocolOp']
        name = protocolOp.getName()

        msgs=[]

        if name == 'bindRequest':
            msgs.append(self.bind_response(protocolOp))
        elif name == 'searchRequest':
            response = self.searchrequest_response(protocolOp)
            msgs.append(response)
            # SearchResultEntry must be followed by SearchResultDone to complete the sequence.
            # For error cases, searchrequest_response already returns a SearchResultDone.
            if isinstance(response, ldapasn1.SearchResultEntry):
                msgs.append(self.searchresult_done())
        elif name == 'unbindRequest':
            self.transport.close()
        elif name == 'abandonRequest':
            pass  # client is abandoning a request, no response needed
        else:
            pass  # unknown operation — do not close, let the client move on

        return (msgs, message_id)


    def bind_response(self, protocolOp):
        try:
            bind_name = str(protocolOp['bindRequest']['name'])
        except Exception:
            bind_name = ''

        authentication = protocolOp['bindRequest']['authentication'].getName()
        msg = ldapasn1.BindResponse()

        if authentication == 'simple':
            username = bind_name
            password = str(protocolOp['bindRequest']['authentication']['simple'])

            if password == '':
                # anonymous bind, allow
                msg['resultCode'] = 0
                msg['matchedDN'] = ''
                msg['diagnosticMessage'] = ''
                self.logger.log(self.protocol_name + "." + self.logger.QUERY, self.transport, extra={'username': username})
            else:
                # credential bind, disallow
                msg['resultCode'] = 49
                msg['matchedDN'] = ''
                msg['diagnosticMessage'] = self._bind_diagnostic_message(username)
                self.logger.log(self.protocol_name + "." + self.logger.LOGIN, self.transport, extra={'username': username, 'password': password})

        elif authentication == 'sicilyNegotiate':
            # Microsoft Sicily (NTLM) — Type 1: raw NTLM bytes, no SPNEGO wrapper.
            # Sicily Phase 1 uses resultCode=0 (success), unlike SASL which uses 14.
            # The Type 2 challenge goes in matchedDN (not serverSaslCreds).
            self._ntlm_challenge = os.urandom(8)
            type2 = build_ntlm_type2(self._ntlm_challenge, self._hostname, self._fqdn, self._dc_parts)
            msg['resultCode'] = 0   # success — Sicily Phase 1 convention
            msg['matchedDN'] = type2
            msg['diagnosticMessage'] = ''

        elif authentication == 'sicilyResponse':
            # Microsoft Sicily (NTLM) — Type 3: extract and log credentials
            ntlm_type3 = bytes(protocolOp['bindRequest']['authentication']['sicilyResponse'])
            username, domain = parse_ntlm_type3(ntlm_type3)
            ntlm_identity = f'{domain}\\{username}' if domain else username
            self.logger.log(self.protocol_name + "." + self.logger.LOGIN, self.transport,
                            extra={'username': ntlm_identity,
                                   'password': ''})
            msg['resultCode'] = 49
            msg['matchedDN'] = ''
            msg['diagnosticMessage'] = self._bind_diagnostic_message(bind_name, ntlm_identity)

        elif authentication == 'sasl':
            try:
                credentials = bytes(protocolOp['bindRequest']['authentication']['sasl']['credentials'])
            except Exception:
                credentials = b''

            ntlm = extract_ntlm(credentials)

            if ntlm and ntlm[8:12] == b'\x01\x00\x00\x00':
                # NTLM Type 1 (Negotiate) — send Type 2 challenge
                self._ntlm_challenge = os.urandom(8)
                type2 = build_ntlm_type2(self._ntlm_challenge, self._hostname, self._fqdn, self._dc_parts)
                msg['resultCode'] = 14  # saslBindInProgress
                msg['matchedDN'] = ''
                msg['diagnosticMessage'] = ''
                msg['serverSaslCreds'] = wrap_spnego(type2)

            elif ntlm and ntlm[8:12] == b'\x03\x00\x00\x00':
                # NTLM Type 3 (Authenticate) — extract and log credentials
                username, domain = parse_ntlm_type3(ntlm)
                ntlm_identity = f'{domain}\\{username}' if domain else username
                self.logger.log(self.protocol_name + "." + self.logger.LOGIN, self.transport,
                                extra={'username': ntlm_identity,
                                       'password': ''})
                msg['resultCode'] = 49
                msg['matchedDN'] = ''
                msg['diagnosticMessage'] = self._bind_diagnostic_message(bind_name, ntlm_identity)

            else:
                msg['resultCode'] = 49
                msg['matchedDN'] = ''
                msg['diagnosticMessage'] = self._bind_diagnostic_message(bind_name)

        return msg

    # Attributes present on the RootDSE that a presence filter (attr=*) would match
    _ROOTDSE_ATTRIBUTES = frozenset([
        'objectclass', 'namingcontexts', 'defaultnamingcontext', 'rootdomainnamingcontext',
        'configurationnamingcontext', 'schemanamingcontext', 'currenttime', 'highestcommittedusn',
        'dshostname', 'dnsHostname', 'servername', 'dsservicename', 'issynchronized',
        'isglobalcatalogready', 'supportedldapversion', 'supportedldappolicies',
        'supportedcontrol', 'supportedcapabilities', 'supportedsaslmechanisms',
        'ldapservicename', 'subschemasubentry', 'forestfunctionality',
        'domainfunctionality', 'domaincontrollerfunctionality',
    ])

    def _filter_matches_rootdse(self, filter_component):
        """Return True if the filter could match the RootDSE entry."""
        try:
            name = filter_component.getName()
        except Exception:
            return True  # unknown filter structure — let it through

        if name == 'present':
            attr = str(filter_component['present']).lower()
            return attr in self._ROOTDSE_ATTRIBUTES

        if name in ('and', 'or'):
            # match if any sub-filter matches (conservative: return True if any child matches)
            for child in filter_component[name]:
                if self._filter_matches_rootdse(child):
                    return True
            return False

        if name == 'not':
            return not self._filter_matches_rootdse(filter_component['not'])

        # equalityMatch, substrings, greaterOrEqual, lessOrEqual, approxMatch, extensibleMatch
        # Extract attribute description from whichever field holds it
        for field in ('equalityMatch', 'substrings', 'greaterOrEqual', 'lessOrEqual',
                      'approxMatch', 'extensibleMatch'):
            try:
                attr = str(filter_component[field]['attributeDesc'] if field != 'substrings'
                           else filter_component[field]['type']).lower()
                return attr in self._ROOTDSE_ATTRIBUTES
            except Exception:
                continue

        return True  # unrecognised — let it through

    def searchrequest_response(self, protocolOp):
        scope = str(protocolOp['searchRequest']['scope'])
        msg = ldapasn1.SearchResultDone()

        try:
            base_object = protocolOp['searchRequest']['baseObject']
        except KeyError:
            base_object = ""

        self.logger.log(self.protocol_name + "." + self.logger.QUERY, self.transport, extra={
            'scope': scope, 
            'baseObject': str(base_object)
        })

        if scope == 'baseObject':
            # Return RootDSE only if the filter matches attributes that actually exist on it.
            # A real AD RootDSE has objectClass but not sAMAccountName, userPrincipalName, etc.
            # Unsupported filters return an empty result (SearchResultDone, resultCode=0).
            if not self._filter_matches_rootdse(protocolOp['searchRequest']['filter']):
                msg['resultCode'] = 0
                msg['matchedDN'] = ''
                msg['diagnosticMessage'] = ''
                return msg

            attributes = protocolOp['searchRequest']['attributes']
            attributes_search_values = []
            for attr in attributes:
                attributes_search_values.append(attr._value.decode(errors='backslashreplace'))

            msg = self.searchresentry_response(attributes_search_values)

        else:
            msg['resultCode'] = 1
            msg['matchedDN'] = ''
            msg['diagnosticMessage'] = 'errorMessage: 000004DC: LdapErr: DSID-0C090C21, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4f7c'
        
        return msg

    def get_functionality_level(self, value: str):
        # Functionality level from : https://learn.microsoft.com/fr-fr/powershell/module/activedirectory/set-addomainmode?view=windowsserver2022-ps

        identifier = [
            'Windows2008Domain',
            'Windows2008R2Domain',
            'Windows2012Domain',
            'Windows2012R2Domain',
            'WinThreshold', # Windows Server 2016
        ]
        try:
            return str(identifier.index(value))
        except ValueError:
            return str(7) # default to 2016

    def searchresentry_response(self, attributes_search_values):
        # default attribute list on Windows Server
        dc_str = ','.join(f'DC={p}' for p in self._dc_parts)
        attributes_values = {
            'domainFunctionality': self.functionality_level,
            'forestFunctionality': self.functionality_level,
            'domainControllerFunctionality': self.functionality_level,
            'rootDomainNamingContext': dc_str,
            'ldapServiceName': f"{self._fqdn}:{self._hostname}$@{self._fqdn.upper()}",
            'isGlobalCatalogReady': 'TRUE',
            'supportedSASLMechanisms': [
                'GSSAPI', 'GSS-SPNEGO', 'EXTERNAL', 'DIGEST-MD5'
            ],
            'supportedLDAPVersion': [
              '3', '2'
            ],
            'supportedLDAPPolicies': [
                'MaxPoolThreads','MaxPercentDirSyncRequests','MaxDatagramRecv','MaxReceiveBuffer','InitRecvTimeout','MaxConnections','MaxConnIdleTime','MaxPageSize','MaxBatchReturnMessages','MaxQueryDuration','MaxDirSyncDuration','MaxTempTableSize','MaxResultSetSize','MinResultSets','MaxResultSetsPerConn','MaxNotificationPerConn','MaxValRange','MaxValRangeTransitive','ThreadMemoryLimit','SystemMemoryLimitPercent'
            ],
            'supportedControl': [
                '1.2.840.113556.1.4.319','1.2.840.113556.1.4.801','1.2.840.113556.1.4.473','1.2.840.113556.1.4.528','1.2.840.113556.1.4.417','1.2.840.113556.1.4.619','1.2.840.113556.1.4.841','1.2.840.113556.1.4.529','1.2.840.113556.1.4.805','1.2.840.113556.1.4.521','1.2.840.113556.1.4.970','1.2.840.113556.1.4.1338','1.2.840.113556.1.4.474','1.2.840.113556.1.4.1339','1.2.840.113556.1.4.1340','1.2.840.113556.1.4.1413','2.16.840.1.113730.3.4.9','2.16.840.1.113730.3.4.10','1.2.840.113556.1.4.1504','1.2.840.113556.1.4.1852','1.2.840.113556.1.4.802','1.2.840.113556.1.4.1907','1.2.840.113556.1.4.1948','1.2.840.113556.1.4.1974','1.2.840.113556.1.4.1341','1.2.840.113556.1.4.2026','1.2.840.113556.1.4.2064','1.2.840.113556.1.4.2065','1.2.840.113556.1.4.2066','1.2.840.113556.1.4.2090','1.2.840.113556.1.4.2205','1.2.840.113556.1.4.2204','1.2.840.113556.1.4.2206','1.2.840.113556.1.4.2211','1.2.840.113556.1.4.2239','1.2.840.113556.1.4.2255','1.2.840.113556.1.4.2256','1.2.840.113556.1.4.2309','1.2.840.113556.1.4.2330','1.2.840.113556.1.4.2354'
            ],
            'supportedCapabilities' : [
                '1.2.840.113556.1.4.800','1.2.840.113556.1.4.1670','1.2.840.113556.1.4.1791','1.2.840.113556.1.4.1935','1.2.840.113556.1.4.2080','1.2.840.113556.1.4.2237'
            ],
            'subschemaSubentry' : f"CN=Aggregate,CN=Schema,CN=Configuration,{dc_str}",
            'serverName' : f"CN={self._hostname},CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,{dc_str}",
            'schemaNamingContext' : f"CN=Schema,CN=Configuration,{dc_str}",
            'namingContexts' : [
                dc_str,
                f"CN=Configuration,{dc_str}",
                f"CN=Schema,CN=Configuration,{dc_str}",
                f"DC=DomainDnsZones,{dc_str}",
                f"DC=ForestDnsZones,{dc_str}",
            ],
            'isSynchronized': 'TRUE',
            'highestCommittedUSN': self._highest_committed_usn,
            'dsServiceName': f"CN=NTDS Settings,CN={self._hostname},CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,{dc_str}",
            'dnsHostName': f"{self._hostname}.{self._fqdn}",
            'defaultNamingContext': dc_str,
            'currentTime': datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S.0Z'),
            'configurationNamingContext': f"CN=Configuration,{dc_str}"
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
        except Exception:
            self.transport.close()
        

class LdapHoneypot(BaseHoneypot):
    """common class to all trapster instance"""

    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.handler = lambda: LdapProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config
