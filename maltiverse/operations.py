""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import requests
import hashlib
from .constants import *
from connectors.core.connector import get_logger, ConnectorError
from requests import exceptions as req_exceptions
logger = get_logger('maltiverse')


class Maltiverse(object):

    def __init__(self, config):
        self.server_url = config.get('server_url').strip()
        self.api_key = config.get('api_key')
        self.headers = {'accept': 'application/json', 'Authorization': 'Bearer {}'.format(self.api_key)}
        if not self.server_url.startswith('https://') and not self.server_url.startswith('http://'):
            self.server_url = 'https://{0}'.format(self.server_url)
        if self.server_url.endswith('/'):
            self.server_url = self.server_url[:-1]

    def make_api_call(self, endpoint=None, method='GET', headers=None, health_check=False):
        url = self.server_url + endpoint
        if headers:
            self.headers.update(headers)
        try:
            logger.debug('Making a request with {0} - {1}'.format(method, url))
            response = requests.request(method, url, headers=self.headers)
            json_resp = response.json()
            if health_check and response.status_code == 200:
                return response
            elif response.status_code in (200, 400, 404):
                try:
                    return json_resp
                except Exception:
                    raise ConnectorError({'status_code': str(response.status_code), 'response': response.content})
            elif response.status_code == 401:
                raise ConnectionError(json_resp.get('message'))
            else:
                logger.error({'status': 'Failure', 'status_code': str(response.status_code), 'response': response.text})
                raise ConnectorError(json_resp.get('message',response.text))
                    
        except req_exceptions.SSLError :
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            raise ConnectorError(str(err))


def get_ip_reputation(config, params):
    """
    Retrieves a reputation from Maltiverse for the IP address submitted to determine if it is suspicious based on the IP address you have specified.
    :param config: config
    :param params: params
    :return: Returns reputation and details from Maltiverse..
    """
    obj = Maltiverse(config)
    endpoint = '/ip/{0}'.format(params.get('ip'))
    return obj.make_api_call(endpoint=endpoint)


def get_domain_reputation(config, params):
    """
    Retrieves a reputation from Maltiverse for the IP address submitted to determine if it is suspicious based on the IP address you have specified.
    :param config: config
    :param params: params
    :return: Returns reputation and details from Maltiverse..
    """
    obj = Maltiverse(config)
    endpoint = '/hostname/{0}'.format(params.get('domain'))
    return obj.make_api_call(endpoint=endpoint)


def get_url_reputation(config, params):
    """
    Retrieves a reputation from Maltiverse for the URL submitted to determine if it is suspicious based on the URL you have specified.
    :param config: config
    :param params: params
    :return: Returns reputation and details from Maltiverse.
    """
    obj = Maltiverse(config)
    url = hashlib.sha256((params.get('url')).encode('utf-8')).hexdigest()
    endpoint = '/url/{0}'.format(url)
    return obj.make_api_call(endpoint=endpoint)


def get_file_reputation(config, params):
    """
    Retrieves a reputation from Maltiverse for the File Hash submitted to determine if it is suspicious based on the File Hash you have specified.
    :param config: config
    :param params: params
    :return: Returns reputation and details from Maltiverse.
    """
    obj = Maltiverse(config)
    hash_endpoint = hash_mapping.get(params.get("filehash_type"),params.get("filehash_type"))
    hash_endpoint = hash_endpoint.lower()
    endpoint = '/sample/{0}'.format(params.get('filehash')) if hash_endpoint == 'sha256' else '/sample/'+ hash_endpoint +'/{0}'.format(params.get('filehash'))
    return obj.make_api_call(endpoint=endpoint)



def _check_health(config):
    try:
        obj = Maltiverse(config)
        obj.make_api_call(endpoint='/ip/1.1.1.1', health_check=True)
        return True
    except Exception as err:
        logger.exception('Health check failed with: {0}'.format(err))
        raise ConnectorError('Health check failed with: {0}'.format(err))


operations = {
    'get_ip_reputation': get_ip_reputation,
    'get_domain_reputation': get_domain_reputation,
    'get_url_reputation': get_url_reputation,
    'get_file_reputation': get_file_reputation
}
