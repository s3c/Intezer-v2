#!/usr/bin/env python3

#https://analyze.intezer.com/api/docs/documentation

from pprint import pprint
import requests
import threading
import time
import re
import os

#NOTE: API changes without notice, so hopefully this is complete
#FEATURE: Ability to pull shared strings
#FEATURE: Ability to look up endpoint host scan IDs, by hostname maybe?
#TEST: Disable dynamic execution and static extraction to see what happens
#TEST: Upload memory module to see what happens

class Intezer:

    def __init__(self, account_api_key):
        self._api_key = account_api_key
        self._get_access_token()

    def _get_failure_codes(self, status_code):

        if status_code == 202:
            return 'Request in progress'
        elif status_code == 400:
            return 'Invalid parameters'
        elif status_code == 401:
            return 'Invalid access token'
        elif status_code == 403:
            return 'Account quota exceeded'
        elif status_code == 404:
            return 'Resource not found'
        elif status_code == 409:
            return 'Resource conflict'
        elif status_code == 410:
            return 'Resource expired'
        elif status_code == 500:
            return 'Internal error'
        else:
            return 'API returned unknown status code: ' + str(status_code)

    #Docs says POST should always return 201 on success, but successfull token request returns 200
    def _get_access_token(self):

        response = requests.post('https://analyze.intezer.com/api/v2-0/get-access-token', json = {'api_key': self._api_key})
        if response.status_code != 200:
            raise RuntimeError(self._get_failure_codes(response.status_code))
        self._access_token = response.json()['result']
        self._session = requests.session()
        self._session.headers['Authorization'] = 'Bearer ' + self._access_token

    def get_analysis_by_hash(self, file_hash):

        file_hash = file_hash.lower()
        if not re.match('^(([0-9a-f]{32})|([0-9a-f]{40})|([0-9a-f]{64}))$', file_hash):
            raise TypeError('Provided hash of incorrect type')

        response = self._session.get('https://analyze.intezer.com/api/v2-0/files/' + file_hash)
        if response.status_code != 200:
            raise RuntimeError(self._get_failure_codes(response.status_code))
        return IntezerAnalysis(self, response.json())

    def analyze_file_by_path(self, file_path, disable_dynamic_execution = False, disable_static_extraction = False, code_item_type = 'file'):

        with open(file_path, 'rb') as inpf:
            data = inpf.read()

        file_name = os.path.split(file_path)[1]

        return self.analyze_file_by_stream(file_name, data, disable_dynamic_execution, disable_static_extraction, code_item_type)

    def analyze_file_by_stream(self, file_name, data, disable_dynamic_execution = False, disable_static_extraction = False, code_item_type = 'file'):

        files = {'file': (file_name, data)}

        response = self._session.post('https://analyze.intezer.com/api/v2-0/analyze', files = files, data = {'disable_dynamic_execution': disable_dynamic_execution, 'disable_static_extraction': disable_static_extraction, 'code_item_type': code_item_type})
        if response.status_code != 201:
            raise RuntimeError(self._get_failure_codes(response.status_code))
        return IntezerAnalysis(self, response.json())

    def submit_analysis_by_hash(self, file_hash, disable_dynamic_execution = False, disable_static_extraction = False):

        file_hash = file_hash.lower()
        if not re.match('^(([0-9a-f]{32})|([0-9a-f]{40})|([0-9a-f]{64}))$', file_hash):
            raise TypeError('Provided hash of incorrect type')

        response = self._session.post('https://analyze.intezer.com/api/v2-0/analyze-by-hash', json = {'hash': file_hash, 'disable_dynamic_execution': disable_dynamic_execution, 'disable_static_extraction': disable_static_extraction})
        if response.status_code != 201:
            raise RuntimeError(self._get_failure_codes(response.status_code))
        return IntezerAnalysis(self, response.json())

    def _get_analysis_summary_by_id(self, analysis_id):

        if not re.match('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', analysis_id):
            raise TypeError('Provided analysis identifier of incorrect type')

        response = self._session.get('https://analyze.intezer.com/api/v2-0/analyses/' + analysis_id)
        if response.status_code != 200:
            raise RuntimeError(self._get_failure_codes(response.status_code))
        return response.json()

    def _get_sub_analysis_ids(self, analysis_id):

        if not re.match('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', analysis_id):
            raise TypeError('Provided analysis identifier of incorrect type')

        response = self._session.get('https://analyze.intezer.com/api/v2-0/analyses/' + analysis_id + '/sub-analyses')
        if response.status_code != 200:
            raise RuntimeError(self._get_failure_codes(response.status_code))
        return response.json()

    def _get_sub_analysis_code_reuse(self, analysis_id, sub_analysis_id):

        if not re.match('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', analysis_id):
            raise TypeError('Provided analysis identifier of incorrect type')

        if not sub_analysis_id == 'root' and not re.match('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', sub_analysis_id):
            raise TypeError('Provided sub analysis identifier of incorrect type')

        response = self._session.get('https://analyze.intezer.com/api/v2-0/analyses/' + analysis_id + '/sub-analyses/' + sub_analysis_id + '/code-reuse')
        if response.status_code != 200:
            raise RuntimeError(self._get_failure_codes(response.status_code))
        return response.json()

    def _get_sub_analysis_metadata(self, analysis_id, sub_analysis_id):

        if not re.match('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', analysis_id):
            raise TypeError('Provided analysis identifier of incorrect type')

        if not sub_analysis_id == 'root' and not re.match('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', sub_analysis_id):
            raise TypeError('Provided sub analysis identifier of incorrect type')

        response = self._session.get('https://analyze.intezer.com/api/v2-0/analyses/' + analysis_id + '/sub-analyses/' + sub_analysis_id + '/metadata')
        if response.status_code != 200:
            raise RuntimeError(self._get_failure_codes(response.status_code))
        return response.json()

    def _get_sub_analysis_shared_code_family_files(self, analysis_id, sub_analysis_id, family_id):

        if not re.match('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', analysis_id):
            raise TypeError('Provided analysis identifier of incorrect type')

        if not re.match('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', sub_analysis_id):
            raise TypeError('Provided sub analysis identifier of incorrect type')

        if not re.match('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', family_id):
            raise TypeError('Provided family identifier of incorrect type')

        response = self._session.post('https://analyze.intezer.com/api/v2-0/analyses/' + analysis_id + '/sub-analyses/' + sub_analysis_id + '/code-reuse/families/'+ family_id + '/find-related-files')
        if response.status_code != 201:
            raise RuntimeError(self._get_failure_codes(response.status_code))
        return response.json()

    def _submit_sub_analysis_account_related_samples(self, analysis_id, sub_analysis_id):

        if not re.match('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', analysis_id):
            raise TypeError('Provided analysis identifier of incorrect type')

        if not sub_analysis_id == 'root' and not re.match('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', sub_analysis_id):
            raise TypeError('Provided sub analysis identifier of incorrect type')

        response = self._session.post('https://analyze.intezer.com/api/v2-0/analyses/' + analysis_id + '/sub-analyses/' + sub_analysis_id + '/get-account-related-samples')
        if response.status_code != 201:
            raise RuntimeError(self._get_failure_codes(response.status_code))
        return response.json()

    def _submit_sub_analysis_vaccine(self, analysis_id, sub_analysis_id, format = 'yara'):

        if not re.match('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', analysis_id):
            raise TypeError('Provided analysis identifier of incorrect type')

        if not sub_analysis_id == 'root' and not re.match('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', sub_analysis_id):
            raise TypeError('Provided sub analysis identifier of incorrect type')

        if format not in ['yara', 'open_ioc', 'stix', 'stix2']:
            raise TypeError('Provided vaccine format not supported')

        response = self._session.post('https://analyze.intezer.com/api/v2-0/analyses/' + analysis_id + '/sub-analyses/' + sub_analysis_id + '/generate-vaccine', json={'format': format})
        if response.status_code != 201:
            raise RuntimeError(self._get_failure_codes(response.status_code))
        return response.json()

    def private_index_add_by_sha256(self, file_hash, index_as = 'trusted', family_name = None):

        file_hash = file_hash.lower()
        if not re.match('^[0-9a-f]{64}$', file_hash):
            raise TypeError('Provided hash should be SHA256')

        if index_as not in ['malicious', 'trusted']:
            raise TypeError('Provided index should be either "trusted" or "malicious"')

        if index_as == 'malicious' and not family_name:
            raise TypeError('Family name must be specified when clasifying as malicious')
        elif index_as == 'trusted' and family_name:
            raise TypeError('Family name cannot be specified when indexing as trusted')

        response = self._session.post('https://analyze.intezer.com/api/v2-0/files/' + file_hash + '/index', json = {'index_as': index_as, 'family_name': family_name})
        if response.status_code != 201:
            raise RuntimeError(self._get_failure_codes(response.status_code))

    def private_index_add_by_path(self, file_path, index_as = 'trusted', family_name = None):

        with open(file_path, 'rb') as inpf:
            data = inpf.read()

        file_name = os.path.split(file_path)[1]
        self.private_index_add_by_stream(file_name, data, index_as, family_name)

    def private_index_add_by_stream(self, file_name, data, index_as = 'trusted', family_name = None):

        if index_as not in ['malicious', 'trusted']:
            raise TypeError('Provided index should be either "trusted" or "malicious"')

        if index_as == 'malicious' and not family_name:
            raise TypeError('Family name must be specified when clasifying as malicious')
        elif index_as == 'trusted' and family_name:
            raise TypeError('Family name cannot be specified when indexing as trusted')

        with open(file_name, 'rb') as inpf:
            data = inpf.read()

        files = {'file': (file_name, data)}

        response = self._session.post('https://analyze.intezer.com/api/v2-0/files/index', files = files, json = {'index_as': index_as, 'family_name': family_name})
        if response.status_code != 201:
            raise RuntimeError(self._get_failure_codes(response.status_code))

    def private_index_remove_by_sha256(self, file_hash):

        file_hash = file_hash.lower()
        if not re.match('^[0-9a-f]{64}$', file_hash):
            raise TypeError('Provided hash should be SHA256')

        response = self._session.delete('https://analyze.intezer.com/api/v2-0/files/' + file_hash + '/index')
        if response.status_code != 201:
            raise RuntimeError(self._get_failure_codes(response.status_code))

    def private_set_label_by_sha256(self, file_hash, label):

        file_hash = file_hash.lower()
        if not re.match('^[0-9a-f]{64}$', file_hash):
            raise TypeError('Provided hash should be SHA256')

        if len(label) > 16:
            raise ValueError('Maximum label length is 16 characters')

        response = self._session.put('https://analyze.intezer.com/api/v2-0/files/' + file_hash + '/label', json = {'label': label})
        if response.status_code != 201:
            raise RuntimeError(self._get_failure_codes(response.status_code))

    def get_file_by_sha256(self, file_hash):

        file_hash = file_hash.lower()
        if not re.match('^[0-9a-f]{64}$', file_hash):
            raise TypeError('Provided hash should be SHA256')

        response = self._session.get('https://analyze.intezer.com/api/v2-0/files/' + file_hash + '/download')
        if response.status_code != 201:
            raise RuntimeError(self._get_failure_codes(response.status_code))
        return response.content

    def private_del_file_by_sha256(self, file_hash):

        if not re.match('^[0-9a-f]{64}$', file_hash):
            raise TypeError('Provided hash should be SHA256')

        response = self._session.delete('https://analyze.intezer.com/api/v2-0/files/' + file_hash)
        if response.status_code != 201:
            raise RuntimeError(self._get_failure_codes(response.status_code))

    def get_endpoint_analysis(self, analysis_id):

        if not re.match('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', analysis_id):
            raise TypeError('Provided analysis identifier of incorrect type')

        response = self._session.get('https://analyze.intezer.com/api/v2-0/endpoint-analyses/' + analysis_id)
        if response.status_code != 200:
            raise RuntimeError(self._get_failure_codes(response.status_code))
        return response.json()

    def get_endpoint_sub_analysis(self, analysis_id, verdicts = ['malicious', 'suspicious']):

        if not re.match('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', analysis_id):
            raise TypeError('Provided analysis identifier of incorrect type')

        valid_verdicts = ['trusted', 'malicious', 'suspicious', 'neutral', 'unknown', 'not_supported']
        invalid_verdicts = [ x for x in verdicts if x not in valid_verdicts]
        if invalid_verdicts:
            raise ValueError('Invalid verdict specified')

        response = self._session.get('https://analyze.intezer.com/api/v2-0/endpoint-analyses/' + analysis_id + '/sub-analyses', json = {'verdicts': verdicts})
        if response.status_code != 200:
            raise RuntimeError(self._get_failure_codes(response.status_code))
        return response.json()

class IntezerAnalysis:

    def __init__(self, intz, resp, sub_analysis_id = 'root', poll = True):
        self._sub_analysis_id = sub_analysis_id
        self._intz = intz
        self._poll = poll
        self._vaccine = None
        self._analysis = None
        self._thread_vaccine = None
        self._sub_analysis_ids = None
        self._metadata = None
        self._code_reuse = None

        self._analysis_id = resp['result_url'].split(sep='/')[-1]

        if 'result' in resp:
            self._analysis = resp
        else:
            self._thread_resp = threading.Thread(target=self._poll_analysis, daemon=True)
            self._thread_resp.start()

    def _poll_result_url(self, url):
        while True:
            try:
                response = self._intz._session.get('https://analyze.intezer.com/api/v2-0' + url)
                response_json = response.json()
                if response.status_code != 200:
                    raise RuntimeError(self._intz._get_failure_codes(response.status_code))
            except RuntimeError as e:
                if str(e) != 'Request in progress':
                    raise e
            if 'result' in response_json:
                return response_json
            time.sleep(1)

    def _poll_analysis_done(self):
        if not self._analysis and not self._poll:
            return False
        elif not self._analysis:
            while not self._analysis:
                time.sleep(1)
        return True

    '''
    {'result': {'analysis_id': '7514b2cf-8e4a-43ee-8898-c23a2b43724b',
                'analysis_time': 'Mon, 28 Jan 2019 12:33:11 GMT',
                'analysis_url': 'https://analyze.intezer.com/#/analyses/7514b2cf-8e4a-43ee-8898-c23a2b43724b',
                'family_name': 'Remote Admin',
                'is_private': True,
                'sha256': 'fb603599b06b39093d8c4a147e266310dce2a1b2e3d076712b5d8a0b3ea5426d',
                'sub_verdict': 'known_malicious',
                'verdict': 'malicious'},
     'result_url': '/analyses/7514b2cf-8e4a-43ee-8898-c23a2b43724b',
     'status': 'succeeded'}
    '''

    def analysis(self):
        while True:
            if self._analysis:
                return self._analysis
            if self._analysis == False:
                raise RuntimeError('Failed to get analysis')
            if self._poll:
                time.sleep(1)
            else:
                return False

    def _poll_analysis(self):
        while True:
            try:
                resp = self._intz._get_analysis_summary_by_id(self._analysis_id)
            except RuntimeError as e:
                if str(e) != 'Request in progress':
                    self._analysis = False
                    return
                time.sleep(1)
                continue
            self._analysis = resp
            break

    '''
    {'result': 'rule '
               'Intezer_Vaccine_d0b69c7762b87fa8b3a387a1d47a0d1f8bbc8ebea513380f701369ec2bee20dd\n'
               '{\n'
               '\tmeta:\n'
               '\t\tcopyright = "Intezer Labs"\n'
               '\t\tdescription = "Automatic YARA vaccination rule created based '
               'on the file\'s genes"\n'
               '\t\tauthor = "Intezer Labs"\n'
               '\t\treference = "https://analyze.intezer.com"\n'
               '\t\tdate = "2019-05-02"\n'
               '\t\tsha256 = '
               '"d0b69c7762b87fa8b3a387a1d47a0d1f8bbc8ebea513380f701369ec2bee20dd"\n'
               '\tstrings:\n'
               '\t\t$4642928_18 = { 8B ?? ?? E8 ?? ?? ?? ?? 5? 5? 8B ?? 99 3B ?? '
               '?? ?? 75 }\n'
               '\t\t$4555153_16 = { 8B ?? ?? 8B ?? ?? 99 F7 ?? ?? ?? ?? ?? 85 ?? '
               '7E }\n'
               '\t\t$4554788_15 = { 83 ?? ?? ?? 0F 95 ?? 34 ?? 88 ?? ?? 84 ?? 74 '
               '}\n'
               '\t\t$4555602_14 = { 8B ?? ?? 8B ?? ?? 8B ?? ?? 4? 85 ?? 0F 8C }\n'
               '\n'
               '\tcondition:\n'
               '\t\t3 of them\n'
               '}',
     'result_url': '/analyses/09715196-602e-44d8-b87f-30240f368694/sub-analyses/3d4835ee-8d4e-4091-98eb-e8a98cdef363/vaccines/yara',
     'status': 'succeeded'}
    '''

    def vaccine(self, format = 'yara'):
        print('Fetching vaccine with: ' + self._analysis_id + ' - ' + self._sub_analysis_id)
        if format not in ['open_ioc', 'stix', 'stix2', 'yara']:
            raise ValueError('Invalid vaccine format specified')
        if not self._thread_vaccine:
            self._thread_vaccine = threading.Thread(target=self._poll_vaccine, daemon=True, args=([format]))
            self._thread_vaccine.start()
        while True:
            if self._vaccine:
                return self._vaccine
            if self._vaccine == False:
                raise RuntimeError('Failed to get vaccine')
            if self._poll:
                time.sleep(1)
            else:
                return False

    def _poll_vaccine(self, format):
        self._poll_analysis_done()
        try:
            resp = self._intz._submit_sub_analysis_vaccine(self._analysis_id, self._sub_analysis_id, format = format)
            self._vaccine = self._poll_result_url(resp['result_url'])
        except RuntimeError as e:
            print(str(e))
            self._vaccine = False
            return

    def _get_sub_analysis_ids(self):
        if self._sub_analysis_id != 'root':
            raise RuntimeError('Sub analysis only available for root object')
        if not self._poll_analysis_done():
            raise RuntimeError('Analysis pending')
        if not self._sub_analysis_ids:
            self._sub_analysis_ids = self._intz._get_sub_analysis_ids(self._analysis_id)
        return self._sub_analysis_ids

    def __iter__(self):
        self._get_sub_analysis_ids()
        self._sub_data = self._sub_analysis_ids['sub_analyses']
        self._sub_index = 0
        return self

    def __next__(self):
        try:
            resp = IntezerAnalysis(self._intz, self._analysis, self._sub_data[self._sub_index]['sub_analysis_id'])
            self._sub_index += 1
        except IndexError:
            raise StopIteration
        return resp

    '''
    {'compilation_timestamp': '2009:07:13 23:16:05+00:00',
     'md5': '1f9a794497e9255241379ae3c3ee3838',
     'sha1': '2c0a2b9f6608ba8b5c08fde5cd1ef6f5e24e7349',
     'sha256': '1920ed79d706de5d5c2b888bf59efae8ae76e85737560344bbe785bfd238c838',
     'size_in_bytes': 53248,
     'ssdeep': '384:53TXpgCLuMM0Ift7d53AAjljtejPYJ7GCjCquOYnw1Mc3pVsnR73Z81i2l+REWX3:5qMSvAAjljtejP27GCjCq/Aw7plv'}
    '''

    def metadata(self):
        if not self._poll_analysis_done():
            return False
        if not self._metadata:
            self._metadata = self._intz._get_sub_analysis_metadata(self._analysis_id, self._sub_analysis_id)
        return self._metadata

    '''
    {'common_gene_count': 157,
     'families': [{'family_id': 'cfd82ebe-c3a3-43d8-bf5d-0d9771dce7bd',
                   'family_name': 'Nanocore',
                   'family_type': 'malware',
                   'reused_gene_count': 800},
                  {'family_id': '069eb656-1977-43e6-8ef3-60b8fbb2d163',
                   'family_name': 'Torwofun',
                   'family_type': 'malware',
                   'reused_gene_count': 8},
                  {'family_id': '78fe0549-168f-448a-b775-951759891309',
                   'family_name': 'SNIPR',
                   'family_type': 'malware',
                   'reused_gene_count': 2},
                  {'family_id': 'a1f3e1f6-88f4-44f0-9efa-991b80f5f2d4',
                   'family_name': 'Aspose Pty Ltd',
                   'family_type': 'library',
                   'reused_gene_count': 21}],
     'gene_count': 841,
     'gene_type': 'dotnet_cil',
     'unique_gene_count': 0}
    '''

    def code_reuse(self):
        print('Fetching code re-use with: ' + self._analysis_id + ' - ' + self._sub_analysis_id)
        if not self._poll_analysis_done():
            return False
        if not self._code_reuse:
            self._code_reuse = self._intz._get_sub_analysis_code_reuse(self._analysis_id, self._sub_analysis_id)
        return self._code_reuse

    '''
    {'result': {'files': [{'original_filename': 'Setup.exe',
                           'reused_gene_count': 12,
                           'sha256': 'dc9b7199657fe5efef7a3050ab94e30f05145fd56703f042d0abcf78a5008eda',
                           'size_in_bytes': 21666304}]},
     'result_url': '/analyses/09715196-602e-44d8-b87f-30240f368694/sub-analyses/3d4835ee-8d4e-4091-98eb-e8a98cdef363/code-reuse/families/34789427-06b4-4858-99e1-928005ed1362/related-files',
     'status': 'succeeded'}
    '''

    def related_family_files(self, family_id):
        if not self._poll_analysis_done():
            return False
        resp = self._intz._get_sub_analysis_shared_code_family_files(self._analysis_id, self._sub_analysis_id, family_id)
        return self._poll_result_url(resp['result_url'])

    '''
    {'result': {'related_samples': [{'analysis': {'analysis_id': '1eb16b0f-7a30-4d31-9ee6-e54b4f3edf67',
                                                  'analysis_time': 'Wed, 24 Apr '
                                                                   '2019 08:52:55 '
                                                                   'GMT',
                                                  'analysis_type': 'file',
                                                  'analysis_url': 'https://analyze.intezer.com/#/analyses/1eb16b0f-7a30-4d31-9ee6-e54b4f3edf67/sub/9e01c8ed-b9e4-472b-90d9-1f63e34d31dc',
                                                  'sha256': '7284608f9cbc8bf51cefde58f20d5127c3334f0947db3fdb6b702346e59f6cd4',
                                                  'sub_analysis_id': '9e01c8ed-b9e4-472b-90d9-1f63e34d31dc',
                                                  'sub_verdict': 'known_malicious',
                                                  'verdict': 'malicious'},
                                     'reused_genes': {'gene_count': 40}},
                                     ...
                                    {'analysis': {'analysis_id': 'c4f43796-2a03-4e3d-adb4-d49ce0009e72',
                                                  'analysis_time': 'Tue, 12 Mar '
                                                                   '2019 04:54:43 '
                                                                   'GMT',
                                                  'analysis_type': 'endpoint',
                                                  'analysis_url': 'https://analyze.intezer.com/#/analyses/c4f43796-2a03-4e3d-adb4-d49ce0009e72/sub/717f7a09-1c3d-4561-8df8-941754342efe',
                                                  'sha256': 'fd217809f5e34218741a33e73168dfb9f63e83e86c1601e4ae64c53a6ab8eadc',
                                                  'sub_analysis_id': '717f7a09-1c3d-4561-8df8-941754342efe',
                                                  'sub_verdict': 'known_trusted',
                                                  'verdict': 'trusted'},
                                     'reused_genes': {'gene_count': 1}}]},
     'result_url': '/analyses/09715196-602e-44d8-b87f-30240f368694/sub-analyses/2f8ff35a-6994-417a-962a-6542b0633129/get-account-related-samples',
     'status': 'succeeded'}
    '''

    def account_related_samples(self):
        if not self._poll_analysis_done():
            return False
        resp = self._intz._submit_sub_analysis_account_related_samples(self._analysis_id, self._sub_analysis_id)
        return self._poll_result_url(resp['result_url'])

if __name__ == '__main__':
    intz = Intezer('xxx')
    resp = intz.analyze_file_by_path('test.exe')

    for x in resp:
        pprint(x.metadata())
        pprint(x.account_related_samples())
        try:
            cr = x.code_reuse()
            pprint(cr)
        except RuntimeError as e:
            if str(e) == 'Resource conflict':
                print('No code for sub-analysis, skipping vaccine generation')
                continue
        for y in cr['families']:
            rf = x.related_family_files(y['family_id'])
            pprint(rf)
        pprint(x.vaccine())
