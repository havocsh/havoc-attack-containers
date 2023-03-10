import re
import math
import base64
import datetime
import urllib.parse

def local_function(function, attributes=[]):
    encoding_functions = ['base64decode', 'base64encode', 'urlencode']
    native_functions = {'abs': abs, 'int': int, 'len': len, 'max': max, 'min': min, 'pow': pow}
    math_functions = {'ceil': math.ceil, 'floor': math.floor, 'log': math.log}
    string_functions = [
        'endswith',
        'format',
        'join',
        'lower',
        'lstrip',
        'replace',
        'rstrip',
        'split',
        'startswith',
        'strip',
        'title',
        'upper'
    ]
    time_functions = ['timestamp', 'formatdate', 'timeadd', 'timecmp']
    regex_functions = ['regex', 'regexall']

    if function in encoding_functions:
        if function == 'base64decode':
            result = base64.b64decode(attributes[0].encode()).decode()
            return result
        if function == 'base64encode':
            result = base64.b64encode(attributes[0].encode()).decode()
            return result
        if function == 'urlencode':
            result = urllib.parse.quote_plus(**attributes)
            return result

    elif function in native_functions:
        result = native_functions[function](*attributes)
        return result
    
    elif function in math_functions:
        result = math_functions[function](*attributes)
        return result
    
    elif function in string_functions:
        if function == 'endswith':
            result = attributes[0].endswith(attributes[1])
            return result
        if function == 'format':
            result = attributes[0].format(attributes[1])
            return result
        if function == 'join':
            result = attributes[1].join(attributes[0])
            return result
        if function == 'lower':
            result = attributes[0].lower()
            return result
        if function == 'lstrip':
            result = attributes[0].lstrip()
            return result
        if function == 'replace':
            result = attributes[0].replace(attributes[1], attributes[2])
            return result
        if function == 'rstrip':
            result = attributes[0].rstrip()
            return result
        if function == 'split':
            result = attributes[0].split(attributes[1])
            return result
        if function == 'startswith':
            result = attributes[0].startswith(attributes[1])
            return result
        if function == 'strip':
            result = attributes[0].strip()
            return result
        if function == 'title':
            result = attributes[0].title()
            return result
        if function == 'upper':
            result = attributes[0].upper()
            return result
    
    elif function in time_functions:
        if function == 'timestamp':
            if attributes:
                time_stamp = datetime.datetime.strptime(attributes[0], '%Y-%m-%dT%H:%M:%S-%Z')
                time_stamp = time_stamp.replace(tzinfo=datetime.timezone.utc)
            else:
                time_stamp = datetime.datetime.now(tz=datetime.timezone.utc)
            result = time_stamp.strftime('%Y-%m-%dT%H:%M:%S-%Z')
            return result
        if function == 'formatdate':
            time_stamp = datetime.datetime.strptime(attributes[1], '%Y-%m-%dT%H:%M:%S-%Z')
            time_stamp = time_stamp.replace(tzinfo=datetime.timezone.utc)
            result = time_stamp.strftime(attributes[0])
            return result
        if function == 'timeadd':
            duration = attributes[1]
            time_stamp = datetime.datetime.strptime(attributes[0], '%Y-%m-%dT%H:%M:%S-%Z')
            time_stamp = time_stamp.replace(tzinfo=datetime.timezone.utc)
            time_add = time_stamp + datetime.timedelta(**duration)
            result = time_add.strftime('%Y-%m-%dT%H:%M:%S-%Z')
            return result
        if function == 'timecmp':
            date1 = datetime.datetime.strptime(attributes[0], '%Y-%m-%dT%H:%M:%S-%Z')
            date2 = datetime.datetime.strptime(attributes[1], '%Y-%m-%dT%H:%M:%S-%Z')
            if date1 == date2:
                return 0
            if date1 < date2:
                return -1
            if date1 > date2:
                return 1

    elif function in regex_functions:
        if function == 'regex':
            regex = re.compile(attributes[0])
            result = re.search(regex, attributes[1])
            return ','.join(result.groups())
        if function == 'regexall':
            regex = re.compile(attributes[0])
            result = re.findall(regex, attributes[1])
            return ','.join(result)
    
    else:
        return 'function_not_supported'


def action_function(havoc_client, function, attributes={}):
    if function == 'wait_for_c2':
        task_name = attributes['task_name']
        wait_for_c2_response = havoc_client.wait_for_c2(task_name)
        if not wait_for_c2_response:
            return 'wait_for_c2_function_failed'
        return wait_for_c2_response
