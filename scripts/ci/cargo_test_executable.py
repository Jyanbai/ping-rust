"""Select the exact performance test executable from Cargo JSON messages."""
import json
import sys


def executable(lines):
    paths = [message['executable'] for message in map(json.loads, lines)
             if message.get('reason') == 'compiler-artifact'
             and message.get('target', {}).get('name') == 'performance_baseline'
             and message.get('profile', {}).get('test') is True
             and message.get('executable')]
    if len(paths) != 1:
        raise ValueError('Expected exactly one performance test executable')
    return paths[0]


if __name__ == '__main__':
    print(executable(sys.stdin))
