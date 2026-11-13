"""Select an exact test executable from Cargo JSON messages."""
import json
import sys


def executable(lines, target='performance_baseline'):
    paths = [message['executable'] for message in map(json.loads, lines)
             if message.get('reason') == 'compiler-artifact'
             and message.get('target', {}).get('name') == target
             and message.get('profile', {}).get('test') is True
             and message.get('executable')]
    if len(paths) != 1:
        raise ValueError('Expected exactly one matching test executable')
    return paths[0]


if __name__ == '__main__':
    print(executable(sys.stdin, sys.argv[1] if len(sys.argv) > 1 else 'performance_baseline'))
