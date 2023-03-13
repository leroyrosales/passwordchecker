import requests
import hashlib
import sys


def request_api_data(query):
    url = 'https://api.pwnedpasswords.com/range/' + query
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {res.status_code}, try again')
    return res


def get_pw_leak_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return


def pwned_api_check(password):
    hash_pw = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    firstfive_char, tail = hash_pw[:5], hash_pw[5:]
    res = request_api_data(firstfive_char)
    return get_pw_leak_count(res, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f'The password \'{password}\' was found {count} times. It would be good to change it.')
        else:
            print(
                f'The password \'{password}\' was not found, so it\'s more than likely secure!')
    return 'Done checking passwords.'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
