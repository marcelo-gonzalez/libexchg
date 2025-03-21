import argparse
import requests
import sys

def download_info(url, path):
    print(f'downloading from {url} to {path}', file=sys.stderr)
    r = requests.get(url, stream=True)
    if r.status_code != 200:
        try:
            content = r.content.decode('utf-8')
        except UnicodeDecodeError as e:
            content = str(r.content)
        print(f'got code {r.status_code} from {url}:\n{content}', file=sys.stderr)
        return 1
    with open(path, 'wb') as f:
        for chunk in r.iter_content(chunk_size=8192):
            f.write(chunk)

def download_bitstamp_info(path):
    download_info('https://www.bitstamp.net/api/v2/trading-pairs-info/', path)

def download_coinbase_info(path):
    download_info('https://api.coinbase.com/api/v3/brokerage/market/products', path)

def download_kraken_info(path):
    download_info('https://api.kraken.com/0/public/AssetPairs', path)

def main():
    parser = argparse.ArgumentParser(description='Download pair info files for use in test code')
    parser.add_argument('--bitstamp-path', type=str, help='Path to which bitstamp pair info will be saved')
    parser.add_argument('--coinbase-path', type=str, help='Path to which coinbase pair info will be saved')
    parser.add_argument('--kraken-path', type=str, help='Path to which kraken pair info will be saved')

    args = parser.parse_args()
    if args.bitstamp_path is None and args.coinbase_path is None and args.kraken_path is None:
        print('Nothing to do. Please give at least one of --bitstamp-path, --coinbase-path or --kraken-path')
        return

    ret = 0
    if args.bitstamp_path:
        download_bitstamp_info(args.bitstamp_path)
    if args.coinbase_path:
        download_coinbase_info(args.coinbase_path)
    if args.kraken_path:
        download_kraken_info(args.kraken_path)

    sys.exit(ret)

if __name__ == '__main__':
    main()