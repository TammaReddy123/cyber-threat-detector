from main import detect_country_from_url, extract_country

test_urls = [
    'https://facebook.com/us',
    'https://amazon.co.uk',
    'https://google.co.in',
    'https://example.com/us/path',
    'https://randomsite.com'
]

print("Testing Country Detection:")
print("=" * 50)

for url in test_urls:
    tld_country = extract_country(url)
    ai_country = detect_country_from_url(url)
    final_country = ai_country if ai_country != 'Unknown' else tld_country

    print(f'URL: {url}')
    print(f'  TLD Detection: {tld_country}')
    print(f'  AI Detection: {ai_country}')
    print(f'  Final Country: {final_country}')
    print()
