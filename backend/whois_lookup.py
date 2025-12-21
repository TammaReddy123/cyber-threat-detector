import whois
import socket

def get_domain_info(url):
    try:
        data = whois.whois(url)
        age = None

        if data.creation_date:
            from datetime import datetime
            created = data.creation_date
            if isinstance(created, list):
                created = created[0]
            age = (datetime.now() - created).days

        return {
            "domain": data.domain_name,
            "registrar": data.registrar,
            "age_days": age
        }
    except:
        return {"domain": None, "registrar": None, "age_days": None}


def get_asn_info(url):
    try:
        ip = socket.gethostbyname(url.replace("http://", "").replace("https://","").split("/")[0])
        return {"ip": ip}
    except:
        return {"ip": None}
