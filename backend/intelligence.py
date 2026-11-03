"""
MATSYA Cyber Intelligence Platform
DNS, RDAP, GeoIP, reputation and evidence-driven threat map
"""

import ipaddress
import os
import re
import socket
from pathlib import Path
from urllib.parse import urlparse

import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

# --------------------------------------------------
# OPTIONAL DNS SUPPORT
# --------------------------------------------------

try:
    import dns.resolver

    DNS_AVAILABLE = True

except ImportError:
    dns = None
    DNS_AVAILABLE = False


# --------------------------------------------------
# OPTIONAL MAXMIND GEOIP SUPPORT
# --------------------------------------------------

try:
    import maxminddb

except ImportError:
    maxminddb = None


# --------------------------------------------------
# ROUTER CONFIGURATION
# --------------------------------------------------

router = APIRouter(
    prefix="/api/intel",
    tags=["Threat Intelligence"],
)

TIMEOUT = 8

BASE_DIR = Path(__file__).resolve().parent

GEOIP_DB_PATH = Path(
    os.getenv(
        "GEOIP_DB_PATH",
        str(BASE_DIR / "data" / "GeoLite2-City.mmdb"),
    )
).expanduser()

ABUSEIPDB_API_KEY = os.getenv(
    "ABUSEIPDB_API_KEY",
    "",
).strip()

VIRUSTOTAL_API_KEY = os.getenv(
    "VIRUSTOTAL_API_KEY",
    "",
).strip()

USER_AGENT = "MATSYA-Cyber-Intelligence/1.0"


# ==================================================
# VALIDATION
# ==================================================

def valid_domain(value: str) -> str:
    """
    Normalize and validate a fully qualified domain name.
    """

    value = str(value).strip().rstrip(".").lower()

    if (
        not value
        or len(value) > 253
        or "://" in value
        or "/" in value
        or ":" in value
    ):
        raise ValueError(
            "Enter a valid domain name."
        )

    try:
        ipaddress.ip_address(value)

    except ValueError:
        pass

    else:
        raise ValueError(
            "Expected a domain name, not an IP address."
        )

    try:
        value = value.encode(
            "idna"
        ).decode("ascii")

    except UnicodeError as exc:
        raise ValueError(
            "Invalid internationalized domain."
        ) from exc

    labels = value.split(".")

    label_pattern = re.compile(
        r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
    )

    if (
        len(labels) < 2
        or any(
            not label
            or len(label) > 63
            or not label_pattern.fullmatch(label)
            for label in labels
        )
    ):
        raise ValueError(
            "Invalid fully qualified domain name."
        )

    return value


def public_ip(value: str):
    """
    Return an IP only if globally routable.
    """

    try:
        address = ipaddress.ip_address(
            str(value).strip()
        )

    except ValueError as exc:
        raise ValueError(
            "Invalid IP address."
        ) from exc

    if not address.is_global:
        raise ValueError(
            "Only globally routable public IP addresses "
            "are supported."
        )

    return address


# ==================================================
# HTTP HELPER
# ==================================================

def http_json(
    url: str,
    headers=None,
    params=None,
):
    """
    Safe bounded HTTP GET request.
    """

    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": (
            "application/rdap+json, "
            "application/json"
        ),
        **(headers or {}),
    }

    try:

        response = requests.get(
            url,
            headers=request_headers,
            params=params,
            timeout=TIMEOUT,
        )

        if response.status_code == 404:
            return None, "No record found"

        response.raise_for_status()

        return response.json(), None

    except requests.RequestException as exc:
        return None, f"Request failed: {exc}"

    except ValueError:
        return None, (
            "Provider returned invalid JSON"
        )


# ==================================================
# RDAP LOOKUP
# ==================================================

def rdap_lookup(
    kind: str,
    value: str,
) -> dict:

    if kind not in {"domain", "ip"}:
        return {
            "status": "unavailable",
            "reason": (
                "Unsupported RDAP lookup type."
            ),
        }

    data, error = http_json(
        f"https://rdap.org/{kind}/{value}"
    )

    if not data:
        return {
            "status": "unavailable",
            "reason": (
                error
                or "No RDAP record found"
            ),
        }

    return {
        "status": "available",
        "source": "RDAP",
        "handle": data.get("handle"),
        "name": data.get("name"),
        "status_codes": data.get(
            "status",
            [],
        ),
        "events": [
            {
                "action": event.get(
                    "eventAction"
                ),
                "date": event.get(
                    "eventDate"
                ),
            }
            for event in data.get(
                "events",
                [],
            )
        ],
    }


# ==================================================
# DNS LOOKUP
# ==================================================

def dns_lookup(domain: str) -> dict:

    record_types = [
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
        "CNAME",
    ]

    records = {}
    errors = {}

    if not DNS_AVAILABLE:
        return {
            "status": "unavailable",
            "reason": (
                "Install dnspython "
                "to query DNS records."
            ),
            "records": {},
            "resolved_ips": [],
        }

    for record_type in record_types:

        try:

            answers = dns.resolver.resolve(
                domain,
                record_type,
                lifetime=TIMEOUT,
            )

            if record_type == "MX":

                records[record_type] = [
                    {
                        "priority": item.preference,
                        "host": str(
                            item.exchange
                        ).rstrip("."),
                    }
                    for item in answers
                ]

            elif record_type == "TXT":

                records[record_type] = [
                    b"".join(
                        item.strings
                    ).decode(
                        "utf-8",
                        errors="replace",
                    )
                    for item in answers
                ]

            else:

                records[record_type] = [
                    (
                        str(item).rstrip(".")
                        if record_type in {
                            "NS",
                            "CNAME",
                        }
                        else str(item)
                    )
                    for item in answers
                ]

        except Exception as exc:
            errors[record_type] = str(exc)

    addresses = sorted(
        set(
            records.get("A", [])
            + records.get("AAAA", [])
        )
    )

    return {
        "status": (
            "available"
            if records
            else "unavailable"
        ),
        "records": records,
        "resolved_ips": addresses,
        "errors": errors,
    }


def resolve_domain_ips(
    domain: str,
) -> list:

    result = dns_lookup(domain)

    found = set(
        result.get(
            "resolved_ips",
            [],
        )
    )

    if not found:

        try:

            for item in socket.getaddrinfo(
                domain,
                None,
                type=socket.SOCK_STREAM,
            ):

                try:
                    found.add(
                        str(
                            ipaddress.ip_address(
                                item[4][0]
                            )
                        )
                    )

                except ValueError:
                    pass

        except socket.gaierror:
            pass

    return sorted(found)


# ==================================================
# GEOLOCATION
# ==================================================

def geoip_lookup(address) -> dict:
    """
    Approximate IP infrastructure geolocation.

    Priority:
    1. Local MaxMind GeoLite2 database
    2. Online ipwho.is fallback
    """

    try:
        address = ipaddress.ip_address(
            str(address).strip()
        )

    except ValueError:
        return {
            "status": "unavailable",
            "reason": "Invalid IP address.",
        }

    if not address.is_global:
        return {
            "status": "unavailable",
            "reason": (
                "GeoIP lookup requires "
                "a public IP address."
            ),
        }

    # ----------------------------------------------
    # LOCAL MAXMIND LOOKUP
    # ----------------------------------------------

    if (
        maxminddb is not None
        and GEOIP_DB_PATH.is_file()
    ):

        try:

            with maxminddb.open_database(
                str(GEOIP_DB_PATH)
            ) as reader:

                result = reader.get(
                    str(address)
                )

            if result:

                country = (
                    result.get("country")
                    or {}
                )

                subdivisions = (
                    result.get("subdivisions")
                    or []
                )

                subdivision = (
                    subdivisions[0]
                    if subdivisions
                    else {}
                )

                city = (
                    result.get("city")
                    or {}
                )

                location = (
                    result.get("location")
                    or {}
                )

                latitude = location.get(
                    "latitude"
                )

                longitude = location.get(
                    "longitude"
                )

                if (
                    isinstance(
                        latitude,
                        (int, float),
                    )
                    and isinstance(
                        longitude,
                        (int, float),
                    )
                ):

                    return {
                        "status": "available",
                        "source": (
                            "MaxMind GeoLite2 City"
                        ),

                        "country": (
                            country.get("names")
                            or {}
                        ).get("en"),

                        "country_iso_code": (
                            country.get(
                                "iso_code"
                            )
                        ),

                        "region": (
                            subdivision.get("names")
                            or {}
                        ).get("en"),

                        "city": (
                            city.get("names")
                            or {}
                        ).get("en"),

                        "latitude": latitude,
                        "longitude": longitude,

                        "has_coordinates": True,

                        "accuracy_radius_km": (
                            location.get(
                                "accuracy_radius"
                            )
                        ),

                        "time_zone": (
                            location.get(
                                "time_zone"
                            )
                        ),

                        "note": (
                            "Approximate IP "
                            "infrastructure geolocation."
                        ),
                    }

        except Exception as exc:

            print(
                "Local GeoIP lookup failed:",
                exc,
            )

    # ----------------------------------------------
    # ONLINE GEOIP FALLBACK
    # ----------------------------------------------

    try:

        response = requests.get(
            f"https://ipwho.is/{address}",
            timeout=TIMEOUT,
            headers={
                "User-Agent": USER_AGENT,
            },
        )

        response.raise_for_status()

        data = response.json()

        if data.get("success") is False:

            return {
                "status": "unavailable",
                "reason": (
                    data.get("message")
                    or (
                        "Online GeoIP lookup failed."
                    )
                ),
            }

        latitude = data.get("latitude")
        longitude = data.get("longitude")

        has_coordinates = (
            isinstance(latitude, (int, float))
            and isinstance(
                longitude,
                (int, float),
            )
        )

        return {
            "status": (
                "available"
                if has_coordinates
                else "unavailable"
            ),

            "source": (
                "Online GeoIP Fallback"
            ),

            "country": data.get(
                "country"
            ),

            "country_iso_code": data.get(
                "country_code"
            ),

            "region": data.get(
                "region"
            ),

            "city": data.get(
                "city"
            ),

            "latitude": latitude,

            "longitude": longitude,

            "has_coordinates": (
                has_coordinates
            ),

            "accuracy_radius_km": None,

            "time_zone": (
                data.get(
                    "timezone",
                    {},
                )
                or {}
            ).get("id"),

            "isp": (
                data.get(
                    "connection",
                    {},
                )
                or {}
            ).get("isp"),

            "organization": (
                data.get(
                    "connection",
                    {},
                )
                or {}
            ).get("org"),

            "note": (
                "Approximate IP infrastructure "
                "geolocation. This does not identify "
                "an individual's exact location."
            ),
        }

    except requests.RequestException as exc:

        return {
            "status": "unavailable",
            "reason": (
                f"Online GeoIP lookup failed: {exc}"
            ),
        }

    except Exception as exc:

        return {
            "status": "unavailable",
            "reason": (
                f"GeoIP lookup failed: {exc}"
            ),
        }


# ==================================================
# REPUTATION LOOKUPS
# ==================================================

def abuseipdb_lookup(ip_value: str) -> dict:

    if not ABUSEIPDB_API_KEY:

        return {
            "status": "not_configured",
            "reason": (
                "ABUSEIPDB_API_KEY "
                "is not configured."
            ),
        }

    data, error = http_json(
        "https://api.abuseipdb.com/api/v2/check",
        headers={
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        },
        params={
            "ipAddress": ip_value,
            "maxAgeInDays": 90,
        },
    )

    if not data:

        return {
            "status": "unavailable",
            "reason": error,
        }

    return {
        "status": "available",
        "source": "AbuseIPDB",
        "data": data.get("data", {}),
    }


# ==================================================
# REQUEST MODELS
# ==================================================

class IntelLookupRequest(BaseModel):

    ips: list[str] = Field(
        default_factory=list
    )

    domains: list[str] = Field(
        default_factory=list
    )

    urls: list[str] = Field(
        default_factory=list
    )


# ==================================================
# THREAT MAP DATA
# ==================================================

@router.post("/map-data")
def get_map_data(
    request: IntelLookupRequest,
):
    """
    Convert evidence IPs into real approximate
    geolocation markers.
    """

    markers = []
    processed_ips = set()

    # ----------------------------------------------
    # DIRECT IP EVIDENCE
    # ----------------------------------------------

    for value in request.ips:

        try:
            address = public_ip(value)

        except ValueError:
            continue

        ip_value = str(address)

        if ip_value in processed_ips:
            continue

        processed_ips.add(ip_value)

        geo = geoip_lookup(ip_value)

        if (
            geo.get("status") == "available"
            and geo.get("has_coordinates")
        ):

            markers.append(
                {
                    "id": f"ip-{ip_value}",

                    "type": "evidence_ip",

                    "ip": ip_value,

                    "latitude": geo.get(
                        "latitude"
                    ),

                    "longitude": geo.get(
                        "longitude"
                    ),

                    "city": geo.get(
                        "city"
                    ),

                    "region": geo.get(
                        "region"
                    ),

                    "country": geo.get(
                        "country"
                    ),

                    "country_code": geo.get(
                        "country_iso_code"
                    ),

                    "source": geo.get(
                        "source"
                    ),

                    "isp": geo.get(
                        "isp"
                    ),

                    "organization": geo.get(
                        "organization"
                    ),

                    "accuracy_radius_km": geo.get(
                        "accuracy_radius_km"
                    ),

                    "evidence_type": (
                        "Direct IP extracted "
                        "from investigation evidence"
                    ),

                    "confidence": 70,

                    "note": geo.get(
                        "note"
                    ),
                }
            )

    # ----------------------------------------------
    # DOMAIN EVIDENCE
    # ----------------------------------------------

    for domain_value in request.domains:

        try:
            domain = valid_domain(
                domain_value
            )

        except ValueError:
            continue

        resolved_ips = resolve_domain_ips(
            domain
        )

        for ip_value in resolved_ips:

            try:
                address = public_ip(
                    ip_value
                )

            except ValueError:
                continue

            normalized_ip = str(address)

            if (
                normalized_ip
                in processed_ips
            ):
                continue

            processed_ips.add(
                normalized_ip
            )

            geo = geoip_lookup(
                normalized_ip
            )

            if (
                geo.get("status")
                != "available"
                or not geo.get(
                    "has_coordinates"
                )
            ):
                continue

            markers.append(
                {
                    "id": (
                        f"domain-"
                        f"{domain}-"
                        f"{normalized_ip}"
                    ),

                    "type": "domain_resolution",

                    "ip": normalized_ip,

                    "domain": domain,

                    "latitude": geo.get(
                        "latitude"
                    ),

                    "longitude": geo.get(
                        "longitude"
                    ),

                    "city": geo.get(
                        "city"
                    ),

                    "region": geo.get(
                        "region"
                    ),

                    "country": geo.get(
                        "country"
                    ),

                    "country_code": geo.get(
                        "country_iso_code"
                    ),

                    "source": geo.get(
                        "source"
                    ),

                    "isp": geo.get(
                        "isp"
                    ),

                    "organization": geo.get(
                        "organization"
                    ),

                    "evidence_type": (
                        "IP resolved from "
                        "domain evidence"
                    ),

                    "confidence": 55,

                    "note": geo.get(
                        "note"
                    ),
                }
            )

    return {
        "status": "available",

        "marker_count": len(markers),

        "markers": markers,

        "summary": {
            "input_ips": len(
                request.ips
            ),

            "input_domains": len(
                request.domains
            ),

            "mapped_locations": len(
                markers
            ),
        },

        "disclaimer": (
            "Locations are approximate IP "
            "infrastructure geolocation and do not "
            "identify an individual's exact "
            "physical location."
        ),
    }


# ==================================================
# IP INTELLIGENCE
# ==================================================

@router.get("/ip/{ip_value}")
def get_ip_intelligence(
    ip_value: str,
):

    try:
        address = public_ip(ip_value)

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    normalized_ip = str(address)

    return {
        "ip": normalized_ip,

        "geoip": geoip_lookup(
            normalized_ip
        ),

        "rdap": rdap_lookup(
            "ip",
            normalized_ip,
        ),

        "reputation": abuseipdb_lookup(
            normalized_ip
        ),
    }


# ==================================================
# DOMAIN INTELLIGENCE
# ==================================================

@router.get("/domain/{domain}")
def get_domain_intelligence(
    domain: str,
):

    try:
        normalized_domain = valid_domain(
            domain
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    dns_result = dns_lookup(
        normalized_domain
    )

    return {
        "domain": normalized_domain,

        "dns": dns_result,

        "rdap": rdap_lookup(
            "domain",
            normalized_domain,
        ),
    }


# ==================================================
# URL INTELLIGENCE
# ==================================================

@router.get("/url")
def get_url_intelligence(
    value: str,
):

    try:

        parsed = urlparse(value)

        if parsed.scheme not in {
            "http",
            "https",
        } or not parsed.hostname:

            raise ValueError(
                "Enter a valid HTTP/HTTPS URL."
            )

        domain = valid_domain(
            parsed.hostname
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    return {
        "url": value,

        "domain": domain,

        "domain_intelligence": (
            get_domain_intelligence(
                domain
            )
        ),
    }


# ==================================================
# INTELLIGENCE HEALTH
# ==================================================

@router.get("/health")
def intelligence_health():

    return {
        "status": "healthy",

        "geoip": {
            "local_database_available": (
                maxminddb is not None
                and GEOIP_DB_PATH.is_file()
            ),

            "database_path": str(
                GEOIP_DB_PATH
            ),

            "online_fallback": True,
        },

        "dns_available": DNS_AVAILABLE,

        "abuseipdb_configured": bool(
            ABUSEIPDB_API_KEY
        ),

        "virustotal_configured": bool(
            VIRUSTOTAL_API_KEY
        ),
    }