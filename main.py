import sys
import base64
from datetime import datetime, timezone
from asn1crypto import cms, core
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

ATTR_MAP = {
    0:  'Receipt Type',
    1:  'Product ID',
    2:  'Bundle Identifier',
    3:  'Application Version',
    4:  'Opaque Value',
    5:  'SHA-1 Hash',
    8:  'Purchase Date',
    10: 'Parental Content Rating',
    12: 'Receipt Creation Date',
    16: 'App Store Installer Version ID',
    17: 'In-App Purchase Receipt',
    19: 'Original Application Version',
    21: 'Expiration Date',
}

def load_receipt(path: str) -> bytes:
    data = open(path, 'rb').read()
    if data.startswith(b'-----BEGIN'):
        lines = data.splitlines()[1:-1]
        data = base64.b64decode(b"".join(lines))
    return data


def parse_attributes(raw: bytes) -> dict:
    result = {}
    attr_set = core.SetOf.load(raw)
    for attr in attr_set:
        attr_type = attr[0].native
        key = ATTR_MAP.get(attr_type, f'type_{attr_type}')
        raw_value = attr[2].native
        if attr_type == 17:
            result[key] = raw_value
            continue
        try:
            val_obj = core.Asn1Value.load(raw_value)
            val = val_obj.native
            if isinstance(val_obj, core.GeneralizedTime):
                val = val.replace(tzinfo=timezone.utc)
        except Exception:
            val = raw_value
        result[key] = val
    return result


def extract_in_app(raw: bytes) -> list:
    purchases = []
    outer = core.SetOf.load(raw)
    for item in outer:
        attrs = parse_attributes(item.contents)
        purchases.append(attrs)
    return purchases


def verify_signature(signed_data: cms.SignedData) -> bool:
    cert = signed_data['certificates'][0].chosen
    pubkey = cert.public_key
    signer_info = signed_data['signer_infos'][0]
    sig = signer_info['signature'].native
    signed_attrs = signer_info['signed_attrs'].dump()
    algo = signer_info['digest_algorithm']['algorithm'].native
    if algo != 'sha1':
        raise NotImplementedError(f"Unknown hashing algorithm: {algo}")
    pubkey.verify(
        sig,
        signed_attrs,
        padding.PKCS1v15(),
        hashes.SHA1()
    )
    return True


def main(path: str):
    receipt_data = load_receipt(path)
    content_info = cms.ContentInfo.load(receipt_data)
    if content_info['content_type'].native != 'signed_data':
        print('Erorr: container not SignedData')
        sys.exit(1)

    signed_data = content_info['content']

    payload = signed_data['encap_content_info']['content'].native
    info = parse_attributes(payload)

    print('=== General ===')
    for k, v in info.items():
        if k != 'in_app':
            print(f"{k}: {v}")

    in_app_bytes = info.get('in_app')
    if in_app_bytes:
        print('\n=== In-App Purchases ===')
        for idx, purch in enumerate(extract_in_app(in_app_bytes), start=1):
            print(f"\n--- Purchase #{idx} ---")
            for k, v in purch.items():
                print(f"{k}: {v}")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} path/to/receipt")
        sys.exit(0)
    main(sys.argv[1])
