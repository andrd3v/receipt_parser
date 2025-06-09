# 🍏 iOS App Store Receipt Parser

A lightweight Python tool for parsing **iOS App Store receipts**, including detailed information about **in-app purchases**. Useful for reverse engineering, security research, or understanding how Apple receipts work under the hood.

---

## ✨ Features

- ✅ Parses `PKCS7`-encoded (CMS) App Store receipts  
- ✅ Extracts key metadata (bundle ID, app version, creation date, etc.)  
- ✅ Displays detailed **in-app purchase** records
- 
---

## 🧰 Requirements

- Python 3.8+
- [asn1crypto](https://pypi.org/project/asn1crypto/)
- [cryptography](https://pypi.org/project/cryptography/)

Install dependencies:

```bash
pip install -r requirements.txt
```

## USAGE

```bash
python3 main.py path/to/receipt
```

> 🧠 **Notes**
>
> - This is a **read-only** parser – it does **not** attempt to forge or modify receipts.  
> - The project is intended for **educational and research purposes only**.  
> - Receipt attributes are decoded using Apple’s known attribute type codes.  
>   Unrecognized types are shown as `type_<number>`.


## 📄 License

This project is licensed under the **MIT License**.  
See the [`LICENSE`](./LICENSE) file for details.
