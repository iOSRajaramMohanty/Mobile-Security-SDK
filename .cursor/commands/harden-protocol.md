Enhance envelope validation.

Backend must validate:
- version (v)
- algorithm

Reject if:
- unknown version
- unsupported algorithm

Enhance canonical payload:
- include HTTP method
- include host
- include content-type

Optional:
- Add AES-GCM AAD