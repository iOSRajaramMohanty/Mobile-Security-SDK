import Foundation

enum CanonicalPayload {
    static func build(
        method: String,
        host: String,
        contentType: String,
        riskScore: Int,
        keyId: String,
        path: String,
        timestampMs: Int64,
        nonce: Data,
        payloadIv: Data,
        payloadCt: Data,
        payloadTag: Data,
        wrapIv: Data,
        wrapCt: Data,
        wrapTag: Data,
        ephemeralPublicSpki: Data,
    ) -> Data {
        let methodB = Data(method.utf8)
        let hostB = Data(host.utf8)
        let contentTypeB = Data(contentType.utf8)
        let keyIdB = Data(keyId.utf8)
        let pathB = Data(path.utf8)
        let pay = payloadIv + payloadCt + payloadTag
        let wrap = wrapIv + wrapCt + wrapTag
        var out = Data()
        appendPrefixed(&out, methodB)
        appendPrefixed(&out, hostB)
        appendPrefixed(&out, contentTypeB)
        out.append(u32BE(UInt32(max(0, min(100, riskScore)))))
        appendPrefixed(&out, keyIdB)
        appendPrefixed(&out, pathB)
        out.append(int64BE(timestampMs))
        appendPrefixed(&out, nonce)
        appendPrefixed(&out, pay)
        appendPrefixed(&out, wrap)
        appendPrefixed(&out, ephemeralPublicSpki)
        return out
    }

    private static func appendPrefixed(_ buf: inout Data, _ chunk: Data) {
        buf.append(u32BE(UInt32(chunk.count)))
        buf.append(chunk)
    }

    private static func u32BE(_ v: UInt32) -> Data {
        var be = v.bigEndian
        return Swift.withUnsafeBytes(of: &be) { Data($0) }
    }

    private static func int64BE(_ v: Int64) -> Data {
        var be = v.bigEndian
        return Swift.withUnsafeBytes(of: &be) { Data($0) }
    }
}
