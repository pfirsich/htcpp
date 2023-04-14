#include "acme.hpp"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <optional>
#include <random>
#include <thread>

#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include <minijson.hpp>

#include "client.hpp"

namespace fs = std::filesystem;
using namespace std::chrono_literals;

// This whole thing is heavily inspired by these projects:
// https://github.com/diafygi/acme-tiny
// https://github.com/jmccl/acme-lw
// https://github.com/ndilieto/uacme/
// Actually I essentially just copied acme-tiny and looked at acme-lw and uacme to find out how to
// replace the invocations to the `openssl` CLI tool with code that uses openssl as a library.

// Also of course I looked at these RFCs:
// https://www.rfc-editor.org/rfc/rfc8555 (ACME)
// https://www.rfc-editor.org/rfc/rfc7515 (JWS)

namespace {
bool isAlpha(char ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
}

bool isDigit(char ch)
{
    return ch >= '0' && ch <= '9';
}

bool isAlphaDigit(char ch)
{
    return isAlpha(ch) || isDigit(ch);
}

bool isValidLabel(std::string_view label)
{
    if (label.empty()) {
        return false;
    }
    if (!isAlpha(label[0])) {
        return false;
    }
    for (const auto ch : label.substr(1)) {
        if (!isAlphaDigit(ch)) {
            return false;
        }
    }
    return true;
}

bool isValidDomainName(std::string_view str)
{
    // https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.1
    size_t cursor = 0;
    while (cursor < str.size()) {
        const auto dot = str.find('.', cursor);
        const auto label = str.substr(cursor, dot - cursor);
        if (!isValidLabel(label)) {
            return false;
        }
        if (dot == std::string_view::npos) {
            break;
        }
        cursor = dot + 1;
    }
    return true;
}

////////////////////////////////////////////////////////////// CRYPTO

template <typename T, typename F>
auto makeUnique(T* ptr, F deleter)
{
    return std::unique_ptr<T, F>(ptr, deleter);
}

std::string encodeBase64(const std::byte* data, size_t size)
{
    if (size == 0) {
        return "";
    }

    auto base64 = BIO_new(BIO_f_base64());
    // Don't insert newlines every 64 characters (like PEM files)
    BIO_set_flags(base64, BIO_FLAGS_BASE64_NO_NL);

    auto out = BIO_new(BIO_s_mem());
    BIO_push(base64, out); // append out after base64

    const auto wRes = BIO_write(base64, data, static_cast<int>(size));
    assert(wRes == static_cast<int>(size));
    const auto fRes = BIO_flush(base64);
    assert(fRes == 1);

    std::string ret(BIO_pending(out), '\0');
    const auto read = BIO_read(out, ret.data(), static_cast<int>(ret.size()));
    assert(read == static_cast<int>(ret.size()));

    BIO_free_all(base64);

    return ret;
}

std::string encodeBase64Url(const std::byte* data, size_t size)
{
    auto base64 = encodeBase64(data, size);

    // first cut off padding
    const auto end = base64.find_last_not_of("=");
    if (end != std::string::npos) {
        base64.resize(end + 1);
    }

    // replace characters that would have to be escaped with corresponding base64url characters
    for (size_t i = 0; i < base64.size(); ++i) {
        if (base64[i] == '+') {
            base64[i] = '-';
        } else if (base64[i] == '/') {
            base64[i] = '_';
        }
    }

    return base64;
}

template <typename Container>
std::string encodeBase64Url(const Container& data)
{
    return encodeBase64Url(reinterpret_cast<const std::byte*>(data.data()), data.size());
}

std::string sha256(const std::byte* data, size_t len)
{
    std::vector<std::byte> hash(EVP_MAX_MD_SIZE);
    unsigned int hashSize = hash.size();
    const auto res = EVP_Digest(
        data, len, reinterpret_cast<unsigned char*>(hash.data()), &hashSize, EVP_sha256(), nullptr);
    assert(res == 1);
    hash.resize(hashSize);
    return encodeBase64Url(hash);
}

std::string sha256(const std::string& str)
{
    return sha256(reinterpret_cast<const std::byte*>(str.data()), str.size());
}

std::string sign(const std::string& input, EVP_PKEY* pkey)
{
    const auto ctx = makeUnique(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey);
    EVP_DigestSignUpdate(ctx.get(), input.data(), input.size());
    size_t sigLen = 0;
    EVP_DigestSignFinal(ctx.get(), nullptr, &sigLen);
    std::string sig(sigLen, '\0');
    EVP_DigestSignFinal(ctx.get(), reinterpret_cast<uint8_t*>(sig.data()), &sigLen);
    return encodeBase64Url(sig);
}

using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

PkeyPtr makePkeyPtr(EVP_PKEY* ptr)
{
    return PkeyPtr(ptr, EVP_PKEY_free);
}

PkeyPtr generatePrivateKey(size_t numBits)
{
    auto ctx = makeUnique(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    if (!ctx) {
        return makePkeyPtr(nullptr);
    }

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        return makePkeyPtr(nullptr);
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), static_cast<int>(numBits)) <= 0) {
        return makePkeyPtr(nullptr);
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0) {
        return makePkeyPtr(nullptr);
    }
    return makePkeyPtr(pkey);
}

bool writePrivateKey(EVP_PKEY* pkey, const std::string& path)
{
    auto file = makeUnique(std::fopen(path.c_str(), "w"), std::fclose);
    if (!file) {
        return false;
    }

    if (!PEM_write_PrivateKey(file.get(), pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        return false;
    }

    return true;
}

PkeyPtr loadPrivateKey(const std::string& path)
{
    auto file = makeUnique(std::fopen(path.c_str(), "r"), std::fclose);
    if (!file) {
        return makePkeyPtr(nullptr);
    }

    auto pkey = PEM_read_PrivateKey(file.get(), nullptr, nullptr, nullptr);
    if (!pkey) {
        return makePkeyPtr(nullptr);
    }

    return makePkeyPtr(pkey);
}

PkeyPtr getPrivateKey(const std::string& path, size_t numBits)
{
    if (fs::exists(path)) {
        auto pkey = loadPrivateKey(path);
        if (!pkey) {
            slog::error("ACME: Could not load account private key from ", path);
            return makePkeyPtr(nullptr);
        }
        return pkey;
    }

    auto pkey = generatePrivateKey(numBits);
    if (!pkey) {
        slog::error("ACME: Could not generate account private key");
        return makePkeyPtr(nullptr);
    }

    if (!writePrivateKey(pkey.get(), path)) {
        slog::error("ACME: Could not write account private key to ", path);
        return makePkeyPtr(nullptr);
    }

    return pkey;
}

struct KeyParameters {
    std::vector<std::byte> modulus;
    std::vector<std::byte> exponent;
};

KeyParameters extractKeyParameters(EVP_PKEY* pkey)
{
    BIGNUM* modulus = nullptr;
    BIGNUM* exponent = nullptr;

    // I think there is no way to have this compile with OpenSSL 3 without deprecation warnings and
    // with OpenSSL 1.1.1. Very lame.
#if OPENSSL_VERSION_NUMBER >= 30303000
    EVP_PKEY_get_bn_param(pkey, "n", &modulus);
    EVP_PKEY_get_bn_param(pkey, "e", &exponent);
#else
    auto rsa = EVP_PKEY_get0_RSA(pkey);
    RSA_get0_key(rsa, &modulus, &exponent, nullptr);
#endif

    KeyParameters params;
    params.modulus.resize(BN_num_bytes(modulus));
    params.exponent.resize(BN_num_bytes(exponent));
    BN_bn2bin(modulus, reinterpret_cast<uint8_t*>(params.modulus.data()));
    BN_bn2bin(exponent, reinterpret_cast<uint8_t*>(params.exponent.data()));

    return params;
}

std::string getSslError()
{
    auto err = ERR_get_error();
    char buf[256];
    std::string errStr = "no error";
    size_t num = 0;
    while (err != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        if (num == 0) {
            errStr = "";
        } else {
            errStr.append(", ");
        }
        errStr.append(buf);
        err = ERR_get_error();
        ++num;
    }
    return errStr;
}

#define CHECK_OR_NULLOPT(cond, ...)                                                                \
    if (!(cond)) {                                                                                 \
        slog::error(__VA_ARGS__);                                                                  \
        return std::nullopt;                                                                       \
    }

std::optional<std::string> generateCertificateSigningRequest(
    const std::string& domain, const std::vector<std::string>& altNames, EVP_PKEY* pkey)
{
    auto req = makeUnique(X509_REQ_new(), X509_REQ_free);
    CHECK_OR_NULLOPT(req, "ACME: X509_REQ_new: " + getSslError());
    auto name = makeUnique(X509_NAME_new(), X509_NAME_free);
    CHECK_OR_NULLOPT(name, "ACME: X509_NAME_new: " + getSslError());
    auto res = X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC,
        reinterpret_cast<const uint8_t*>(domain.data()), static_cast<int>(domain.size()), -1, 0);
    CHECK_OR_NULLOPT(res, "ACME: X509_NAME_add_entry_by_txt: " + getSslError());
    res = X509_REQ_set_subject_name(req.get(), name.get());

    std::string san;
    for (const auto& name : altNames) {
        if (!san.empty()) {
            san += ",";
        }
        san += "DNS:" + name;
    }

    if (!san.empty()) {
        using Exts = STACK_OF(X509_EXTENSION);
        auto extsDeleter
            = [](Exts* exts) { sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free); };
        auto exts
            = std::unique_ptr<Exts, void (*)(Exts*)>(sk_X509_EXTENSION_new_null(), extsDeleter);

        auto ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, san.c_str());
        CHECK_OR_NULLOPT(ext, "ACME: X509V3_EXT_conf_nid: " + getSslError());
        res = sk_X509_EXTENSION_push(exts.get(), ext);
        CHECK_OR_NULLOPT(res, "ACME: sk_X509_EXTENSION_push: " + getSslError());
        res = X509_REQ_add_extensions(req.get(), exts.get());
        CHECK_OR_NULLOPT(res, "ACME: X509_REQ_add_extensions: " + getSslError());
    }

    res = X509_REQ_set_pubkey(req.get(), pkey);
    CHECK_OR_NULLOPT(res, "ACME: X509_REQ_set_pubkey: " + getSslError());
    res = X509_REQ_sign(req.get(), pkey, EVP_sha256());
    CHECK_OR_NULLOPT(res, "ACME: X509_REQ_sign: " + getSslError());

    std::string der;
    const auto derSize = i2d_X509_REQ(req.get(), nullptr);
    CHECK_OR_NULLOPT(derSize > 0, "ACME: i2d_X509_REQ: " + getSslError());
    der.resize(derSize);
    auto derPtr = reinterpret_cast<uint8_t*>(der.data());
    const auto size = i2d_X509_REQ(req.get(), &derPtr);
    CHECK_OR_NULLOPT(size == derSize, "ACME: i2d_X509_REQ: " + getSslError());

    return der;
}

std::optional<Duration> getCertValidAfterNow(const std::string& path)
{
    auto f = makeUnique(std::fopen(path.c_str(), "r"), std::fclose);
    CHECK_OR_NULLOPT(f, "ACME: Could not open certificate file");
    // path most likely points to a PEM file containing a certificate chain (i.e. multiple
    // certificates).
    // Usually these are ordered as end-user certificate, intermediates*, root, so we simply load
    // the first one and check that.
    auto cert = makeUnique(PEM_read_X509(f.get(), nullptr, nullptr, nullptr), X509_free);
    CHECK_OR_NULLOPT(cert, "ACME: Could not load certificate: ", getSslError());

    const auto tm = X509_get0_notAfter(cert.get());
    CHECK_OR_NULLOPT(
        cert, "ACME: Could not retrieve the notAfter field of the certificate: ", getSslError());

    int days = 0;
    int secs = 0;
    if (!ASN1_TIME_diff(&days, &secs, nullptr, tm)) {
        slog::error("ACME: Could not calculate time difference: ", getSslError());
        return std::nullopt;
    }
    const uint32_t udays = days > 0 ? static_cast<uint32_t>(days) : 0;
    const uint32_t usecs = secs > 0 ? static_cast<uint32_t>(secs) : 0;

    // We do not check if this certificate even belongs to any of our domains. The caller should
    // make sure that this is the case.

    return Duration { udays, 0, 0, usecs }.normalized();
}

//////////////////////////////////////////////////////////////// HTTP

struct JsonResponse {
    StatusCode status;
    HeaderMap<> headers;
    minijson::JsonValue json;

    static std::optional<JsonResponse> parse(Response&& resp)
    {
        const auto contentType = resp.headers.get("Content-Type");
        if (!contentType || contentType.value() != "application/json") {
            slog::error("ACME: Invalid Content-Type: ", contentType.value_or("<none>"));
            return std::nullopt;
        }

        auto json = minijson::parse(resp.body);
        if (!json) {
            slog::error("ACME: Invalid JSON: ", json.error().message);
            return std::nullopt;
        }
        return JsonResponse { resp.status, std::move(resp.headers), std::move(*json) };
    }
};

struct NoBodyResponse {
    StatusCode status;
    HeaderMap<> headers;

    static std::optional<NoBodyResponse> parse(Response&& resp)
    {
        const auto contentType = resp.headers.get("Content-Type");
        if (contentType) {
            slog::error("ACME: Non-Empty Content-Type: ", contentType.value());
            return std::nullopt;
        }
        if (!resp.body.empty()) {
            slog::error("ACME: Body not empty");
            return std::nullopt;
        }
        return NoBodyResponse { resp.status, std::move(resp.headers) };
    }
};

struct TextResponse {
    StatusCode status;
    HeaderMap<> headers;
    std::string contentType;
    std::string body;

    static std::optional<TextResponse> parse(Response&& resp)
    {
        auto contentType = resp.headers.get("Content-Type");
        if (!contentType) {
            slog::error("ACME: No Content-Type");
            return std::nullopt;
        }
        return TextResponse { resp.status, std::move(resp.headers), std::string(*contentType),
            std::move(resp.body) };
    }
};

template <typename R>
void logResponse(const R& resp)
{
    slog::info("Status: ", static_cast<uint32_t>(resp.status));
    slog::info("Headers:");
    for (const auto& [name, value] : resp.headers.getEntries()) {
        slog::info(name, ": ", value);
    }
}

template <typename ResponseType = JsonResponse>
std::optional<ResponseType> acmeRequest(ThreadRequester& req, Method method, const std::string& url,
    HeaderMap<> headers = {}, const std::string& body = "")
{
    // https://www.rfc-editor.org/rfc/rfc8555#section-6.1
    // ACME clients MUST send a User-Agent header field, in accordance with [RFC7231].  This header
    // field SHOULD include the name and version of the ACME software in addition to the name and
    // version of the underlying HTTP client software.
    headers.add("User-Agent", "whacme");

    auto resp = req.request(method, url, headers, body).get();
    if (!resp) {
        slog::error("ACME: ", toString(method), " ", url, " failed: ", resp.error().message());
        return std::nullopt;
    }

    if (static_cast<uint32_t>(resp->status) / 100 != 2) {
        slog::error("ACME: ", toString(method), " ", url,
            " failed. Status: ", static_cast<uint32_t>(resp->status));
        logResponse(*resp);
        slog::info("Body:\n", resp->body);
        return std::nullopt;
    }

    auto ret = ResponseType::parse(std::move(*resp));
    if (!ret) {
        logResponse(*resp);
        slog::info("Body:\n", resp->body);
        return std::nullopt;
    }
    return ret;
}

std::optional<std::string> getNewNonce(ThreadRequester& req, const std::string& newNonceUrl)
{
    const auto resp = acmeRequest<NoBodyResponse>(req, Method::Get, newNonceUrl);
    if (!resp) {
        return std::nullopt;
    }

    const auto replayNonce = resp->headers.get("Replay-Nonce");
    if (!replayNonce) {
        slog::error("Missing Replay-Nonce header");
        logResponse(*resp);
        return std::nullopt;
    }

    return std::string(*replayNonce);
}

// Note that nonce is an in-out parameter and will be updated with the newly received nonce
template <typename ResponseType = JsonResponse>
std::optional<ResponseType> signedRequest(ThreadRequester& req, const std::string& url,
    const std::string& payload, const std::string& keyId, std::string& nonce, EVP_PKEY* pkey)
{
    const auto payloadB64 = encodeBase64Url(payload);

    assert(!nonce.empty());
    const auto protect = "{\"url\": \"" + url + "\", \"alg\":\"RS256\", \"nonce\":\"" + nonce
        + "\", " + keyId + "}";
    nonce.clear(); // It has been used up
    const auto protectB64 = encodeBase64Url(protect);

    const auto signature = sign(protectB64 + "." + payloadB64, pkey);
    const auto body = "{\"protected\":\"" + protectB64 + "\",\"payload\":\"" + payloadB64
        + "\",\"signature\":\"" + signature + "\"}";

    HeaderMap<> headers;
    headers.add("Content-Type", "application/jose+json");
    auto resp = acmeRequest<ResponseType>(req, Method::Post, url, std::move(headers), body);
    if (!resp) {
        return std::nullopt;
    }

    const auto replayNonce = resp->headers.get("Replay-Nonce");
    if (replayNonce) {
        nonce = *replayNonce;
    }
    return resp;
}

bool waitForStatusValid(ThreadRequester& req, const std::string& url, const std::string& keyId,
    std::string& nonce, EVP_PKEY* pkey)
{
    static constexpr uint32_t maxTries = 60;
    uint32_t tryNum = 1;
    while (tryNum < maxTries) {
        slog::info("ACME: Checking.. (", tryNum, ")");
        const auto resp = signedRequest(req, url, "", keyId, nonce, pkey);
        // We already logged if (!resp)
        if (resp) {
            const auto status = resp->json["status"];
            if (!status.isString()) {
                slog::error(
                    "ACME: No 'status' attribute in response object: ", resp->json.dump("  "));
                return false;
            }
            if (status.asString() == "valid") {
                return true;
            } else {
                slog::error("ACME: Failed (Object Status: ", status.asString(), ")");
            }
        }
        std::this_thread::sleep_for(1s);
        tryNum++;
    }
    slog::error("ACME: Failed after maximum number of retries");
    return false;
}

//////////////////////////////////////////////////////// JSON PARSING

struct NewOrder {
    std::vector<std::string> authorizations;
    std::string finalize;
};

struct Authz {
    struct Challenge {
        std::string status;
        std::string token;
        std::string type;
        std::string url;
    };

    struct Identifier {
        std::string value;
    };

    std::vector<Challenge> challenges;
    Identifier identifier;
    std::string status;
};

bool parse(const minijson::JsonValue& json, std::string& s)
{
    if (!json.isString()) {
        return false;
    }
    s = json.asString();
    return true;
}

template <typename T>
bool parse(const minijson::JsonValue& json, std::vector<T>& s)
{
    if (!json.isArray()) {
        return false;
    }
    for (const auto& elem : json.asArray()) {
        if (!parse(elem, s.emplace_back())) {
            return false;
        }
    }
    return true;
}

bool parse(const minijson::JsonValue& json, NewOrder& o)
{
    return parse(json["authorizations"], o.authorizations) && parse(json["finalize"], o.finalize);
}

bool parse(const minijson::JsonValue& json, Authz::Challenge& c)
{
    return parse(json["status"], c.status) && parse(json["token"], c.token)
        && parse(json["type"], c.type) && parse(json["url"], c.url);
}

bool parse(const minijson::JsonValue& json, Authz::Identifier& i)
{
    return parse(json["value"], i.value);
}

bool parse(const minijson::JsonValue& json, Authz& a)
{
    return parse(json["challenges"], a.challenges) && parse(json["identifier"], a.identifier)
        && parse(json["status"], a.status);
}

bool prepareDirectories(const fs::path& path)
{
    const auto dir = path.parent_path();
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) {
        slog::error("ACME: Could not create directories '", dir.string(), "': ", ec.message());
        return false;
    }
    return true;
}
}

AcmeClient::AcmeClient(IoQueue& io, Config::Acme config)
    : io_(io)
    , config_(config)
    , requester_(io)
    , challenges_(std::make_shared<std::vector<Challenge>>())
    , challengesListener_(
          io, [this](decltype(challenges_)&& challenges) { challenges_ = std::move(challenges); })
    , currentContextListener_(io, [this](decltype(currentContext_)&& currentContext) {
        currentContext_ = std::move(currentContext);
    })
{
    thread_ = std::thread([this]() { threadFunc(); });
}

std::shared_ptr<SslContext> AcmeClient::getCurrentContext() const
{
    return currentContext_;
}

std::shared_ptr<std::vector<AcmeClient::Challenge>> AcmeClient::getChallenges() const
{
    return challenges_;
}

void AcmeClient::threadFunc()
{
    if (!isValidDomainName(config_.domain)) {
        slog::fatal("ACME: '", config_.domain, "' is not a valid domain name");
        std::exit(0xac);
    }

    if (!prepareDirectories(config_.accountPrivateKeyPath)
        || !prepareDirectories(config_.certPrivateKeyPath)
        || !prepareDirectories(config_.certPath)) {
        std::exit(0xac);
    }

    auto accountPkey = getPrivateKey(config_.accountPrivateKeyPath, config_.rsaKeyLength);
    if (!accountPkey) {
        std::exit(0xac);
    }

    const auto keyParams = extractKeyParameters(accountPkey.get());

    const auto jwk = "{\"e\":\"" + encodeBase64Url(keyParams.exponent)
        + "\",\"kty\":\"RSA\",\"n\":\"" + encodeBase64Url(keyParams.modulus) + "\"}";
    const auto jwkThumbprint = sha256(jwk);

    if (needIssueCertificate()) {
        if (!issueCertificate(jwk, jwkThumbprint, accountPkey.get())) {
            slog::fatal("ACME: Could not issue initial certificate");
            std::exit(0xac);
        }
    }

    if (!updateContext()) {
        slog::fatal("ACME: Could not create initial context");
        std::exit(0xac);
    }

    std::default_random_engine rng(std::random_device {}());
    const auto jitterRange = static_cast<int32_t>(config_.renewCheckJitter.toSeconds());
    std::uniform_int_distribution<int32_t> jitterDist(-jitterRange, jitterRange);

    while (true) {
        const auto time = ::time(nullptr);
        // There is no way this can fail (the only possible error should not happen with nullptr)
        // (famous last words)
        assert(time != (::time_t)-1);

        ::tm lt;
        const auto ltRet = ::localtime_r(&time, &lt);
        assert(ltRet); // I don't want to handle this
        const TimePoint now { static_cast<uint32_t>(lt.tm_hour), static_cast<uint32_t>(lt.tm_min),
            static_cast<uint32_t>(lt.tm_sec) };

        // 1d as a failsafe so this code can be broken forever and I might never notice
        auto dSec = Duration::fromDays(1).toSeconds();
        for (const auto& checkTime : config_.renewCheckTimes) {
            const auto dur = now.getDurationUntil(checkTime);
            dSec = std::min(dSec, dur.toSeconds());
        }
        const auto jitter = jitterDist(rng);
        if (static_cast<int32_t>(dSec) + jitter < 60) {
            dSec = 60;
        } else {
            dSec = static_cast<uint32_t>(static_cast<int32_t>(dSec) + jitter);
        }
        ::sleep(dSec);

        if (needIssueCertificate()) {
            if (!issueCertificate(jwk, jwkThumbprint, accountPkey.get())) {
                // We logged it, but we can't do much else but try again later
                continue;
            }
        }

        if (!updateContext()) {
            // Either we didn't need to reissue, which means we could load the certificate and check
            // it's validity or we just issued a certificate and it did not fail.
            // If this happens, something went very wrong (a "this should never happen" type of
            // deal). So I prefer to exit.
            slog::fatal("ACME: Could not create context");
            std::exit(0xac);
        }
    }
}

bool AcmeClient::needIssueCertificate() const
{
    if (!fs::exists(config_.certPath)) {
        return true;
    }

    const auto validTime = getCertValidAfterNow(config_.certPath);
    if (!validTime) {
        slog::error("ACME: Could not load existing certificate from ", config_.certPath);
        return true;
    }

    if (*validTime < config_.renewBeforeExpiry) {
        slog::info(
            "ACME: Certificate is valid for ", toString(*validTime), ". Reissuing certificate.");
        return true;
    }

    slog::info("ACME: Certificate is still valid for ", toString(*validTime),
        ". Don't reissue certificate.");
    return false;
}

bool AcmeClient::updateContext()
{
    auto ctx = SslContext::createServer(config_.certPath, config_.certPrivateKeyPath);
    if (!ctx) {
        return false;
    }
    slog::info("ACME: Updating context");
    currentContextListener_.emit(std::shared_ptr<SslContext>(std::move(ctx)));
    return true;
}

bool AcmeClient::issueCertificate(
    const std::string& jwk, const std::string& jwkThumbprint, EVP_PKEY* accountPkey)
{
    auto certPkey = getPrivateKey(config_.certPrivateKeyPath, config_.rsaKeyLength);
    if (!certPkey) {
        return false;
    }

    const auto csrDer
        = generateCertificateSigningRequest(config_.domain, config_.altNames, certPkey.get());
    if (!csrDer) {
        slog::error("Could not encode CSR");
        return false;
    }

    const auto directory = acmeRequest<JsonResponse>(requester_, Method::Get, config_.url);
    if (!directory) {
        return false;
    }
    const auto newAccountUrl = directory->json["newAccount"].asString();
    const auto newNonceUrl = directory->json["newNonce"].asString();
    const auto newOrderUrl = directory->json["newOrder"].asString();

    auto nonceRes = getNewNonce(requester_, newNonceUrl);
    if (!nonceRes) {
        return false;
    }
    std::string nonce = *nonceRes;

    const auto jwkKeyId = "\"jwk\": " + jwk;
    const auto newAccountResp = signedRequest(requester_, newAccountUrl,
        R"({"termsOfServiceAgreed": true})", jwkKeyId, nonce, accountPkey);
    if (!newAccountResp) {
        return false;
    }

    // If a new account was created for this private key, 201 is returned.
    // If an account already exists, 200 is returned.
    // In both cases, the "Location" header will contain a URL to the account, which we will use as
    // a new key identifier.
    const auto accountUrl = newAccountResp->headers.get("Location");
    if (!accountUrl) {
        slog::error("ACME: Missing 'Location' header in newAccount response");
        logResponse(*newAccountResp);
        slog::info("Body:\n", newAccountResp->json.dump("  "));
        return false;
    }
    const auto kidKeyId = "\"kid\": \"" + std::string(*accountUrl) + "\"";

    if (newAccountResp->status == StatusCode::Ok) {
        slog::info("ACME: Account already exists for account key. Account URL: ", *accountUrl);
    } else if (newAccountResp->status == StatusCode::Created) {
        slog::info("ACME: New account created for account key. Account URL: ", *accountUrl);
    }

    std::string newOrderPayload = "{\"identifiers\": [";
    newOrderPayload += "{\"type\": \"dns\", \"value\": \"" + config_.domain + "\"}";
    for (const auto& domain : config_.altNames) {
        newOrderPayload += ", {\"type\": \"dns\", \"value\": \"" + domain + "\"}";
    }
    newOrderPayload += "]}";

    const auto newOrderResp
        = signedRequest(requester_, newOrderUrl, newOrderPayload, kidKeyId, nonce, accountPkey);
    if (!newOrderResp) {
        return false;
    }

    // Again the Location header contains the URL to the order.
    // The order has an 'expires' attribute that is 7 weeks in the future.
    // Even if I create another order, it returns the same order ID (without updating expires)
    // with status 201 Created.
    const auto orderUrl = newOrderResp->headers.get("Location");
    if (!orderUrl) {
        slog::error("ACME: Missing 'Location' header in newOrder response");
        logResponse(*newOrderResp);
        slog::info("Body:\n", newOrderResp->json.dump("  "));
        return false;
    }

    NewOrder newOrder;
    if (!parse(newOrderResp->json, newOrder)) {
        slog::error("ACME: Malformed newOrder response: ", newOrderResp->json.dump("  "));
        return false;
    }

    slog::info("ACME: Requested new order");

    for (const auto& authUrl : newOrder.authorizations) {
        const auto authzResp = signedRequest(requester_, authUrl, "", kidKeyId, nonce, accountPkey);
        if (!authzResp) {
            return false;
        }

        Authz authz;
        if (!parse(authzResp->json, authz)) {
            slog::error("ACME: Malformed authz response: ", authzResp->json.dump("  "));
            return false;
        }

        if (authz.status == "valid") {
            continue;
        }

        const auto domain = authz.identifier.value;

        for (const auto& challenge : authz.challenges) {
            if (challenge.type != "http-01") {
                continue;
            }

            const auto path = "/.well-known/acme-challenge/" + challenge.token;
            const auto keyAuth = challenge.token + "." + jwkThumbprint;
            auto challenges = std::vector<Challenge> { { path, keyAuth } };
            slog::info("ACME: Received challenge ", path);
            challengesListener_.emit(
                std::make_shared<std::vector<Challenge>>(std::move(challenges)));

            // We actually have to wait until the main thread has consumed the event until we can
            // really confirm the challenge has been completed, but considering that the
            // conformation and the request from the ACME server take some time, it should be fine.

            // Confirm the challenge has been completed
            const auto confResp
                = signedRequest(requester_, challenge.url, "{}", kidKeyId, nonce, accountPkey);
            if (!confResp) {
                return false;
            }

            slog::info("ACME: Challenge confirmed completed. Waiting for authorization.");
            if (!waitForStatusValid(requester_, authUrl, kidKeyId, nonce, accountPkey)) {
                return false;
            }
            slog::info("ACME: Authorized");

            // https://www.rfc-editor.org/rfc/rfc8555#section-7.1.4:
            // "A client should attempt to fulfill one of these challenges, and a server should
            // consider any one of the challenges sufficient to make the authorization valid."
            // So we break after fulfilling one challenge
            break;
        }
    }

    slog::info("ACME: Finalize order (sending CSR)");
    const auto finalizePayload = "{\"csr\": \"" + encodeBase64Url(*csrDer) + "\"}";
    const auto finalizeResp = signedRequest(
        requester_, newOrder.finalize, finalizePayload, kidKeyId, nonce, accountPkey);
    if (!finalizeResp) {
        return false;
    }

    slog::info("ACME: Waiting for order to complete");
    if (!waitForStatusValid(requester_, std::string(*orderUrl), kidKeyId, nonce, accountPkey)) {
        return false;
    }

    const auto certificateUrl = finalizeResp->json["certificate"];
    if (!certificateUrl.isString()) {
        slog::error(
            "ACME: Missing certificate url in finalize response: ", finalizeResp->json.dump("  "));
        return false;
    }

    slog::info("ACME: Downloading certificate");
    const auto certificateResp = signedRequest<TextResponse>(
        requester_, certificateUrl.asString(), "", kidKeyId, nonce, accountPkey);
    if (!certificateResp) {
        return false;
    }
    if (certificateResp->contentType != "application/pem-certificate-chain") {
        slog::error("ACME: Invalid Content-Type for certificate: ", certificateResp->contentType);
        return false;
    }
    const auto certPem = certificateResp->body;

    slog::info("ACME: Saving certificate");
    auto certFile = makeUnique(std::fopen(config_.certPath.c_str(), "w"), std::fclose);
    if (!certFile) {
        slog::error(
            "ACME: Could not open destination file for certificate: ", errnoToString(errno));
        return false;
    }
    if (std::fwrite(certPem.data(), 1, certPem.size(), certFile.get()) != certPem.size()) {
        slog::error("ACME: Could not write certificate file: ", errnoToString(errno));
        return false;
    }
    if (std::fclose(certFile.release()) != 0) {
        slog::error("ACME: Could not close certificate file: ", errnoToString(errno));
        return false;
    }

    return true;
}

namespace {
std::unordered_map<std::string, std::unique_ptr<AcmeClient>>& getAcmeClients()
{
    static std::unordered_map<std::string, std::unique_ptr<AcmeClient>> clients;
    return clients;
}
}

AcmeClient* registerAcmeClient(const std::string& name, IoQueue& io, Config::Acme config)
{
    return getAcmeClients()
        .emplace(name, std::make_unique<AcmeClient>(io, std::move(config)))
        .first->second.get();
}

AcmeClient* getAcmeClient(const std::string& name)
{
    const auto it = getAcmeClients().find(name);
    return it != getAcmeClients().end() ? it->second.get() : nullptr;
}
