pub usingnamespace @cImport({
    @cDefine("WOLFSSL_TLS13", "");
    @cDefine("SESSION_INDEX", "");
    @cDefine("SESSION_CERTS", "");

    @cInclude("wolfssl/ssl.h");
});
