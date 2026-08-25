use browserd_egress::{
    CanonicalUrl, ProxyProtocolError, ProxyProtocolLimits, ProxyRequest, ProxyRequestKind,
};

fn limits() -> ProxyProtocolLimits {
    ProxyProtocolLimits {
        max_header_bytes: 16 * 1024,
        max_header_count: 64,
        max_request_target_bytes: 8 * 1024,
    }
}

#[test]
fn connect_authority_is_canonicalized_without_forwarding_proxy_headers() {
    let bytes = b"CONNECT Example.COM.:443 HTTP/1.1\r\nHost: Example.COM.:443\r\nProxy-Connection: keep-alive\r\n\r\nclient-hello";
    let request = ProxyRequest::parse(bytes, limits());
    assert!(request.is_ok());
    let Ok(request) = request else {
        return;
    };

    assert_eq!(request.kind(), ProxyRequestKind::ConnectTunnel);
    assert_eq!(request.method(), "CONNECT");
    assert_eq!(request.url().host(), "example.com");
    assert_eq!(request.url().port(), 443);
    assert!(request.upstream_head().is_empty());
    assert_eq!(request.buffered_after_head(), b"client-hello");
}

#[test]
fn absolute_form_http_is_rewritten_to_origin_form_and_hop_headers_are_removed() {
    let bytes = b"POST http://example.com:8080/a/../submit?q=1 HTTP/1.1\r\nHost: example.com:8080\r\nConnection: keep-alive, x-remove\r\nX-Remove: secret\r\nProxy-Authorization: Browserd should-not-forward\r\nContent-Length: 4\r\nX-Trace: safe\r\n\r\ndata";
    let request = ProxyRequest::parse(bytes, limits());
    assert!(request.is_ok());
    let Ok(request) = request else {
        return;
    };

    assert_eq!(request.kind(), ProxyRequestKind::ForwardHttp);
    assert_eq!(request.url().path_and_query(), "/submit?q=1");
    assert_eq!(request.buffered_after_head(), b"data");
    let head = String::from_utf8_lossy(request.upstream_head());
    assert!(head.starts_with("POST /submit?q=1 HTTP/1.1\r\n"));
    assert!(head.contains("Host: example.com:8080\r\n"));
    assert!(head.contains("Content-Length: 4\r\n"));
    assert!(head.contains("X-Trace: safe\r\n"));
    assert!(head.contains("Connection: close\r\n"));
    assert!(!head.to_ascii_lowercase().contains("proxy-authorization"));
    assert!(!head.to_ascii_lowercase().contains("x-remove"));
    assert!(!head.to_ascii_lowercase().contains("proxy-connection:"));
}

#[test]
fn websocket_upgrade_is_preserved_but_other_connection_nominated_headers_are_removed() {
    let bytes = b"GET ws://example.com/socket HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade, x-remove\r\nUpgrade: websocket\r\nX-Remove: no\r\nSec-WebSocket-Key: abc\r\n\r\n";
    let request = ProxyRequest::parse(bytes, limits());
    assert!(request.is_ok());
    if let Ok(request) = request {
        let head = String::from_utf8_lossy(request.upstream_head()).to_ascii_lowercase();
        assert!(head.contains("connection: upgrade\r\n"));
        assert!(head.contains("upgrade: websocket\r\n"));
        assert!(head.contains("sec-websocket-key: abc\r\n"));
        assert!(!head.contains("x-remove"));
    }
}

#[test]
fn parser_rejects_request_smuggling_and_ambiguous_authority_forms() {
    let invalid = [
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
        "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
        "GET http://example.com/ HTTP/1.1\r\nHost: attacker.test\r\n\r\n",
        "GET http://user@example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET /origin-form HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "CONNECT example.com:443/path HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n folded: bad\r\n\r\n",
        "get http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\nsecond-request",
        "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\n\r\ntoolong",
    ];

    for request in invalid {
        assert!(ProxyRequest::parse(request.as_bytes(), limits()).is_err());
    }
    assert_eq!(
        ProxyRequest::parse(
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-Bad: a\0b\r\n\r\n",
            limits(),
        ),
        Err(ProxyProtocolError::InvalidHeader)
    );
}

#[test]
fn connection_header_cannot_nominate_framing_or_routing_headers() {
    let invalid = [
        b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\ncOnNeCtIoN: keep-alive, CoNtEnT-LeNgTh\r\nContent-Length: 4\r\n\r\ndata".as_slice(),
        b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\nCONNECTION: HOST\r\n\r\n".as_slice(),
        b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: Transfer-Encoding\r\n\r\n".as_slice(),
    ];

    for request in invalid {
        assert_eq!(
            ProxyRequest::parse(request, limits()),
            Err(ProxyProtocolError::InvalidHeader),
            "connection-nominated routing and framing headers must fail closed"
        );
    }
}

#[test]
fn parser_enforces_header_count_header_bytes_and_target_bytes() {
    let tiny_header = ProxyProtocolLimits {
        max_header_bytes: 32,
        ..limits()
    };
    assert_eq!(
        ProxyRequest::parse(
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
            tiny_header,
        ),
        Err(ProxyProtocolError::HeaderTooLarge)
    );

    let one_header = ProxyProtocolLimits {
        max_header_count: 1,
        ..limits()
    };
    assert_eq!(
        ProxyRequest::parse(
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX: y\r\n\r\n",
            one_header,
        ),
        Err(ProxyProtocolError::TooManyHeaders)
    );

    let short_target = ProxyProtocolLimits {
        max_request_target_bytes: 8,
        ..limits()
    };
    assert_eq!(
        ProxyRequest::parse(
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
            short_target,
        ),
        Err(ProxyProtocolError::RequestTargetTooLarge)
    );
}

#[test]
fn incomplete_headers_are_distinguished_from_invalid_headers() {
    assert_eq!(
        ProxyRequest::parse(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com",
            limits()
        ),
        Err(ProxyProtocolError::IncompleteHeader)
    );
}

#[test]
fn declared_url_remains_compatible_with_the_connection_planner() {
    let request = ProxyRequest::parse(
        b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n",
        limits(),
    );
    assert!(request.is_ok());
    if let Ok(request) = request {
        let expected = CanonicalUrl::parse("http://example.com/path");
        assert!(expected.is_ok());
        if let Ok(expected) = expected {
            assert_eq!(request.url(), &expected);
        }
    }
}
