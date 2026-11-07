use browserd_api::decode_artifact_upload;

#[test]
fn upload_filename_is_a_bounded_utf8_basename() {
    for name in [
        "x".to_owned(),
        "첨부 문서.txt".to_owned(),
        "a".repeat(255),
        "한".repeat(85),
    ] {
        let json = serde_json::json!({"display_filename":name,"declared_content_type":null,"expected_size_bytes":1,"data_base64":"YQ=="});
        assert!(
            decode_artifact_upload(&json.to_string()).is_ok(),
            "{name:?}"
        );
    }
    for name in [
        "".to_owned(),
        ".".to_owned(),
        "..".to_owned(),
        "../x".to_owned(),
        "/x".to_owned(),
        "a\\b".to_owned(),
        "a\nb".to_owned(),
        "a\u{7f}b".to_owned(),
        "a".repeat(256),
        format!("{}a", "한".repeat(85)),
    ] {
        let json = serde_json::json!({"display_filename":name,"declared_content_type":null,"expected_size_bytes":1,"data_base64":"YQ=="});
        assert!(
            decode_artifact_upload(&json.to_string()).is_err(),
            "{name:?}"
        );
    }
}

#[test]
fn upload_accepts_exact_bounded_content_and_rejects_mismatched_or_invalid_base64() {
    let body = decode_artifact_upload(
        r#"{"display_filename":"hello.txt","declared_content_type":"text/plain","expected_size_bytes":5,"data_base64":"aGVsbG8="}"#,
    );
    assert!(body.is_ok());
    if let Ok(body) = body {
        assert_eq!(
            body.decode_bytes().ok().as_deref(),
            Some(b"hello".as_slice())
        );
    }
    for (size, data) in [(4, "aGVsbG8="), (5, "!!!"), (0, ""), (524_289, "AA==")] {
        let json = serde_json::json!({"display_filename":"x", "declared_content_type":null, "expected_size_bytes":size, "data_base64":data});
        assert!(decode_artifact_upload(&json.to_string()).is_err());
    }
}

#[test]
fn metadata_only_request_cannot_create_an_empty_upload() {
    let parsed = decode_artifact_upload(
        r#"{"display_filename":"hello.txt","declared_content_type":null,"expected_size_bytes":5}"#,
    );
    // Old metadata envelopes can still be decoded, but cannot be submitted as file content.
    assert!(parsed.is_ok());
    if let Ok(body) = parsed {
        assert!(body.decode_bytes().is_err());
    }
}
