from truthgate import secrets as detector


def test_detects_supported_secret_shapes_without_retaining_values():
    aws = "AKIA1234567890ABCDEF"
    github = "ghp_" + "A" * 36
    source = f'aws = "{aws}"\ngithub = "{github}"\npassword = "correct horse battery staple"\n'

    findings = detector.find_secrets(source)

    assert [item.kind for item in findings] == [
        "aws_access_key",
        "github_token",
        "credential_assignment",
    ]
    rendered = repr(findings)
    assert aws not in rendered
    assert github not in rendered
    assert "correct horse battery staple" not in rendered


def test_ignores_explicit_placeholders_and_invalid_input():
    assert detector.find_secrets('password = "changeme"\napi_key = "<YOUR_API_KEY>"\n') == ()
    assert detector.find_secrets(None) == ()
