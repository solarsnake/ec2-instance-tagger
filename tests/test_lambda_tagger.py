import json

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

import lambda_tagger

IID = "i-0123456789abcdef0"
EVENT = {"detail": {"instance-id": IID}}


@pytest.fixture
def stubbed(monkeypatch):
    client = boto3.client("ec2", region_name="us-east-1")
    monkeypatch.setattr(lambda_tagger, "_ec2_client", lambda: client)
    monkeypatch.setattr(lambda_tagger, "_sleep", lambda _seconds: None)
    for var in ("TAG_KEY", "OVERWRITE_EXISTING", "SKIP_EKS_NODES"):
        monkeypatch.delenv(var, raising=False)
    with Stubber(client) as stubber:
        yield stubber


def instance(platform="Linux/UNIX", tags=None):
    inst = {"InstanceId": IID, "PlatformDetails": platform}
    if tags is not None:
        inst["Tags"] = [{"Key": k, "Value": v} for k, v in tags.items()]
    return {"Reservations": [{"Instances": [inst]}]}


def expect_tag(stubber, key, value):
    stubber.add_response(
        "create_tags", {}, {"Resources": [IID], "Tags": [{"Key": key, "Value": value}]}
    )


@pytest.mark.parametrize(
    ("details", "expected"),
    [
        ("Windows", "windows"),
        ("Windows with SQL Server Standard", "windows"),
        ("Red Hat Enterprise Linux", "rhel"),
        ("Red Hat BYOL Linux", "rhel"),
        ("SUSE Linux", "suse"),
        ("Linux/UNIX", "linux"),
        ("Ubuntu Pro", "linux"),
        ("", "linux"),
        (None, "linux"),
    ],
)
def test_classify_platform(details, expected):
    assert lambda_tagger.classify_platform(details) == expected


def test_tags_windows_instance(stubbed):
    stubbed.add_response("describe_instances", instance("Windows"), {"InstanceIds": [IID]})
    expect_tag(stubbed, "os", "windows")
    result = lambda_tagger.lambda_handler(EVENT, None)
    assert result == {"instance_id": IID, "action": "tagged", "reason": None, "value": "windows"}
    stubbed.assert_no_pending_responses()


def test_custom_tag_key(stubbed, monkeypatch):
    monkeypatch.setenv("TAG_KEY", "Platform")
    stubbed.add_response("describe_instances", instance(), {"InstanceIds": [IID]})
    expect_tag(stubbed, "Platform", "linux")
    result = lambda_tagger.lambda_handler(EVENT, None)
    assert result["action"] == "tagged"
    stubbed.assert_no_pending_responses()


@pytest.mark.parametrize("eks_tag", lambda_tagger.EKS_TAGS)
def test_skips_each_eks_tag(stubbed, eks_tag):
    stubbed.add_response(
        "describe_instances", instance(tags={eks_tag: "x"}), {"InstanceIds": [IID]}
    )
    result = lambda_tagger.lambda_handler(EVENT, None)
    assert result["action"] == "skipped"
    assert result["reason"] == "eks-node"
    stubbed.assert_no_pending_responses()


def test_eks_skip_disabled_tags_anyway(stubbed, monkeypatch):
    monkeypatch.setenv("SKIP_EKS_NODES", "false")
    stubbed.add_response(
        "describe_instances",
        instance(tags={"eks:cluster-name": "c"}),
        {"InstanceIds": [IID]},
    )
    expect_tag(stubbed, "os", "linux")
    result = lambda_tagger.lambda_handler(EVENT, None)
    assert result["action"] == "tagged"
    stubbed.assert_no_pending_responses()


def test_existing_tag_kept(stubbed):
    stubbed.add_response(
        "describe_instances", instance(tags={"os": "custom"}), {"InstanceIds": [IID]}
    )
    result = lambda_tagger.lambda_handler(EVENT, None)
    assert result["action"] == "skipped"
    assert result["reason"] == "tag-exists"
    stubbed.assert_no_pending_responses()


def test_existing_tag_overwritten_when_enabled(stubbed, monkeypatch):
    monkeypatch.setenv("OVERWRITE_EXISTING", "true")
    stubbed.add_response(
        "describe_instances", instance("Windows", tags={"os": "custom"}), {"InstanceIds": [IID]}
    )
    expect_tag(stubbed, "os", "windows")
    result = lambda_tagger.lambda_handler(EVENT, None)
    assert result["action"] == "tagged"
    stubbed.assert_no_pending_responses()


def test_not_found_error_is_skipped(stubbed):
    for _ in range(3):
        stubbed.add_client_error("describe_instances", "InvalidInstanceID.NotFound")
    result = lambda_tagger.lambda_handler(EVENT, None)
    assert result == {
        "instance_id": IID,
        "action": "skipped",
        "reason": "not-found",
        "value": None,
    }
    stubbed.assert_no_pending_responses()


def test_not_found_then_success_is_tagged(stubbed):
    stubbed.add_client_error("describe_instances", "InvalidInstanceID.NotFound")
    stubbed.add_response("describe_instances", instance("Windows"), {"InstanceIds": [IID]})
    expect_tag(stubbed, "os", "windows")
    result = lambda_tagger.lambda_handler(EVENT, None)
    assert result["action"] == "tagged"
    assert result["value"] == "windows"
    stubbed.assert_no_pending_responses()


def test_not_found_retries_exactly_three_describe_calls(stubbed, monkeypatch):
    delays = []
    monkeypatch.setattr(lambda_tagger, "_sleep", delays.append)
    for _ in range(3):
        stubbed.add_client_error("describe_instances", "InvalidInstanceID.NotFound")
    result = lambda_tagger.lambda_handler(EVENT, None)
    assert result["reason"] == "not-found"
    assert delays == [1, 2]
    stubbed.assert_no_pending_responses()


def test_empty_reservations_is_skipped(stubbed):
    for _ in range(3):
        stubbed.add_response("describe_instances", {"Reservations": []}, {"InstanceIds": [IID]})
    result = lambda_tagger.lambda_handler(EVENT, None)
    assert result["action"] == "skipped"
    assert result["reason"] == "not-found"
    stubbed.assert_no_pending_responses()


def test_other_describe_error_is_logged_and_raised(stubbed, capsys):
    stubbed.add_client_error("describe_instances", "UnauthorizedOperation")
    with pytest.raises(ClientError):
        lambda_tagger.lambda_handler(EVENT, None)
    parsed = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert parsed["action"] == "error"
    assert parsed["instance_id"] == IID
    stubbed.assert_no_pending_responses()


@pytest.mark.parametrize("event", [{}, {"detail": {}}, {"detail": None}])
def test_bad_event_is_skipped(stubbed, event):
    result = lambda_tagger.lambda_handler(event, None)
    assert result == {
        "instance_id": None,
        "action": "skipped",
        "reason": "bad-event",
        "value": None,
    }
    stubbed.assert_no_pending_responses()


def test_create_tags_error_is_logged_and_raised(stubbed, capsys):
    stubbed.add_response("describe_instances", instance(), {"InstanceIds": [IID]})
    stubbed.add_client_error("create_tags", "RequestLimitExceeded")
    with pytest.raises(ClientError):
        lambda_tagger.lambda_handler(EVENT, None)
    parsed = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert parsed["action"] == "error"
    assert parsed["instance_id"] == IID
    stubbed.assert_no_pending_responses()


def test_env_bool_parsing(monkeypatch):
    for raw in ("true", "True", "TRUE", "1", "yes", "YES"):
        monkeypatch.setenv("FLAG", raw)
        assert lambda_tagger._env_bool("FLAG", False) is True
    for raw in ("false", "FALSE", "0", "no", "", "garbage"):
        monkeypatch.setenv("FLAG", raw)
        assert lambda_tagger._env_bool("FLAG", True) is False
    monkeypatch.delenv("FLAG")
    assert lambda_tagger._env_bool("FLAG", True) is True
    assert lambda_tagger._env_bool("FLAG", False) is False


def test_log_line_is_json(stubbed, capsys):
    stubbed.add_response("describe_instances", instance(), {"InstanceIds": [IID]})
    expect_tag(stubbed, "os", "linux")
    lambda_tagger.lambda_handler(EVENT, None)
    last = capsys.readouterr().out.strip().splitlines()[-1]
    parsed = json.loads(last)
    assert parsed["action"] == "tagged"
    assert parsed["tag_key"] == "os"
    stubbed.assert_no_pending_responses()
