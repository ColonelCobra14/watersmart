"""Test client."""

from unittest.mock import ANY, AsyncMock, MagicMock, call

from homeassistant.core import HomeAssistant
import pytest

from custom_components.watersmart.client import (
    AuthenticationError,
    InvalidAccountNumberError,
    Requires2FAError,
    ScrapeError,
    WaterSmartClient,
)


async def test_init_with_cookies(hass: HomeAssistant):
    """Test client initialization with cookies binds to correct domain."""
    client = WaterSmartClient(
        hostname="test",
        username="test@home-assistant.io",
        password="Passw0rd",  # noqa: S106
        cookies={"auth_session": "test_cookie"},
    )

    cookies = list(client._session.cookie_jar)
    assert len(cookies) == 1
    assert cookies[0].key == "auth_session"
    assert cookies[0].value == "test_cookie"
    assert cookies[0]["domain"] == "test.watersmart.com"

    await client._session.close()


async def test_login_success(hass: HomeAssistant, mock_aiohttp_session, fixture_loader):
    mock_aiohttp_session.post.return_value.text.return_value = (
        fixture_loader.login_success_html
    )
    mock_aiohttp_session.get.return_value.status = 200

    client = WaterSmartClient(
        hostname="test",
        username="test@home-assistant.io",
        password="Passw0rd",  # noqa: S106
    )

    await client.async_get_account_number()

    mock_aiohttp_session.get.assert_has_calls(
        [
            call(
                "https://test.watersmart.com/index.php/logout/login",
                headers=ANY,
            ),
        ]
    )

    mock_aiohttp_session.post.assert_has_calls(
        [
            call(
                "https://test.watersmart.com/index.php/logout/login?forceEmail=1",
                data={
                    "token": "",
                    "email": "test@home-assistant.io",
                    "password": "Passw0rd",
                },
                headers=ANY,
            ),
        ]
    )


async def test_login_sends_browser_headers(
    hass: HomeAssistant, mock_aiohttp_session, fixture_loader
):
    """Portals/WAFs may reject non-browser clients; login POST must look like a browser."""
    mock_aiohttp_session.post.return_value.text.return_value = (
        fixture_loader.login_success_html
    )

    client = WaterSmartClient(
        hostname="test",
        username="test@home-assistant.io",
        password="Passw0rd",  # noqa: S106
    )

    await client.async_get_account_number()

    _, kwargs = mock_aiohttp_session.post.call_args
    headers = kwargs["headers"]
    assert headers["User-Agent"].startswith("Mozilla/5.0")
    assert "Accept" in headers
    assert "Accept-Language" in headers


async def test_hourly_data_sends_browser_headers(
    hass: HomeAssistant, mock_aiohttp_session, fixture_loader
):
    """The data request must also look like a browser for a consistent auth flow."""
    mock_aiohttp_session.post.return_value.text.return_value = (
        fixture_loader.login_success_html
    )
    mock_aiohttp_session.get.return_value.text.return_value = (
        fixture_loader.realtime_api_response_json
    )

    client = WaterSmartClient(hostname="test", username="", password="")
    await client.async_get_hourly_data()

    _, kwargs = mock_aiohttp_session.get.call_args_list[-1]
    assert kwargs["headers"]["User-Agent"].startswith("Mozilla/5.0")


async def test_login_success_with_refreshtoken(
    hass: HomeAssistant, mock_aiohttp_session, fixture_loader
):
    resp1 = AsyncMock()
    resp1.text.return_value = fixture_loader.login_refreshtoken_html
    resp2 = AsyncMock()
    resp2.text.return_value = fixture_loader.login_success_html
    mock_aiohttp_session.post.side_effect = [resp1, resp2]

    client = WaterSmartClient(
        hostname="test",
        username="test@home-assistant.io",
        password="Passw0rd",  # noqa: S106
    )

    await client.async_get_account_number()

    assert mock_aiohttp_session.post.call_count == 2

    mock_aiohttp_session.post.assert_has_calls(
        [
            call(
                "https://test.watersmart.com/index.php/logout/login?forceEmail=1",
                data={
                    "token": "",
                    "email": "test@home-assistant.io",
                    "password": "Passw0rd",
                },
                headers=ANY,
            ),
        ]
    )
    mock_aiohttp_session.post.assert_has_calls(
        [
            call(
                "https://test.watersmart.com/index.php/logout/login?forceEmail=1",
                data={
                    "token": "",
                    "loginRefreshToken": "12.34 56.78",
                    "email": "test@home-assistant.io",
                    "password": "Passw0rd",
                },
                headers=ANY,
            ),
        ]
    )


async def test_login_is_preserved(
    hass: HomeAssistant, mock_aiohttp_session, fixture_loader
):
    mock_aiohttp_session.post.return_value.text.return_value = (
        fixture_loader.login_success_html
    )

    client = WaterSmartClient(
        hostname="test",
        username="test@home-assistant.io",
        password="Passw0rd",  # noqa: S106
    )

    await client.async_get_account_number()
    await client.async_get_account_number()

    assert mock_aiohttp_session.post.call_count == 1


async def test_login_failure(hass: HomeAssistant, mock_aiohttp_session, fixture_loader):
    mock_aiohttp_session.post.return_value.text.return_value = (
        fixture_loader.login_error_html
    )

    client = WaterSmartClient(
        hostname="test",
        username="test@home-assistant.io",
        password="Passw0rd",  # noqa: S106
    )

    with pytest.raises(AuthenticationError):
        await client.async_get_account_number()


async def test_login_requires_2fa(hass: HomeAssistant, mock_aiohttp_session):
    """Test login process properly detects and raises Requires2FAError."""
    mock_aiohttp_session.post.return_value.text.return_value = (
        "<html>verification code</html>"
    )

    client = WaterSmartClient(
        hostname="test",
        username="test@home-assistant.io",
        password="Passw0rd",  # noqa: S106
    )

    with pytest.raises(Requires2FAError):
        await client.async_get_account_number()


async def test_async_verify_2fa_success(hass: HomeAssistant, mock_aiohttp_session):
    """Test submitting 2FA successfully and extracting cookies."""
    mock_aiohttp_session.post.return_value.text.return_value = "<html>success</html>"

    # Mock cookies in the jar
    mock_cookie = MagicMock()
    mock_cookie.key = "auth_session"
    mock_cookie.value = "my_saved_cookie"
    mock_aiohttp_session.cookie_jar = [mock_cookie]

    client = WaterSmartClient(
        hostname="test",
        username="test@home-assistant.io",
        password="Passw0rd",  # noqa: S106
        session=mock_aiohttp_session,
    )

    cookies = await client.async_verify_2fa("123456")

    mock_aiohttp_session.post.assert_called_once_with(
        "https://test.watersmart.com/index.php/welcome/verify",
        data={"verificationCode": "123456"},
        headers=ANY,
    )
    assert cookies == {"auth_session": "my_saved_cookie"}


async def test_async_verify_2fa_failure(hass: HomeAssistant, mock_aiohttp_session):
    """Test submitting 2FA fails with error message."""
    mock_aiohttp_session.post.return_value.text.return_value = (
        '<html><div class="error-message">Invalid Code</div></html>'
    )

    client = WaterSmartClient(
        hostname="test",
        username="test@home-assistant.io",
        password="Passw0rd",  # noqa: S106
        session=mock_aiohttp_session,
    )

    with pytest.raises(AuthenticationError) as exc:
        await client.async_verify_2fa("wrong_code")

    assert "Invalid Code" in exc.value._errors


async def test_structure_change_failure(
    hass: HomeAssistant, mock_aiohttp_session, fixture_loader
):
    mock_aiohttp_session.post.return_value.text.return_value = (
        fixture_loader.login_structure_change_failure_html
    )

    client = WaterSmartClient(
        hostname="test",
        username="test@home-assistant.io",
        password="Passw0rd",  # noqa: S106
    )

    with pytest.raises(ScrapeError):
        await client.async_get_account_number()


async def test_async_get_account_number(
    hass: HomeAssistant, mock_aiohttp_session, fixture_loader
):
    mock_aiohttp_session.post.return_value.text.return_value = (
        fixture_loader.login_success_html
    )

    client = WaterSmartClient(
        hostname="test",
        username="test@home-assistant.io",
        password="Passw0rd",  # noqa: S106
    )
    account_number = await client.async_get_account_number()

    assert account_number == "1234567-8900"


async def test_account_number_unmatchable(
    hass: HomeAssistant, mock_aiohttp_session, fixture_loader
):
    mock_aiohttp_session.post.return_value.text.return_value = (
        fixture_loader.account_number_unmatchable_html
    )

    client = WaterSmartClient(
        hostname="test",
        username="test@home-assistant.io",
        password="Passw0rd",  # noqa: S106
    )

    with pytest.raises(InvalidAccountNumberError):
        await client.async_get_account_number()


async def test_async_get_async_get_hourly_data(
    hass: HomeAssistant,
    mock_aiohttp_session,
    fixture_loader,
):
    mock_aiohttp_session.post.return_value.text.return_value = (
        fixture_loader.login_success_html
    )
    mock_aiohttp_session.get.return_value.text.return_value = (
        fixture_loader.realtime_api_response_json
    )

    client = WaterSmartClient(hostname="", username="", password="")
    hourly = await client.async_get_hourly_data()

    # Verify both pre-flight login GET and realtime data GET happened
    assert mock_aiohttp_session.get.call_count == 2

    mock_aiohttp_session.get.assert_has_calls(
        [
            call(
                "https://.watersmart.com/index.php/rest/v1/Chart/RealTimeChart",
                headers=ANY,
            ),
        ]
    )

    assert mock_aiohttp_session.post.call_count == 1  # for login
    assert hourly == [
        {
            "read_datetime": 1718823600,
            "gallons": 7.48,
            "flags": None,
            "leak_gallons": 0,
        },
        {"read_datetime": 1718827200, "gallons": 0, "flags": None, "leak_gallons": 0},
        {
            "read_datetime": 1718830800,
            "gallons": 7.48,
            "flags": None,
            "leak_gallons": 0,
        },
        {"read_datetime": 1718834400, "gallons": 0, "flags": None, "leak_gallons": 0},
    ]
