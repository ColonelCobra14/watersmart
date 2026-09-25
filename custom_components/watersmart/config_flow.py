"""Config flow for WaterSmart integration."""

from asyncio import timeout
import logging
from typing import Any

from aiohttp import ClientError
from aiohttp.client_exceptions import ClientConnectorError
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import voluptuous as vol

from .client import AuthenticationError, Requires2FAError, WaterSmartClient
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
    }
)


class WaterSmartConfigFlow(ConfigFlow, domain=DOMAIN):  # type: ignore[call-arg]
    """Handle a config flow for WaterSmart."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        self.login_data: dict[str, Any] | None = None
        self.api_client: WaterSmartClient | None = None
        self.account_number: str | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step.

        Returns:
            The config flow result.
        """
        errors: dict[str, str] = {}

        if user_input is not None:
            self.login_data = user_input
            session = async_get_clientsession(self.hass)

            self.api_client = WaterSmartClient(
                user_input[CONF_HOST],
                user_input[CONF_USERNAME],
                user_input[CONF_PASSWORD],
                session=session,
            )

            try:
                async with timeout(30):
                    self.account_number = (
                        await self.api_client.async_get_account_number()
                    )
            except Requires2FAError:
                return await self.async_step_2fa()
            except (ClientConnectorError, TimeoutError, ClientError):
                errors["base"] = "cannot_connect"
            except AuthenticationError:
                errors["base"] = "invalid_auth"
            except Exception:
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                if self.account_number:
                    return self.async_create_entry(
                        title=f"{user_input[CONF_HOST]} ({user_input[CONF_USERNAME]})",
                        data=user_input,
                    )
                errors["base"] = "invalid_auth"

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
            description_placeholders={
                "example_host": "bendoregon",
                "example_url": "https://bendoregon.watersmart.com/",
            },
        )

    async def async_step_2fa(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the 2FA step.

        Returns:
            The config flow result.
        """
        errors: dict[str, str] = {}

        assert self.api_client is not None
        assert self.login_data is not None

        if user_input is not None:
            try:
                async with timeout(30):
                    # Submit the code and retrieve the authenticated cookies
                    cookies = await self.api_client.async_verify_2fa(user_input["code"])
                    self.login_data["cookies"] = cookies

                    # Verify we can now scrape the account number successfully
                    self.account_number = (
                        await self.api_client.async_get_account_number()
                    )

                    if self.account_number:
                        return self.async_create_entry(
                            title=f"{self.login_data[CONF_HOST]} ({self.login_data[CONF_USERNAME]})",
                            data=self.login_data,
                        )
                    errors["base"] = "invalid_auth"
            except AuthenticationError:
                errors["base"] = "invalid_auth"
            except Exception:
                _LOGGER.exception("Unexpected exception during 2FA")
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="2fa",
            data_schema=vol.Schema({vol.Required("code"): str}),
            errors=errors,
        )


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
