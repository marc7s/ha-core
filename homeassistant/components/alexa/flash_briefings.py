"""Support for Alexa skill service end point."""

import hmac
from http import HTTPStatus
import logging
import uuid

from aiohttp.web_response import StreamResponse

from homeassistant.components import http
from homeassistant.const import CONF_PASSWORD
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import template
from homeassistant.helpers.typing import ConfigType
import homeassistant.util.dt as dt_util

from .const import (
    API_PASSWORD,
    ATTR_MAIN_TEXT,
    ATTR_REDIRECTION_URL,
    ATTR_STREAM_URL,
    ATTR_TITLE_TEXT,
    ATTR_UID,
    ATTR_UPDATE_DATE,
    CONF_AUDIO,
    CONF_DISPLAY_URL,
    CONF_TEXT,
    CONF_TITLE,
    CONF_UID,
    DATE_FORMAT,
)

_LOGGER = logging.getLogger(__name__)

FLASH_BRIEFINGS_API_ENDPOINT = "/api/alexa/flash_briefings/{briefing_id}"


@callback
def async_setup(hass: HomeAssistant, flash_briefing_config: ConfigType) -> None:
    """Activate Alexa component."""
    hass.http.register_view(AlexaFlashBriefingView(hass, flash_briefing_config))


class AlexaFlashBriefingView(http.HomeAssistantView):
    """Handle Alexa Flash Briefing skill requests."""

    url = FLASH_BRIEFINGS_API_ENDPOINT
    requires_auth = False
    name = "api:alexa:flash_briefings"

    def __init__(self, hass: HomeAssistant, flash_briefings: ConfigType) -> None:
        """Initialize Alexa view."""
        super().__init__()
        self.flash_briefings = flash_briefings

    def get_rendered_value(self, item: dict, key: str) -> str | None:
        """Help function."""
        value = item.get(key)
        if value is not None:
            if isinstance(value, template.Template):
                return str(value.async_render(parse_result=False))
            if isinstance(value, str):
                return value
        return None

    def get_briefing(self, briefing_id: str) -> list:
        """Initialize Alexa view."""
        briefing = []

        for item in self.flash_briefings.get(briefing_id, []):
            output = {}

            output[ATTR_TITLE_TEXT] = self.get_rendered_value(item, CONF_TITLE)
            output[ATTR_MAIN_TEXT] = self.get_rendered_value(item, CONF_TEXT)
            output[ATTR_STREAM_URL] = self.get_rendered_value(item, CONF_AUDIO)
            output[ATTR_REDIRECTION_URL] = self.get_rendered_value(
                item, CONF_DISPLAY_URL
            )

            if (uid := item.get(CONF_UID)) is None:
                uid = str(uuid.uuid4())
            output[ATTR_UID] = uid

            output[ATTR_UPDATE_DATE] = dt_util.utcnow().strftime(DATE_FORMAT)

            briefing.append(output)

        return briefing

    @callback
    def get(
        self, request: http.HomeAssistantRequest, briefing_id: str
    ) -> StreamResponse | tuple[bytes, HTTPStatus]:
        """Handle Alexa Flash Briefing request."""
        _LOGGER.debug("Received Alexa flash briefing request for: %s", briefing_id)

        if request.query.get(API_PASSWORD) is None:
            err = "No password provided for Alexa flash briefing: %s"
            _LOGGER.error(err, briefing_id)
            return b"", HTTPStatus.UNAUTHORIZED

        if not hmac.compare_digest(
            request.query[API_PASSWORD].encode("utf-8"),
            self.flash_briefings[CONF_PASSWORD].encode("utf-8"),
        ):
            err = "Wrong password for Alexa flash briefing: %s"
            _LOGGER.error(err, briefing_id)
            return b"", HTTPStatus.UNAUTHORIZED

        if not isinstance(self.flash_briefings.get(briefing_id), list):
            err = "No configured Alexa flash briefing was found for: %s"
            _LOGGER.error(err, briefing_id)
            return b"", HTTPStatus.NOT_FOUND

        return self.json(self.get_briefing(briefing_id))
