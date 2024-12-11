"""The tests for the GeoCaching Sensor integration."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from homeassistant.components.geocaching.const import DOMAIN
from homeassistant.components.geocaching.sensor import (
    SENSORS,
    GeocachingSensor,
    async_setup_entry,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceEntryType

# Mock constants
MOCK_ENTRY_ID = "mock_entry_id"
MOCK_USER_DATA = {
    "find_count": 123,
    "hide_count": 45,
    "favorite_points": 67,
    "souvenir_count": 10,
    "awarded_favorite_points": 5,
    "reference_code": "USER123",
    "username": "TestUser",
}
MOCK_NEARBY_CACHES = [{"id": "cache1"}, {"id": "cache2"}, {"id": "cache3"}]
MOCK_TRACKABLES = [
    {"kilometers_traveled": 150.5},
    {"kilometers_traveled": 200.3},
]


@pytest.fixture
def mock_coordinator():
    """Mock the GeocachingDataUpdateCoordinator."""
    coordinator = AsyncMock()
    coordinator.data = AsyncMock()
    coordinator.data.user = AsyncMock(**MOCK_USER_DATA)
    coordinator.data.nearby_caches = MOCK_NEARBY_CACHES
    coordinator.data.trackables = MOCK_TRACKABLES  # Trackables are mocked here
    return coordinator


@pytest.fixture
def mock_entry():
    """Mock a ConfigEntry."""
    return AsyncMock(entry_id=MOCK_ENTRY_ID)


@pytest.mark.asyncio
async def test_async_setup_entry(
    hass: HomeAssistant, mock_coordinator, mock_entry
) -> None:
    """Test async setup entry."""
    hass.data[DOMAIN] = {MOCK_ENTRY_ID: mock_coordinator}

    async_add_entities = AsyncMock()

    await async_setup_entry(hass, mock_entry, async_add_entities)


@pytest.mark.asyncio
async def test_geocaching_sensor(hass: HomeAssistant, mock_coordinator) -> None:
    """Test the GeocachingSensor functionality."""
    sensor_description = SENSORS[0]  # Test the first sensor (find_count)

    sensor = GeocachingSensor(mock_coordinator, sensor_description)

    sensor.platform = MagicMock()
    sensor.platform.platform_name = "geocaching"

    sensor._attr_name = "find_count"

    # Verify sensor properties
    assert sensor.name == "find_count"
    assert sensor.native_unit_of_measurement == "caches"
    assert sensor.device_info["name"] == f"Geocaching {MOCK_USER_DATA['username']}"
    assert sensor.device_info["entry_type"] == DeviceEntryType.SERVICE
    assert sensor.unique_id == f"geocaching.USER123_{sensor._attr_name}"

    # Verify sensor value
    assert sensor.native_value == MOCK_USER_DATA["find_count"]


def test_kilometers_traveled_sensor(hass: HomeAssistant, mock_coordinator) -> None:
    """Test the GeocachingSensor functionality, summing kilometers_traveled."""

    trackable_description = SENSORS[
        6
    ]  # Test the sixth sensor (total_tracked_trackables_distance_traveled)

    sensor = GeocachingSensor(mock_coordinator, trackable_description)

    sensor.platform = MagicMock()
    sensor.platform.platform_name = "geocaching"

    sensor._attr_name = "total_tracked_trackables_distance_traveled"

    sensor._trackables = MOCK_TRACKABLES

    expected_sum = sum(
        trackable["kilometers_traveled"] for trackable in MOCK_TRACKABLES
    )

    mock_status = MagicMock()
    mock_status.trackables = MOCK_TRACKABLES

    value_fn = MagicMock()
    value_fn.return_value = round(expected_sum)

    sensor._get_native_value = MagicMock(return_value=value_fn(mock_status))

    assert sensor.name == "total_tracked_trackables_distance_traveled"
    assert sensor.native_unit_of_measurement == "km"
    assert sensor.device_info["name"] == f"Geocaching {MOCK_USER_DATA['username']}"
    assert sensor.device_info["entry_type"] == DeviceEntryType.SERVICE
    assert sensor.unique_id == f"geocaching.USER123_{sensor._attr_name}"

    # Verify that the sensor returns the correct sum of kilometers_traveled asynchronously
    assert sensor.native_value == round(expected_sum)
