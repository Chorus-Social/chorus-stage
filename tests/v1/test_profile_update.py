# tests/v1/test_profile_update.py
"""Tests for profile update functionality."""

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from chorus_stage.models import User


class TestProfileUpdate:
    """Test profile update endpoint functionality."""

    def test_get_my_profile_success(self, client: TestClient, test_user: User, auth_token: dict[str, str]) -> None:
        """Test getting current user's profile."""
        response = client.get("/api/v1/users/me/profile", headers=auth_token)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["display_name"] == test_user.display_name
        assert data["accent_color"] == test_user.accent_color

    def test_get_my_profile_unauthorized(self, client: TestClient) -> None:
        """Test getting profile without authentication."""
        response = client.get("/api/v1/users/me/profile")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_update_my_profile_display_name_only(self, client: TestClient, test_user: User, auth_token: dict[str, str], db_session) -> None:
        """Test updating only display name."""
        new_display_name = "Updated Display Name"
        
        response = client.patch(
            "/api/v1/users/me/profile",
            json={"display_name": new_display_name},
            headers=auth_token
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["display_name"] == new_display_name
        assert data["accent_color"] == test_user.accent_color  # Should remain unchanged
        
        # Verify database was actually updated
        db_session.refresh(test_user)
        assert test_user.display_name == new_display_name
        assert test_user.accent_color == test_user.accent_color  # Should remain unchanged

    def test_update_my_profile_accent_color_only(self, client: TestClient, test_user: User, auth_token: dict[str, str], db_session) -> None:
        """Test updating only accent color."""
        new_accent_color = "#00FF00"
        
        response = client.patch(
            "/api/v1/users/me/profile",
            json={"accent_color": new_accent_color},
            headers=auth_token
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["display_name"] == test_user.display_name  # Should remain unchanged
        assert data["accent_color"] == new_accent_color
        
        # Verify database was actually updated
        db_session.refresh(test_user)
        assert test_user.display_name == test_user.display_name  # Should remain unchanged
        assert test_user.accent_color == new_accent_color

    def test_update_my_profile_both_fields(self, client: TestClient, test_user: User, auth_token: dict[str, str], db_session) -> None:
        """Test updating both display name and accent color."""
        new_display_name = "Completely New Name"
        new_accent_color = "#FF00FF"
        
        response = client.patch(
            "/api/v1/users/me/profile",
            json={
                "display_name": new_display_name,
                "accent_color": new_accent_color
            },
            headers=auth_token
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["display_name"] == new_display_name
        assert data["accent_color"] == new_accent_color
        
        # Verify database was actually updated
        db_session.refresh(test_user)
        assert test_user.display_name == new_display_name
        assert test_user.accent_color == new_accent_color

    def test_update_my_profile_empty_payload(self, client: TestClient, test_user: User, auth_token: dict[str, str], db_session) -> None:
        """Test updating with empty payload (no changes)."""
        original_display_name = test_user.display_name
        original_accent_color = test_user.accent_color
        
        response = client.patch(
            "/api/v1/users/me/profile",
            json={},
            headers=auth_token
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["display_name"] == original_display_name
        assert data["accent_color"] == original_accent_color
        
        # Verify database was not changed
        db_session.refresh(test_user)
        assert test_user.display_name == original_display_name
        assert test_user.accent_color == original_accent_color

    def test_update_my_profile_null_values(self, client: TestClient, test_user: User, auth_token: dict[str, str], db_session) -> None:
        """Test updating with null values (should not change fields)."""
        original_display_name = test_user.display_name
        original_accent_color = test_user.accent_color
        
        response = client.patch(
            "/api/v1/users/me/profile",
            json={
                "display_name": None,
                "accent_color": None
            },
            headers=auth_token
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["display_name"] == original_display_name
        assert data["accent_color"] == original_accent_color
        
        # Verify database was not changed
        db_session.refresh(test_user)
        assert test_user.display_name == original_display_name
        assert test_user.accent_color == original_accent_color

    def test_update_my_profile_unauthorized(self, client: TestClient) -> None:
        """Test updating profile without authentication."""
        response = client.patch(
            "/api/v1/users/me/profile",
            json={"display_name": "New Name"}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_update_my_profile_invalid_accent_color(self, client: TestClient, test_user: User, auth_token: dict[str, str]) -> None:
        """Test updating with invalid accent color format."""
        response = client.patch(
            "/api/v1/users/me/profile",
            json={"accent_color": "invalid_color"},
            headers=auth_token
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        data = response.json()
        assert "accent color must be a valid hex color code" in data["detail"][0]["msg"].lower()

    def test_update_my_profile_display_name_too_long(self, client: TestClient, test_user: User, auth_token: dict[str, str]) -> None:
        """Test updating with display name that's too long."""
        long_name = "a" * 101  # Exceeds max_length=100
        
        response = client.patch(
            "/api/v1/users/me/profile",
            json={"display_name": long_name},
            headers=auth_token
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        data = response.json()
        assert "ensure this value has at most 100 characters" in data["detail"][0]["msg"].lower()

    def test_update_my_profile_display_name_too_short(self, client: TestClient, test_user: User, auth_token: dict[str, str]) -> None:
        """Test updating with display name that's too short."""
        response = client.patch(
            "/api/v1/users/me/profile",
            json={"display_name": ""},  # Empty string should fail min_length=1
            headers=auth_token
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        data = response.json()
        assert "ensure this value has at least 1 character" in data["detail"][0]["msg"].lower()

    def test_update_my_profile_persistence_across_requests(self, client: TestClient, test_user: User, auth_token: dict[str, str], db_session) -> None:
        """Test that profile updates persist across multiple requests."""
        new_display_name = "Persistent Name"
        new_accent_color = "#123456"
        
        # Update profile
        response = client.patch(
            "/api/v1/users/me/profile",
            json={
                "display_name": new_display_name,
                "accent_color": new_accent_color
            },
            headers=auth_token
        )
        assert response.status_code == status.HTTP_200_OK
        
        # Verify database was updated
        db_session.refresh(test_user)
        assert test_user.display_name == new_display_name
        assert test_user.accent_color == new_accent_color
        
        # Make another request to get profile - should return updated values
        response = client.get("/api/v1/users/me/profile", headers=auth_token)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["display_name"] == new_display_name
        assert data["accent_color"] == new_accent_color

    def test_update_my_profile_partial_update_persistence(self, client: TestClient, test_user: User, auth_token: dict[str, str], db_session) -> None:
        """Test that partial updates work correctly and persist."""
        original_display_name = test_user.display_name
        new_accent_color = "#ABCDEF"
        
        # Update only accent color
        response = client.patch(
            "/api/v1/users/me/profile",
            json={"accent_color": new_accent_color},
            headers=auth_token
        )
        assert response.status_code == status.HTTP_200_OK
        
        # Verify database was updated
        db_session.refresh(test_user)
        assert test_user.display_name == original_display_name  # Should remain unchanged
        assert test_user.accent_color == new_accent_color
        
        # Now update only display name
        new_display_name = "Updated After Color"
        response = client.patch(
            "/api/v1/users/me/profile",
            json={"display_name": new_display_name},
            headers=auth_token
        )
        assert response.status_code == status.HTTP_200_OK
        
        # Verify both changes persist
        db_session.refresh(test_user)
        assert test_user.display_name == new_display_name
        assert test_user.accent_color == new_accent_color  # Should still be the previous update
